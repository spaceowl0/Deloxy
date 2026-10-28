//! DeloxyStore v1: a small crash-safe persistent file store (flat namespace, whole-file atomic replace).
//!
//! Layout (512-byte sectors):
//! ```text
//! 0                superblock  (magic, version, total sectors, dir sectors, data start, crc32)
//! 1 .. 1+D         directory slot A      (D = DIR_SECTORS)
//! 1+D .. 1+2D      directory slot B
//! 1+2D ..          data extents (contiguous, one per file)
//! ```
//! **Crash safety.** A write puts the new file contents into free extents (free = not referenced by the
//! *committed* directory), flushes, then writes a complete new directory image with `generation+1` into the
//! slot that is NOT current, and flushes again. Mount picks the valid slot (CRC ok) with the highest
//! generation. A power cut at any point leaves either the old or the new directory intact: the old one is
//! never modified before the new one is complete, and data it references is never overwritten.
//! Every file carries a CRC-32 that `read` verifies. This is *not* a journaling filesystem: no directories,
//! no partial writes, no permissions (access is by capability), no wear levelling, one writer at a time.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::drivers::blk::{BlkErr, SECTOR};

pub const DIR_SECTORS: u64 = 32;
pub const DIR_BYTES: usize = DIR_SECTORS as usize * SECTOR;
pub const DATA_START: u64 = 1 + 2 * DIR_SECTORS;
pub const NAME_MAX: usize = 47;
pub const MAX_FILES: usize = 128;
pub const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
const ENTRY_SIZE: usize = 64;
const SB_MAGIC: &[u8; 8] = b"DLXSTORE";
const DIR_MAGIC: &[u8; 8] = b"DLXDIR01";
const VERSION: u32 = 1;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum StoreErr {
    Io(BlkErr),
    NoFilesystem,
    Corrupt,
    NotFound,
    BadName,
    TooLarge,
    NoSpace,
    TooManyFiles,
}

impl From<BlkErr> for StoreErr {
    fn from(e: BlkErr) -> StoreErr {
        StoreErr::Io(e)
    }
}

/// Minimal block device interface (the real one is virtio-blk; tests use a RAM disk).
pub trait BlockDev {
    fn sectors(&self) -> u64;
    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), BlkErr>;
    fn write(&mut self, sector: u64, buf: &[u8]) -> Result<(), BlkErr>;
    fn flush(&mut self) -> Result<(), BlkErr>;
    fn read_only(&self) -> bool {
        false
    }
}

impl BlockDev for crate::drivers::blk::Disk {
    fn sectors(&self) -> u64 {
        self.capacity_sectors()
    }
    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), BlkErr> {
        crate::drivers::blk::Disk::read(self, sector, buf)
    }
    fn write(&mut self, sector: u64, buf: &[u8]) -> Result<(), BlkErr> {
        crate::drivers::blk::Disk::write(self, sector, buf)
    }
    fn flush(&mut self) -> Result<(), BlkErr> {
        crate::drivers::blk::Disk::flush(self)
    }
    fn read_only(&self) -> bool {
        self.is_read_only()
    }
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub start: u64,
    pub size: u64,
    pub crc: u32,
}

/// Names the kernel owns: user programs may read but never create, replace or delete them.
pub fn is_reserved(name: &str) -> bool {
    name.starts_with("upd.") || name.starts_with("perms.")
}

pub fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= NAME_MAX && n != "." && n != ".." && n.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b'+'))
}

fn sectors_for(bytes: u64) -> u64 {
    (bytes + SECTOR as u64 - 1) / SECTOR as u64
}

pub struct Store<D: BlockDev> {
    dev: D,
    total: u64,
    gen: u64,
    /// slot (0 or 1) holding the committed directory
    cur_slot: u8,
    entries: Vec<Entry>,
}

#[derive(Clone, Copy, Debug)]
pub struct StoreStats {
    pub total_bytes: u64,
    pub data_bytes: u64,
    pub used_bytes: u64,
    pub files: usize,
    pub generation: u64,
}

fn encode_dir(gen: u64, entries: &[Entry]) -> Vec<u8> {
    let mut img = vec![0u8; DIR_BYTES];
    img[0..8].copy_from_slice(DIR_MAGIC);
    img[8..16].copy_from_slice(&gen.to_le_bytes());
    img[16..20].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    for (i, e) in entries.iter().enumerate() {
        let o = 32 + i * ENTRY_SIZE;
        let nb = e.name.as_bytes();
        img[o..o + nb.len()].copy_from_slice(nb);
        img[o + 48..o + 56].copy_from_slice(&e.start.to_le_bytes());
        // entry layout: name[48] | start u64 | size u32 (MAX_FILE_BYTES < 4 GiB) | crc u32
        img[o + 56..o + 60].copy_from_slice(&(e.size as u32).to_le_bytes());
        img[o + 60..o + 64].copy_from_slice(&e.crc.to_le_bytes());
    }
    let c = crc32(&img);
    img[20..24].copy_from_slice(&c.to_le_bytes());
    img
}

/// Validate and decode a directory image; `None` if anything is off (bad magic, CRC, entry values).
fn decode_dir(img: &[u8], total: u64) -> Option<(u64, Vec<Entry>)> {
    if img.len() != DIR_BYTES || &img[0..8] != DIR_MAGIC {
        return None;
    }
    let stored = u32::from_le_bytes(img[20..24].try_into().ok()?);
    let mut tmp = img.to_vec();
    tmp[20..24].fill(0);
    if crc32(&tmp) != stored {
        return None;
    }
    let gen = u64::from_le_bytes(img[8..16].try_into().ok()?);
    let n = u32::from_le_bytes(img[16..20].try_into().ok()?) as usize;
    if n > MAX_FILES {
        return None;
    }
    let mut out: Vec<Entry> = Vec::new();
    for i in 0..n {
        let o = 32 + i * ENTRY_SIZE;
        let nl = img[o..o + 48].iter().position(|&b| b == 0).unwrap_or(48);
        let name = core::str::from_utf8(&img[o..o + nl]).ok()?;
        if !valid_name(name) || out.iter().any(|e| e.name == name) {
            return None;
        }
        let start = u64::from_le_bytes(img[o + 48..o + 56].try_into().ok()?);
        let size = u32::from_le_bytes(img[o + 56..o + 60].try_into().ok()?) as u64;
        let crc = u32::from_le_bytes(img[o + 60..o + 64].try_into().ok()?);
        if size as usize > MAX_FILE_BYTES {
            return None;
        }
        if size > 0 {
            let end = start.checked_add(sectors_for(size))?;
            if start < DATA_START || end > total {
                return None;
            }
        }
        out.push(Entry { name: String::from(name), start, size, crc });
    }
    // extents must not overlap
    let mut ext: Vec<(u64, u64)> = out.iter().filter(|e| e.size > 0).map(|e| (e.start, e.start + sectors_for(e.size))).collect();
    ext.sort();
    if ext.windows(2).any(|w| w[0].1 > w[1].0) {
        return None;
    }
    Some((gen, out))
}

impl<D: BlockDev> Store<D> {
    pub fn into_dev(self) -> D {
        self.dev
    }
    pub fn dev_mut(&mut self) -> &mut D {
        &mut self.dev
    }

    /// Write a fresh empty store (destroys existing content).
    pub fn format(mut dev: D) -> Result<Store<D>, StoreErr> {
        if dev.read_only() {
            return Err(StoreErr::Io(BlkErr::ReadOnly));
        }
        let total = dev.sectors();
        if total < DATA_START + 8 {
            return Err(StoreErr::NoSpace);
        }
        let mut sb = vec![0u8; SECTOR];
        sb[0..8].copy_from_slice(SB_MAGIC);
        sb[8..12].copy_from_slice(&VERSION.to_le_bytes());
        sb[16..24].copy_from_slice(&total.to_le_bytes());
        sb[24..28].copy_from_slice(&(DIR_SECTORS as u32).to_le_bytes());
        sb[32..40].copy_from_slice(&DATA_START.to_le_bytes());
        let c = crc32(&sb[..SECTOR - 4]);
        sb[SECTOR - 4..].copy_from_slice(&c.to_le_bytes());
        // invalidate slot B first, write slot A (gen 1), then the superblock last: a half-formatted disk has no valid superblock
        dev.write(1 + DIR_SECTORS, &vec![0u8; DIR_BYTES])?;
        dev.write(1, &encode_dir(1, &[]))?;
        dev.flush()?;
        dev.write(0, &sb)?;
        dev.flush()?;
        Ok(Store { dev, total, gen: 1, cur_slot: 0, entries: Vec::new() })
    }

    pub fn mount(mut dev: D) -> Result<Store<D>, (StoreErr, D)> {
        let mut sb = vec![0u8; SECTOR];
        if let Err(e) = dev.read(0, &mut sb) {
            return Err((e.into(), dev));
        }
        if &sb[0..8] != SB_MAGIC {
            return Err((StoreErr::NoFilesystem, dev));
        }
        let c = u32::from_le_bytes(sb[SECTOR - 4..].try_into().unwrap());
        let total = u64::from_le_bytes(sb[16..24].try_into().unwrap());
        if crc32(&sb[..SECTOR - 4]) != c || u32::from_le_bytes(sb[8..12].try_into().unwrap()) != VERSION || total > dev.sectors() {
            return Err((StoreErr::Corrupt, dev));
        }
        let mut best: Option<(u64, u8, Vec<Entry>)> = None;
        for slot in 0..2u8 {
            let mut img = vec![0u8; DIR_BYTES];
            if let Err(e) = dev.read(1 + slot as u64 * DIR_SECTORS, &mut img) {
                return Err((e.into(), dev));
            }
            if let Some((g, ents)) = decode_dir(&img, total) {
                if best.as_ref().map_or(true, |b| g > b.0) {
                    best = Some((g, slot, ents));
                }
            }
        }
        match best {
            Some((gen, cur_slot, entries)) => Ok(Store { dev, total, gen, cur_slot, entries }),
            None => Err((StoreErr::Corrupt, dev)),
        }
    }

    pub fn list(&self) -> &[Entry] {
        &self.entries
    }

    pub fn stats(&self) -> StoreStats {
        StoreStats {
            total_bytes: self.total * SECTOR as u64,
            data_bytes: (self.total - DATA_START) * SECTOR as u64,
            used_bytes: self.entries.iter().map(|e| sectors_for(e.size) * SECTOR as u64).sum(),
            files: self.entries.len(),
            generation: self.gen,
        }
    }

    pub fn read(&mut self, name: &str) -> Result<Vec<u8>, StoreErr> {
        let e = self.entries.iter().find(|e| e.name == name).cloned().ok_or(StoreErr::NotFound)?;
        if e.size == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; sectors_for(e.size) as usize * SECTOR];
        self.dev.read(e.start, &mut buf)?;
        buf.truncate(e.size as usize);
        if crc32(&buf) != e.crc {
            return Err(StoreErr::Corrupt);
        }
        Ok(buf)
    }

    /// First-fit allocation of `n` sectors among the extents of the committed directory.
    fn alloc(&self, n: u64) -> Option<u64> {
        let mut used: Vec<(u64, u64)> = self.entries.iter().filter(|e| e.size > 0).map(|e| (e.start, e.start + sectors_for(e.size))).collect();
        used.sort();
        let mut pos = DATA_START;
        for (s, e) in used {
            if s >= pos && s - pos >= n {
                return Some(pos);
            }
            pos = pos.max(e);
        }
        if self.total >= pos && self.total - pos >= n { Some(pos) } else { None }
    }

    fn commit(&mut self, new_entries: Vec<Entry>) -> Result<(), StoreErr> {
        let new_gen = self.gen + 1;
        let slot = 1 - self.cur_slot;
        let img = encode_dir(new_gen, &new_entries);
        self.dev.flush()?; // data first
        self.dev.write(1 + slot as u64 * DIR_SECTORS, &img)?;
        self.dev.flush()?;
        self.gen = new_gen;
        self.cur_slot = slot;
        self.entries = new_entries;
        Ok(())
    }

    /// Create or atomically replace `name`.
    pub fn write(&mut self, name: &str, data: &[u8]) -> Result<(), StoreErr> {
        if self.dev.read_only() {
            return Err(StoreErr::Io(BlkErr::ReadOnly));
        }
        if !valid_name(name) {
            return Err(StoreErr::BadName);
        }
        if data.len() > MAX_FILE_BYTES {
            return Err(StoreErr::TooLarge);
        }
        let exists = self.entries.iter().any(|e| e.name == name);
        if !exists && self.entries.len() >= MAX_FILES {
            return Err(StoreErr::TooManyFiles);
        }
        let mut entry = Entry { name: String::from(name), start: 0, size: data.len() as u64, crc: crc32(data) };
        if !data.is_empty() {
            let n = sectors_for(data.len() as u64);
            entry.start = self.alloc(n).ok_or(StoreErr::NoSpace)?;
            let mut padded = data.to_vec();
            padded.resize(n as usize * SECTOR, 0);
            self.dev.write(entry.start, &padded)?;
        }
        let mut new_entries: Vec<Entry> = self.entries.iter().filter(|e| e.name != name).cloned().collect();
        new_entries.push(entry);
        self.commit(new_entries)
    }

    pub fn delete(&mut self, name: &str) -> Result<(), StoreErr> {
        if self.dev.read_only() {
            return Err(StoreErr::Io(BlkErr::ReadOnly));
        }
        if !self.entries.iter().any(|e| e.name == name) {
            return Err(StoreErr::NotFound);
        }
        let new_entries: Vec<Entry> = self.entries.iter().filter(|e| e.name != name).cloned().collect();
        self.commit(new_entries)
    }
}

// ------------------------------------------------------------------ RAM disk (tests) ---

/// In-memory block device with write-failure injection, used by the selftest to prove crash safety.
pub struct RamDisk {
    pub data: Vec<u8>,
    /// `Some(n)`: the n-th write from now (0-based) is torn (half of it lands) and every later write/flush fails.
    pub fail_at_write: Option<usize>,
    pub writes: usize,
    dead: bool,
}

impl RamDisk {
    pub fn new(sectors: u64) -> RamDisk {
        RamDisk { data: vec![0u8; sectors as usize * SECTOR], fail_at_write: None, writes: 0, dead: false }
    }
    pub fn revive(&mut self) {
        self.dead = false;
        self.fail_at_write = None;
        self.writes = 0;
    }
}

impl BlockDev for RamDisk {
    fn sectors(&self) -> u64 {
        (self.data.len() / SECTOR) as u64
    }
    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), BlkErr> {
        let s = sector as usize * SECTOR;
        let e = s.checked_add(buf.len()).ok_or(BlkErr::OutOfRange)?;
        if e > self.data.len() {
            return Err(BlkErr::OutOfRange);
        }
        buf.copy_from_slice(&self.data[s..e]);
        Ok(())
    }
    fn write(&mut self, sector: u64, buf: &[u8]) -> Result<(), BlkErr> {
        if self.dead {
            return Err(BlkErr::Io);
        }
        let s = sector as usize * SECTOR;
        let e = s.checked_add(buf.len()).ok_or(BlkErr::OutOfRange)?;
        if e > self.data.len() {
            return Err(BlkErr::OutOfRange);
        }
        if self.fail_at_write == Some(self.writes) {
            let half = (buf.len() / 2) & !(SECTOR - 1);
            self.data[s..s + half].copy_from_slice(&buf[..half]);
            // a torn sector: garbage in the next one
            if half < buf.len() {
                for b in &mut self.data[s + half..s + half + SECTOR.min(buf.len() - half)] {
                    *b = 0xA5;
                }
            }
            self.dead = true;
            return Err(BlkErr::Io);
        }
        self.writes += 1;
        self.data[s..e].copy_from_slice(buf);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), BlkErr> {
        if self.dead { Err(BlkErr::Io) } else { Ok(()) }
    }
}

// ------------------------------------------------------------------ global instance ---

use crate::drivers::blk::{self as blkdrv, Disk as VirtioBlk};
use crate::sync::IrqMutex;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// No virtio-blk device was found.
    NoDevice,
    /// A disk is present but carries no DeloxyStore (nothing is ever formatted without an explicit request).
    Unformatted,
    Ready,
    /// Device or metadata problem; the string says which.
    Failed(&'static str),
}

struct Global {
    state: State,
    store: Option<Store<VirtioBlk>>,
    spare: Option<VirtioBlk>,
}

static G: IrqMutex<Global> = IrqMutex::new(Global { state: State::NoDevice, store: None, spare: None });

/// Probe the disk and mount an existing store. Never formats.
pub fn init() {
    use log::{info, warn};
    let mut g = G.lock();
    match blkdrv::probe_first() {
        None => info!("store: no disk present (virtio-blk, AHCI/SATA)"),
        Some(Err(e)) => {
            warn!("store: disk probe failed: {}", e);
            g.state = State::Failed("probe failed");
        }
        Some(Ok(dev)) => {
            let (cap, ro) = (dev.capacity_sectors(), dev.is_read_only());
            info!("store: {} found, {} MiB{}", dev.kind(), cap / 2048, if ro { " (read-only)" } else { "" });
            match Store::mount(dev) {
                Ok(st) => {
                    let s = st.stats();
                    info!("store: mounted, generation {}, {} file(s), {} KiB used", s.generation, s.files, s.used_bytes / 1024);
                    g.store = Some(st);
                    g.state = State::Ready;
                }
                Err((StoreErr::NoFilesystem, dev)) => {
                    info!("store: disk has no DeloxyStore (not formatting automatically; use 'format' in the shell)");
                    g.spare = Some(dev);
                    g.state = State::Unformatted;
                }
                Err((e, dev)) => {
                    warn!("store: mount failed: {:?} (disk left untouched)", e);
                    g.spare = Some(dev);
                    g.state = State::Failed("corrupt or unreadable");
                }
            }
        }
    }
}

pub fn state() -> State {
    G.lock().state
}

/// Run `f` on the mounted store.
pub fn with<R>(f: impl FnOnce(&mut Store<VirtioBlk>) -> R) -> Result<R, StoreErr> {
    let mut g = G.lock();
    match g.store.as_mut() {
        Some(s) => Ok(f(s)),
        None => Err(StoreErr::NoFilesystem),
    }
}

/// Format the disk (destroys everything). Works on an unformatted, failed or already-formatted disk.
pub fn format_device() -> Result<(), StoreErr> {
    let mut g = G.lock();
    let dev = match (g.store.take(), g.spare.take()) {
        (Some(s), _) => s.into_dev(),
        (None, Some(d)) => d,
        (None, None) => return Err(StoreErr::NoFilesystem),
    };
    match Store::format(dev) {
        Ok(st) => {
            g.store = Some(st);
            g.state = State::Ready;
            Ok(())
        }
        Err(e) => {
            g.state = State::Failed("format failed");
            Err(e)
        }
    }
}

/// An opened store file (immutable snapshot).
pub struct StoredFile {
    pub name: String,
    pub data: Vec<u8>,
}

impl AsRef<[u8]> for StoredFile {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}
