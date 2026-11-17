//! DeloxyStore v2: a crash-safe, writable, hierarchical persistent filesystem on a block device.
//!
//! Layout (512-byte sectors; the first 65 sectors are the same as v1, so v1 disks mount and migrate in place):
//! ```text
//! 0                superblock  (magic, version, total sectors, dir sectors, data start, crc32)
//! 1 .. 1+D         root slot A  (only its first sector is used by v2; D = DIR_SECTORS)
//! 1+D .. 1+2D      root slot B
//! 1+2D ..          data area: file extents and metadata images, allocated first-fit
//! ```
//! **Metadata** is one image (`DLXMETA2`): every inode (file, directory, symlink) with mode, mtime, size, CRC-32
//! and either an extent list (files), name->inode entries (directories) or the link target (symlinks). A root slot
//! is a single sector `{gen, meta extent, meta CRC, next inode}` protected by its own CRC.
//! **Crash safety (copy-on-write).** An operation writes new file data into free extents (free = not referenced
//! by the *committed* metadata), flushes, writes a complete new metadata image into another free extent, flushes,
//! and only then writes the root slot that is NOT current with `generation+1`, and flushes again. Mount takes the
//! valid slot (slot CRC, metadata CRC and full structural validation) with the highest generation; a torn write
//! anywhere leaves the previous generation intact because nothing it references is ever overwritten.
//! Every file carries a CRC-32 that `read` verifies. Namespace operations (create, mkdir, rename, unlink, rmdir,
//! symlink) are each one atomic commit. This is *not* a journaling filesystem: whole-file replace, no hard links,
//! no owners (access is by capability), one writer at a time, no wear levelling.
//! **v1 compatibility:** a v1 store (flat directory, `DLXDIR01` slots) mounts as a root directory of files and is
//! converted by its first write: the v2 root record goes into the other slot with `generation+1`, referencing the
//! v1 files' extents unchanged (the superblock is never rewritten, so a torn write cannot brick the disk). A v1-only
//! kernel would mount the older v1 slot afterwards, i.e. downgrading after migration loses the newer changes.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::drivers::blk::{BlkErr, SECTOR};

pub const DIR_SECTORS: u64 = 32;
pub const DIR_BYTES: usize = DIR_SECTORS as usize * SECTOR;
pub const DATA_START: u64 = 1 + 2 * DIR_SECTORS;
/// Longest *flat* name (the shell's `save`/`cp`, the update/permission files).
pub const NAME_MAX: usize = 47;
/// Longest single path component in the hierarchy.
pub const COMP_MAX: usize = 255;
pub const PATH_MAX: usize = 4096;
/// Maximum number of inodes (files + directories + symlinks), root included.
pub const MAX_FILES: usize = 20_000;
/// On-disk limit for one file (the disk size and the metadata image are the practical limits).
pub const MAX_FILE_BYTES: usize = 1 << 40;
/// Limit for the whole-file `Vec` API (`read`/`write`); bigger files use `read_at`/`write_at`/`truncate`.
pub const MAX_INMEM_BYTES: usize = 32 * 1024 * 1024;
/// Integrity granule: every file carries one CRC-32 per 64 KiB chunk, so a range can be verified without
/// reading the whole file.
pub const CHUNK: usize = 64 * 1024;
const CHUNK_U: u64 = CHUNK as u64;
const CHUNK_SECT: u64 = (CHUNK / SECTOR) as u64;
pub const MAX_EXTENTS: usize = 1 << 16;
const ALLOC_FRAGS: usize = 4096;
pub const MAX_META_BYTES: usize = 32 * 1024 * 1024;
pub const SYMLINK_MAX: usize = 1024;
pub const ROOT: u32 = 1;
const MAX_HOPS: usize = 16;
const SB_MAGIC: &[u8; 8] = b"DLXSTORE";
const DIR_MAGIC: &[u8; 8] = b"DLXDIR01";
const ROOT_MAGIC: &[u8; 8] = b"DLXRT002";
const ROOT3_MAGIC: &[u8; 8] = b"DLXRT003";
/// Commit-log record: 24-byte header (magic, payload length, payload CRC, pad, generation) + payload, padded to a sector.
const LOG_MAGIC: u32 = 0x3144_474C;
const LOG_HDR: usize = 24;
const LOG_PAYLOAD_MAX: usize = 1024 * 1024;
const META_MAGIC: &[u8; 8] = b"DLXMETA2";
const META3_MAGIC: &[u8; 8] = b"DLXMETA3";
const V1_ENTRY_SIZE: usize = 64;
const VERSION: u32 = 2;

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
    Exists,
    NotDir,
    IsDir,
    NotEmpty,
    /// moving a directory into itself, reading a non-symlink as a link, ...
    Invalid,
    /// too many levels of symbolic links
    Loop,
}

impl StoreErr {
    /// The POSIX errno a foreign program sees for this error.
    pub fn errno(self) -> i64 {
        match self {
            StoreErr::NoFilesystem => 19, // ENODEV
            StoreErr::NotFound => 2,
            StoreErr::BadName | StoreErr::Invalid => 22,
            StoreErr::TooLarge => 27,
            StoreErr::NoSpace | StoreErr::TooManyFiles => 28,
            StoreErr::Exists => 17,
            StoreErr::NotDir => 20,
            StoreErr::IsDir => 21,
            StoreErr::NotEmpty => 39,
            StoreErr::Loop => 40,
            StoreErr::Corrupt | StoreErr::Io(_) => 5,
        }
    }
}

impl From<BlkErr> for StoreErr {
    fn from(e: BlkErr) -> StoreErr {
        StoreErr::Io(e)
    }
}

/// Minimal block device interface (the real one is virtio-blk/AHCI; tests use a RAM disk).
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

const fn make_crc_tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut n = 1;
    while n < 8 {
        let mut i = 0;
        while i < 256 {
            let p = t[n - 1][i];
            t[n][i] = (p >> 8) ^ t[0][(p & 0xFF) as usize];
            i += 1;
        }
        n += 1;
    }
    t
}
static CRC_TABLE: [[u32; 256]; 8] = make_crc_tables();

/// CRC-32 (IEEE), slice-by-8.
pub fn crc32(data: &[u8]) -> u32 {
    let t = &CRC_TABLE;
    let mut c = !0u32;
    let mut it = data.chunks_exact(8);
    for w in &mut it {
        let a = u32::from_le_bytes([w[0], w[1], w[2], w[3]]) ^ c;
        let b = u32::from_le_bytes([w[4], w[5], w[6], w[7]]);
        c = t[7][(a & 0xFF) as usize]
            ^ t[6][((a >> 8) & 0xFF) as usize]
            ^ t[5][((a >> 16) & 0xFF) as usize]
            ^ t[4][(a >> 24) as usize]
            ^ t[3][(b & 0xFF) as usize]
            ^ t[2][((b >> 8) & 0xFF) as usize]
            ^ t[1][((b >> 16) & 0xFF) as usize]
            ^ t[0][(b >> 24) as usize];
    }
    for &b in it.remainder() {
        c = t[0][((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

fn chunk_crcs(data: &[u8]) -> Vec<u32> {
    data.chunks(CHUNK).map(crc32).collect()
}

fn table_crc(chunks: &[u32]) -> u32 {
    let mut b = Vec::with_capacity(chunks.len() * 4);
    for c in chunks {
        b.extend_from_slice(&c.to_le_bytes());
    }
    crc32(&b)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub start: u64,
    pub size: u64,
    pub crc: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
}

impl Kind {
    fn code(self) -> u8 {
        match self {
            Kind::File => 1,
            Kind::Dir => 2,
            Kind::Symlink => 3,
        }
    }
    fn from_code(c: u8) -> Option<Kind> {
        match c {
            1 => Some(Kind::File),
            2 => Some(Kind::Dir),
            3 => Some(Kind::Symlink),
            _ => None,
        }
    }
}

/// `stat` result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub ino: u32,
    pub kind: Kind,
    pub mode: u16,
    pub size: u64,
    pub mtime: u64,
    pub crc: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub kind: Kind,
    pub size: u64,
    pub ino: u32,
}

/// Names the kernel owns at the store root: user programs may read them but never create, replace or delete them.
pub fn is_reserved(name: &str) -> bool {
    name.starts_with("upd.") || name.starts_with("perms.")
}

/// Is the first component of `path` a kernel-owned root name (`upd.*`, `perms.*`)?
pub fn is_reserved_path(path: &str) -> bool {
    path.split('/').find(|c| !c.is_empty() && *c != ".").map_or(false, is_reserved)
}

/// A flat name (the v1 namespace: shell `save`, `upd.*`, `de.conf`, `perms.db`).
pub fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= NAME_MAX && n != "." && n != ".." && n.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b'+'))
}

/// One path component of the hierarchy: any UTF-8 except '/' and NUL, not "." / "..", at most 255 bytes.
pub fn valid_component(n: &str) -> bool {
    !n.is_empty() && n.len() <= COMP_MAX && n != "." && n != ".." && !n.bytes().any(|c| c == b'/' || c == 0)
}

fn sectors_for(bytes: u64) -> u64 {
    (bytes + SECTOR as u64 - 1) / SECTOR as u64
}

fn now_secs() -> u64 {
    crate::time::unix_ms() / 1000
}

#[derive(Clone, Debug)]
struct Inode {
    kind: Kind,
    mode: u16,
    mtime: u64,
    size: u64,
    crc: u32,
    extents: Vec<(u64, u32)>,
    /// CRC-32 of every 64 KiB chunk (empty for a legacy v2 file, which has one whole-file CRC in `crc`)
    chunks: Vec<u32>,
    entries: BTreeMap<String, u32>,
    target: String,
}

impl Inode {
    fn dir(mode: u16, mtime: u64) -> Inode {
        Inode { kind: Kind::Dir, mode, mtime, size: 0, crc: 0, extents: Vec::new(), chunks: Vec::new(), entries: BTreeMap::new(), target: String::new() }
    }
    fn file(mode: u16, mtime: u64, size: u64, crc: u32, extents: Vec<(u64, u32)>, chunks: Vec<u32>) -> Inode {
        Inode { kind: Kind::File, mode, mtime, size, crc, extents, chunks, entries: BTreeMap::new(), target: String::new() }
    }
    fn symlink(target: &str, mtime: u64) -> Inode {
        Inode { kind: Kind::Symlink, mode: 0o777, mtime, size: target.len() as u64, crc: 0, extents: Vec::new(), chunks: Vec::new(), entries: BTreeMap::new(), target: String::from(target) }
    }
    fn stat(&self, ino: u32) -> Stat {
        Stat { ino, kind: self.kind, mode: self.mode, size: self.size, mtime: self.mtime, crc: self.crc }
    }
}

/// Copy-on-write overlay over the committed inode map: operations stage their changes here and either commit
/// them all (one metadata image) or drop them.
struct Tx<'a> {
    base: &'a BTreeMap<u32, Inode>,
    ov: BTreeMap<u32, Option<Inode>>,
    next_ino: u32,
    count: usize,
}

impl<'a> Tx<'a> {
    fn new(base: &'a BTreeMap<u32, Inode>, next_ino: u32) -> Tx<'a> {
        Tx { base, ov: BTreeMap::new(), next_ino, count: base.len() }
    }
    fn get(&self, ino: u32) -> Option<&Inode> {
        match self.ov.get(&ino) {
            Some(Some(i)) => Some(i),
            Some(None) => None,
            None => self.base.get(&ino),
        }
    }
    fn put(&mut self, ino: u32, i: Inode) {
        if self.get(ino).is_none() {
            self.count += 1;
        }
        self.ov.insert(ino, Some(i));
    }
    fn del(&mut self, ino: u32) {
        if self.get(ino).is_some() {
            self.count -= 1;
        }
        self.ov.insert(ino, None);
    }
    fn fresh(&mut self) -> Result<u32, StoreErr> {
        if self.count >= MAX_FILES || self.next_ino == u32::MAX {
            return Err(StoreErr::TooManyFiles);
        }
        let n = self.next_ino;
        self.next_ino += 1;
        Ok(n)
    }
    fn finish(self) -> (BTreeMap<u32, Option<Inode>>, u32) {
        (self.ov, self.next_ino)
    }
}

fn comps_of(path: &str) -> VecDeque<String> {
    path.split('/').filter(|c| !c.is_empty() && *c != ".").map(String::from).collect()
}

/// Resolve `path` (from the store root; "store/" prefix tolerated for absolute symlink targets) to an inode,
/// expanding symbolic links (the last one only when `follow_last`).
fn walk(tx: &Tx, path: &str, follow_last: bool) -> Result<u32, StoreErr> {
    walk_full(tx, path, follow_last).map(|r| r.0)
}

/// Like `walk`, also returning the canonical component names (symlinks expanded, no "." / "..").
fn walk_full(tx: &Tx, path: &str, follow_last: bool) -> Result<(u32, Vec<String>), StoreErr> {
    if path.len() > PATH_MAX {
        return Err(StoreErr::BadName);
    }
    let mut stack: Vec<u32> = vec![ROOT];
    let mut names: Vec<String> = Vec::new();
    let mut queue = comps_of(path);
    let mut hops = 0;
    while let Some(c) = queue.pop_front() {
        if c == ".." {
            if stack.len() > 1 {
                stack.pop();
                names.pop();
            }
            continue;
        }
        let cur = *stack.last().unwrap();
        let dir = tx.get(cur).ok_or(StoreErr::Corrupt)?;
        if dir.kind != Kind::Dir {
            return Err(StoreErr::NotDir);
        }
        let child = *dir.entries.get(&c).ok_or(StoreErr::NotFound)?;
        let ci = tx.get(child).ok_or(StoreErr::Corrupt)?;
        if ci.kind == Kind::Symlink && (follow_last || !queue.is_empty()) {
            hops += 1;
            if hops > MAX_HOPS {
                return Err(StoreErr::Loop);
            }
            let mut t = ci.target.as_str();
            if t.starts_with('/') {
                stack.truncate(1);
                names.clear();
                t = t.trim_start_matches('/');
                if t == "store" {
                    t = "";
                } else if let Some(r) = t.strip_prefix("store/") {
                    t = r;
                }
            }
            for x in comps_of(t).into_iter().rev() {
                queue.push_front(x);
            }
            continue;
        }
        stack.push(child);
        names.push(c);
    }
    Ok((*stack.last().unwrap(), names))
}

/// `(directory inode, final name)` for creating/removing `path` (the final component is not looked up).
fn walk_parent(tx: &Tx, path: &str) -> Result<(u32, String), StoreErr> {
    let mut comps = comps_of(path);
    let last = comps.pop_back().ok_or(StoreErr::BadName)?;
    if last == ".." || !valid_component(&last) {
        return Err(StoreErr::BadName);
    }
    let parent_path: Vec<String> = comps.into_iter().collect();
    let p = walk(tx, &parent_path.join("/"), true)?;
    if tx.get(p).ok_or(StoreErr::Corrupt)?.kind != Kind::Dir {
        return Err(StoreErr::NotDir);
    }
    Ok((p, last))
}

/// Is `needle` inside the directory tree rooted at `top` (or `top` itself)?
fn contains_dir(tx: &Tx, top: u32, needle: u32) -> bool {
    let mut work = vec![top];
    let mut seen = 0usize;
    while let Some(d) = work.pop() {
        if d == needle {
            return true;
        }
        seen += 1;
        if seen > MAX_FILES {
            return true; // cannot happen on a validated tree; refuse rather than loop
        }
        if let Some(i) = tx.get(d) {
            if i.kind == Kind::Dir {
                work.extend(i.entries.values().copied());
            }
        }
    }
    false
}

// ------------------------------------------------------------------ on-disk encoding ---

fn encode_inode(o: &mut Vec<u8>, ino: u32, i: &Inode) {
    o.extend_from_slice(&ino.to_le_bytes());
    o.push(i.kind.code());
    o.push(0);
    o.extend_from_slice(&i.mode.to_le_bytes());
    o.extend_from_slice(&i.mtime.to_le_bytes());
    o.extend_from_slice(&i.size.to_le_bytes());
    o.extend_from_slice(&i.crc.to_le_bytes());
    match i.kind {
        Kind::File => {
            o.extend_from_slice(&(i.extents.len() as u32).to_le_bytes());
            for (s, n) in &i.extents {
                o.extend_from_slice(&s.to_le_bytes());
                o.extend_from_slice(&n.to_le_bytes());
            }
            o.extend_from_slice(&(i.chunks.len() as u32).to_le_bytes());
            for c in &i.chunks {
                o.extend_from_slice(&c.to_le_bytes());
            }
        }
        Kind::Dir => {
            o.extend_from_slice(&(i.entries.len() as u32).to_le_bytes());
            for (name, c) in &i.entries {
                o.extend_from_slice(&c.to_le_bytes());
                o.extend_from_slice(&(name.len() as u16).to_le_bytes());
                o.extend_from_slice(name.as_bytes());
            }
        }
        Kind::Symlink => {
            o.extend_from_slice(&(i.target.len() as u32).to_le_bytes());
            o.extend_from_slice(i.target.as_bytes());
        }
    }
}

fn encode_meta(merged: &[(u32, &Inode)], next_ino: u32) -> Vec<u8> {
    let mut o: Vec<u8> = Vec::with_capacity(64 + merged.len() * 48);
    o.extend_from_slice(META3_MAGIC);
    o.extend_from_slice(&(merged.len() as u32).to_le_bytes());
    o.extend_from_slice(&next_ino.to_le_bytes());
    for (ino, i) in merged {
        encode_inode(&mut o, *ino, i);
    }
    o
}

/// The changes of one commit as a log payload: next inode counter, then per inode `1` + full inode or `0` + number.
fn encode_delta(ov: &BTreeMap<u32, Option<Inode>>, old: &BTreeMap<u32, Inode>, next_ino: u32) -> Vec<u8> {
    let mut o: Vec<u8> = Vec::with_capacity(64 + ov.len() * 64);
    o.extend_from_slice(&next_ino.to_le_bytes());
    o.extend_from_slice(&(ov.len() as u32).to_le_bytes());
    for (ino, v) in ov {
        match v {
            Some(i) if i.kind == Kind::Dir && old.get(ino).map_or(false, |p| p.kind == Kind::Dir) => {
                // a directory that already exists: log only the entries that changed (a big directory must not be
                // written whole on every create/unlink)
                let prev = &old[ino];
                o.push(2);
                o.extend_from_slice(&ino.to_le_bytes());
                o.extend_from_slice(&i.mode.to_le_bytes());
                o.extend_from_slice(&i.mtime.to_le_bytes());
                let adds: Vec<(&String, &u32)> = i.entries.iter().filter(|(n, c)| prev.entries.get(*n) != Some(*c)).collect();
                let dels: Vec<&String> = prev.entries.keys().filter(|n| !i.entries.contains_key(*n)).collect();
                o.extend_from_slice(&(adds.len() as u32).to_le_bytes());
                for (n, c) in adds {
                    o.extend_from_slice(&c.to_le_bytes());
                    o.extend_from_slice(&(n.len() as u16).to_le_bytes());
                    o.extend_from_slice(n.as_bytes());
                }
                o.extend_from_slice(&(dels.len() as u32).to_le_bytes());
                for n in dels {
                    o.extend_from_slice(&(n.len() as u16).to_le_bytes());
                    o.extend_from_slice(n.as_bytes());
                }
            }
            Some(i) => {
                o.push(1);
                encode_inode(&mut o, *ino, i);
            }
            None => {
                o.push(0);
                o.extend_from_slice(&ino.to_le_bytes());
            }
        }
    }
    o
}

struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let e = self.p.checked_add(n)?;
        let s = self.b.get(self.p..e)?;
        self.p = e;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|s| u32::from_le_bytes(s.try_into().unwrap()))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
    }
}

fn decode_inode(r: &mut Rd, v3: bool, next_ino: u32, total: u64) -> Option<(u32, Inode)> {
    let ino = r.u32()?;
    let kind = Kind::from_code(r.u8()?)?;
    let _ = r.u8()?;
    let mode = r.u16()? & 0o7777;
    let mtime = r.u64()?;
    let size = r.u64()?;
    let crc = r.u32()?;
    let aux = r.u32()? as usize;
    if ino == 0 || ino >= next_ino {
        return None;
    }
    let inode = match kind {
        Kind::File => {
            if aux > MAX_EXTENTS || size > MAX_FILE_BYTES as u64 {
                return None;
            }
            if aux == 0 && size > 0 {
                return None;
            }
            let mut ex = Vec::with_capacity(aux);
            let mut sum = 0u64;
            for _ in 0..aux {
                let s = r.u64()?;
                let n = r.u32()?;
                let e = s.checked_add(n as u64)?;
                if n == 0 || s < DATA_START || e > total {
                    return None;
                }
                sum += n as u64;
                ex.push((s, n));
            }
            if sum != sectors_for(size) {
                return None;
            }
            let mut chunks = Vec::new();
            if v3 {
                let nc = r.u32()? as usize;
                // nc == 0 with data: a legacy file migrated from v1/v2 (its `crc` is the whole-file CRC)
                if nc as u64 != size.div_ceil(CHUNK_U) && nc != 0 {
                    return None;
                }
                chunks.reserve(nc);
                for _ in 0..nc {
                    chunks.push(r.u32()?);
                }
            }
            Inode::file(mode, mtime, size, crc, ex, chunks)
        }
        Kind::Dir => {
            if aux > MAX_FILES {
                return None;
            }
            let mut d = Inode::dir(mode, mtime);
            for _ in 0..aux {
                let c = r.u32()?;
                let nl = r.u16()? as usize;
                let name = core::str::from_utf8(r.take(nl)?).ok()?;
                if !valid_component(name) || d.entries.insert(String::from(name), c).is_some() {
                    return None;
                }
            }
            d
        }
        Kind::Symlink => {
            if aux == 0 || aux > SYMLINK_MAX || size != aux as u64 {
                return None;
            }
            let t = core::str::from_utf8(r.take(aux)?).ok()?;
            Inode::symlink(t, mtime)
        }
    };
    Some((ino, inode))
}

fn validate_tree(map: &BTreeMap<u32, Inode>) -> bool {
    // tree shape: root is a directory, every other inode is referenced exactly once, everything is reachable
    if map.get(&ROOT).map(|i| i.kind) != Some(Kind::Dir) {
        return false;
    }
    let mut refs: BTreeMap<u32, u32> = BTreeMap::new();
    for i in map.values() {
        for c in i.entries.values() {
            if *c == ROOT || !map.contains_key(c) {
                return false;
            }
            *refs.entry(*c).or_insert(0) += 1;
        }
    }
    if refs.len() != map.len() - 1 || refs.values().any(|&n| n != 1) {
        return false;
    }
    let mut seen = 0usize;
    let mut work = vec![ROOT];
    while let Some(d) = work.pop() {
        seen += 1;
        if seen > map.len() {
            return false; // cycle
        }
        work.extend(map[&d].entries.values().copied());
    }
    if seen != map.len() {
        return false;
    }
    // extents must not overlap
    let mut ext: Vec<(u64, u64)> = map.values().flat_map(|i| i.extents.iter().map(|&(s, n)| (s, s + n as u64))).collect();
    ext.sort();
    if ext.windows(2).any(|w| w[0].1 > w[1].0) {
        return false;
    }
    true
}

/// Parse a checkpoint image (no tree validation: a commit log may still have to be replayed on top).
fn decode_meta_raw(img: &[u8], total: u64) -> Option<(BTreeMap<u32, Inode>, u32)> {
    let mut r = Rd { b: img, p: 0 };
    let magic = r.take(8)?;
    let v3 = magic == META3_MAGIC;
    if !v3 && magic != META_MAGIC {
        return None;
    }
    let count = r.u32()? as usize;
    let next_ino = r.u32()?;
    if count == 0 || count > MAX_FILES {
        return None;
    }
    let mut map: BTreeMap<u32, Inode> = BTreeMap::new();
    for _ in 0..count {
        let (ino, inode) = decode_inode(&mut r, v3, next_ino, total)?;
        if map.insert(ino, inode).is_some() {
            return None;
        }
    }
    if r.p != img.len() {
        return None;
    }
    Some((map, next_ino))
}

/// Apply one log payload to the tree; returns the new next-inode counter.
fn apply_delta(map: &mut BTreeMap<u32, Inode>, payload: &[u8], total: u64, prev_next: u32) -> Option<u32> {
    let mut r = Rd { b: payload, p: 0 };
    let next_ino = r.u32()?;
    if next_ino < prev_next {
        return None;
    }
    let count = r.u32()? as usize;
    if count > MAX_FILES {
        return None;
    }
    for _ in 0..count {
        match r.u8()? {
            1 => {
                let (ino, inode) = decode_inode(&mut r, true, next_ino, total)?;
                map.insert(ino, inode);
            }
            0 => {
                let ino = r.u32()?;
                map.remove(&ino)?;
            }
            2 => {
                let ino = r.u32()?;
                let mode = r.u16()? & 0o7777;
                let mtime = r.u64()?;
                let d = map.get_mut(&ino)?;
                if d.kind != Kind::Dir {
                    return None;
                }
                d.mode = mode;
                d.mtime = mtime;
                for _ in 0..r.u32()? {
                    let c = r.u32()?;
                    let nl = r.u16()? as usize;
                    let name = core::str::from_utf8(r.take(nl)?).ok()?;
                    if !valid_component(name) || c == 0 || c >= next_ino {
                        return None;
                    }
                    d.entries.insert(String::from(name), c);
                }
                for _ in 0..r.u32()? {
                    let nl = r.u16()? as usize;
                    let name = core::str::from_utf8(r.take(nl)?).ok()?;
                    d.entries.remove(name)?;
                }
            }
            _ => return None,
        }
    }
    (r.p == payload.len()).then_some(next_ino)
}

/// Replay `buf` (the used part of the log) on top of a checkpoint made at generation `ckpt_gen`; the last record must
/// carry `root_gen`. Returns the final next-inode counter.
fn replay_log(map: &mut BTreeMap<u32, Inode>, buf: &[u8], ckpt_gen: u64, root_gen: u64, total: u64, mut next: u32) -> Option<u32> {
    let mut p = 0usize;
    let mut g = ckpt_gen;
    while p < buf.len() {
        if buf.len() - p < LOG_HDR {
            return None;
        }
        let h = &buf[p..p + LOG_HDR];
        if u32::from_le_bytes(h[0..4].try_into().ok()?) != LOG_MAGIC {
            return None;
        }
        let len = u32::from_le_bytes(h[4..8].try_into().ok()?) as usize;
        let crc = u32::from_le_bytes(h[8..12].try_into().ok()?);
        let gen = u64::from_le_bytes(h[16..24].try_into().ok()?);
        g += 1;
        if gen != g || len > LOG_PAYLOAD_MAX {
            return None;
        }
        let rs = sectors_for((LOG_HDR + len) as u64) as usize * SECTOR;
        if p + rs > buf.len() {
            return None;
        }
        let payload = &buf[p + LOG_HDR..p + LOG_HDR + len];
        if crc32(payload) != crc {
            return None;
        }
        next = apply_delta(map, payload, total, next)?;
        p += rs;
    }
    (g == root_gen).then_some(next)
}

/// Decode and fully validate a metadata image (structure, extents, tree shape). `None` on any inconsistency.
fn decode_meta(img: &[u8], total: u64) -> Option<(BTreeMap<u32, Inode>, u32)> {
    let (map, next) = decode_meta_raw(img, total)?;
    validate_tree(&map).then_some((map, next))
}

/// Root record (one sector). `ckpt_gen` is the generation of the checkpoint image `(mstart, mlen, mcrc, ckpt_next)`
/// (`mstart2` = an identical mirror copy, 0 if none, used when the primary image fails its CRC);
/// `log = (start, capacity, used)` in sectors is the commit log appended after it (records ckpt_gen+1 ..= gen).
#[allow(clippy::too_many_arguments)]
fn encode_root(gen: u64, ckpt_gen: u64, mstart: u64, mstart2: u64, mlen: u32, mcrc: u32, ckpt_next: u32, log: (u64, u64, u64)) -> Vec<u8> {
    let mut s = vec![0u8; SECTOR];
    s[0..8].copy_from_slice(ROOT3_MAGIC);
    s[8..16].copy_from_slice(&gen.to_le_bytes());
    s[16..24].copy_from_slice(&mstart.to_le_bytes());
    s[24..28].copy_from_slice(&mlen.to_le_bytes());
    s[28..32].copy_from_slice(&mcrc.to_le_bytes());
    s[32..36].copy_from_slice(&ckpt_next.to_le_bytes());
    s[40..48].copy_from_slice(&ckpt_gen.to_le_bytes());
    s[48..56].copy_from_slice(&log.0.to_le_bytes());
    s[56..60].copy_from_slice(&(log.1 as u32).to_le_bytes());
    s[60..64].copy_from_slice(&(log.2 as u32).to_le_bytes());
    s[64..72].copy_from_slice(&mstart2.to_le_bytes());
    let c = crc32(&s[0..72]);
    s[72..76].copy_from_slice(&c.to_le_bytes());
    s
}

/// A v1 flat directory slot: `(generation, [(name, start, size, crc)])`.
fn decode_dir_v1(img: &[u8], total: u64) -> Option<(u64, Vec<(String, u64, u64, u32)>)> {
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
    if n > 128 {
        return None;
    }
    let mut out: Vec<(String, u64, u64, u32)> = Vec::new();
    for i in 0..n {
        let o = 32 + i * V1_ENTRY_SIZE;
        let nl = img[o..o + 48].iter().position(|&b| b == 0).unwrap_or(48);
        let name = core::str::from_utf8(&img[o..o + nl]).ok()?;
        if !valid_name(name) || out.iter().any(|e| e.0 == name) {
            return None;
        }
        let start = u64::from_le_bytes(img[o + 48..o + 56].try_into().ok()?);
        let size = u32::from_le_bytes(img[o + 56..o + 60].try_into().ok()?) as u64;
        let crc = u32::from_le_bytes(img[o + 60..o + 64].try_into().ok()?);
        if size > 0 {
            let end = start.checked_add(sectors_for(size))?;
            if start < DATA_START || end > total {
                return None;
            }
        }
        out.push((String::from(name), start, size, crc));
    }
    let mut ext: Vec<(u64, u64)> = out.iter().filter(|e| e.2 > 0).map(|e| (e.1, e.1 + sectors_for(e.2))).collect();
    ext.sort();
    if ext.windows(2).any(|w| w[0].1 > w[1].0) {
        return None;
    }
    Some((gen, out))
}

fn tree_from_v1(files: &[(String, u64, u64, u32)]) -> (BTreeMap<u32, Inode>, u32) {
    let mut map = BTreeMap::new();
    let mut root = Inode::dir(0o755, 0);
    let mut next = ROOT + 1;
    for (name, start, size, crc) in files {
        let ex = if *size > 0 { vec![(*start, sectors_for(*size) as u32)] } else { Vec::new() };
        root.entries.insert(name.clone(), next);
        map.insert(next, Inode::file(0o644, 0, *size, *crc, ex, Vec::new()));
        next += 1;
    }
    map.insert(ROOT, root);
    (map, next)
}

// ------------------------------------------------------------------ allocation ---

/// Free space of the data area as coalesced runs (`start -> end`, sectors). Allocation takes from it; sectors a
/// commit stops referencing are given back only after that commit is durable, so "free" always means "not
/// referenced by the committed tree".
struct FreeMap {
    runs: BTreeMap<u64, u64>,
}

fn split_u32(mut s: u64, mut n: u64) -> Vec<(u64, u32)> {
    let mut v = Vec::new();
    while n > 0 {
        let t = n.min(u32::MAX as u64);
        v.push((s, t as u32));
        s += t;
        n -= t;
    }
    v
}

impl FreeMap {
    fn new(total: u64, used: &mut Vec<(u64, u64)>) -> FreeMap {
        used.sort();
        let mut runs = BTreeMap::new();
        let mut pos = DATA_START;
        for &(s, e) in used.iter() {
            if s > pos {
                runs.insert(pos, s);
            }
            pos = pos.max(e);
        }
        if total > pos {
            runs.insert(pos, total);
        }
        FreeMap { runs }
    }
    fn carve(&mut self, s: u64, take: u64) {
        if let Some(e) = self.runs.remove(&s) {
            if s + take < e {
                self.runs.insert(s + take, e);
            }
        }
    }
    fn free_sectors(&self) -> u64 {
        self.runs.iter().map(|(s, e)| e - s).sum()
    }
    /// `n` sectors as at most `max_ext` extents: one first-fit run if possible, otherwise the largest runs.
    fn take(&mut self, n: u64, max_ext: usize) -> Option<Vec<(u64, u32)>> {
        if n == 0 {
            return Some(Vec::new());
        }
        let hit = self.runs.iter().find(|(&s, &e)| e - s >= n).map(|(&s, _)| s);
        if let Some(s) = hit {
            self.carve(s, n);
            return Some(split_u32(s, n));
        }
        if max_ext <= 1 {
            return None;
        }
        let mut by_size: Vec<(u64, u64)> = self.runs.iter().map(|(&s, &e)| (s, e - s)).collect();
        by_size.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let mut picked: Vec<(u64, u64)> = Vec::new();
        let mut got = 0u64;
        for (s, l) in by_size {
            if picked.len() >= max_ext || got >= n {
                break;
            }
            let t = l.min(n - got);
            picked.push((s, t));
            got += t;
        }
        if got < n {
            return None;
        }
        picked.sort();
        let mut out = Vec::new();
        for (s, t) in picked {
            self.carve(s, t);
            out.extend(split_u32(s, t));
        }
        Some(out)
    }
    fn give(&mut self, s: u64, e: u64) {
        if e <= s {
            return;
        }
        let (mut s, mut e) = (s, e);
        if let Some((&ps, &pe)) = self.runs.range(..=s).next_back() {
            if pe >= s {
                s = ps;
                e = e.max(pe);
            }
        }
        loop {
            let next = self.runs.range(s..).next().map(|(&a, &b)| (a, b));
            match next {
                Some((ns, ne)) if ns <= e => {
                    e = e.max(ne);
                    self.runs.remove(&ns);
                }
                _ => break,
            }
        }
        self.runs.insert(s, e);
    }
    fn give_ext(&mut self, ex: &[(u64, u32)]) {
        for &(s, n) in ex {
            self.give(s, s + n as u64);
        }
    }
}

/// Sectors in `old` that `new` no longer references.
fn freed_ranges(old: &[(u64, u32)], new: &[(u64, u32)]) -> Vec<(u64, u64)> {
    let mut o: Vec<(u64, u64)> = old.iter().map(|&(s, n)| (s, s + n as u64)).collect();
    o.sort();
    if new.is_empty() {
        return o;
    }
    let mut nw: Vec<(u64, u64)> = new.iter().map(|&(s, n)| (s, s + n as u64)).collect();
    nw.sort();
    let mut out = Vec::new();
    let mut j = 0;
    for (s, e) in o {
        let mut cur = s;
        while j < nw.len() && nw[j].1 <= cur {
            j += 1;
        }
        let mut k = j;
        while k < nw.len() && nw[k].0 < e {
            if nw[k].0 > cur {
                out.push((cur, nw[k].0));
            }
            cur = cur.max(nw[k].1);
            k += 1;
        }
        if cur < e {
            out.push((cur, e));
        }
    }
    out
}

/// Split an extent list after `at` sectors (the left part has exactly `at` sectors, or everything if shorter).
fn split_extents(ex: &[(u64, u32)], at: u64) -> (Vec<(u64, u32)>, Vec<(u64, u32)>) {
    let (mut left, mut right) = (Vec::new(), Vec::new());
    let mut pos = 0u64;
    for &(s, n) in ex {
        let n64 = n as u64;
        if pos + n64 <= at {
            left.push((s, n));
        } else if pos >= at {
            right.push((s, n));
        } else {
            let k = at - pos;
            left.push((s, k as u32));
            right.push((s + k, (n64 - k) as u32));
        }
        pos += n64;
    }
    (left, right)
}

fn merge_adjacent(ex: Vec<(u64, u32)>) -> Vec<(u64, u32)> {
    let mut out: Vec<(u64, u32)> = Vec::with_capacity(ex.len());
    for (s, n) in ex {
        if n == 0 {
            continue;
        }
        if let Some(l) = out.last_mut() {
            if l.0 + l.1 as u64 == s && (l.1 as u64 + n as u64) <= u32::MAX as u64 {
                l.1 += n;
                continue;
            }
        }
        out.push((s, n));
    }
    out
}

/// Read `count` sectors starting at file sector `first` of an extent list into `out` (one device request per extent piece).
fn read_sectors<D: BlockDev>(dev: &mut D, ex: &[(u64, u32)], first: u64, count: u64, out: &mut [u8]) -> Result<(), StoreErr> {
    let mut pos = 0u64;
    let mut done = 0u64;
    for &(s, n) in ex {
        let n64 = n as u64;
        let end = pos + n64;
        if end > first && done < count {
            let skip = first.max(pos) - pos;
            let take = (n64 - skip).min(count - done);
            dev.read(s + skip, &mut out[(done as usize) * SECTOR..((done + take) as usize) * SECTOR])?;
            done += take;
        }
        pos = end;
        if done == count {
            break;
        }
    }
    if done != count {
        return Err(StoreErr::Corrupt);
    }
    Ok(())
}

/// Write `data` (a multiple of the sector size) starting at file sector `first` of an extent list.
fn write_sectors<D: BlockDev>(dev: &mut D, ex: &[(u64, u32)], first: u64, data: &[u8]) -> Result<(), StoreErr> {
    let count = (data.len() / SECTOR) as u64;
    let mut pos = 0u64;
    let mut done = 0u64;
    for &(s, n) in ex {
        let n64 = n as u64;
        let end = pos + n64;
        if end > first && done < count {
            let skip = first.max(pos) - pos;
            let take = (n64 - skip).min(count - done);
            dev.write(s + skip, &data[(done as usize) * SECTOR..((done + take) as usize) * SECTOR])?;
            done += take;
        }
        pos = end;
        if done == count {
            break;
        }
    }
    if done != count {
        return Err(StoreErr::Corrupt);
    }
    Ok(())
}

/// Write the bytes of `data` into freshly allocated `extents` without copying (only a sub-sector tail is padded).
fn write_data<D: BlockDev>(dev: &mut D, extents: &[(u64, u32)], data: &[u8]) -> Result<(), StoreErr> {
    let full = data.len() / SECTOR * SECTOR;
    if full > 0 {
        write_sectors(dev, extents, 0, &data[..full])?;
    }
    if full < data.len() {
        let mut tail = [0u8; SECTOR];
        tail[..data.len() - full].copy_from_slice(&data[full..]);
        write_sectors(dev, extents, (full / SECTOR) as u64, &tail)?;
    }
    Ok(())
}

fn used_list(inodes: &BTreeMap<u32, Inode>, meta: (u64, u64), meta2: u64, log: (u64, u64, u64)) -> Vec<(u64, u64)> {
    let mut u: Vec<(u64, u64)> = Vec::new();
    for i in inodes.values() {
        for &(s, n) in &i.extents {
            u.push((s, s + n as u64));
        }
    }
    if meta.1 > 0 {
        u.push((meta.0, meta.0 + meta.1));
    }
    if meta2 != 0 {
        u.push((meta2, meta2 + meta.1));
    }
    if log.1 > 0 {
        u.push((log.0, log.0 + log.1));
    }
    u
}

/// Build the new content of chunks `c0..=c1` (old data merged with `data` at `off`, gaps zero) in batches of at most
/// 16 chunks, write it into `new_ex` and return the chunk CRCs.
#[allow(clippy::too_many_arguments)]
fn build_region<D: BlockDev>(
    dev: &mut D,
    oext: &[(u64, u32)],
    ochunks: &[u32],
    osize: u64,
    new_ex: &[(u64, u32)],
    c0: u64,
    c1: u64,
    new_size: u64,
    off: u64,
    data: &[u8],
) -> Result<Vec<u32>, StoreErr> {
    let end = off + data.len() as u64;
    let mut crcs: Vec<u32> = Vec::with_capacity((c1 - c0 + 1) as usize);
    let mut written = 0u64;
    let mut buf: Vec<u8> = Vec::new();
    let mut oldtmp: Vec<u8> = Vec::new();
    let mut c = c0;
    while c <= c1 {
        let be = (c + 15).min(c1);
        let bstart = c * CHUNK_U;
        let bend = ((be + 1) * CHUNK_U).min(new_size);
        let nsect = sectors_for(bend - bstart);
        buf.clear();
        buf.resize(nsect as usize * SECTOR, 0);
        for k in c..=be {
            let ks = k * CHUNK_U;
            let ke = (ks + CHUNK_U).min(new_size);
            let rel = (ks - bstart) as usize;
            let dst = &mut buf[rel..rel + (ke - ks) as usize];
            if ks < osize {
                let old_end = (ks + CHUNK_U).min(osize);
                let covers = !data.is_empty() && off <= ks && end >= old_end;
                if !covers {
                    let olen = old_end - ks;
                    let ns = sectors_for(olen);
                    oldtmp.clear();
                    oldtmp.resize(ns as usize * SECTOR, 0);
                    read_sectors(dev, oext, k * CHUNK_SECT, ns, &mut oldtmp)?;
                    if (k as usize) < ochunks.len() && crc32(&oldtmp[..olen as usize]) != ochunks[k as usize] {
                        return Err(StoreErr::Corrupt);
                    }
                    dst[..olen as usize].copy_from_slice(&oldtmp[..olen as usize]);
                }
            }
            if !data.is_empty() {
                let lo = off.max(ks);
                let hi = end.min(ke);
                if lo < hi {
                    dst[(lo - ks) as usize..(hi - ks) as usize].copy_from_slice(&data[(lo - off) as usize..(hi - off) as usize]);
                }
            }
            crcs.push(crc32(dst));
        }
        write_sectors(dev, new_ex, written, &buf)?;
        written += nsect;
        c = be + 1;
    }
    Ok(crcs)
}

pub struct Store<D: BlockDev> {
    dev: D,
    total: u64,
    gen: u64,
    /// slot (0 or 1) holding the committed root record
    cur_slot: u8,
    inodes: BTreeMap<u32, Inode>,
    next_ino: u32,
    /// committed metadata extent (start, sectors); (0, 0) while a v1 directory is still the committed state
    meta: (u64, u64),
    /// checkpoint bookkeeping for the root record: (image bytes, image CRC, next inode counter at the checkpoint, checkpoint generation)
    ck: (u32, u32, u32, u64),
    /// start of the mirror copy of the checkpoint image (0 = none)
    meta2: u64,
    /// commit log extent (start, capacity, used) in sectors; capacity 0 = no log (every commit is a checkpoint)
    log: (u64, u64, u64),
    free: FreeMap,
    /// set when a commit failed after the root record may have reached the disk: the in-memory state can no
    /// longer be trusted to match the disk, so every further mutation is refused until the next mount
    poisoned: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct StoreStats {
    pub total_bytes: u64,
    pub data_bytes: u64,
    pub used_bytes: u64,
    pub files: usize,
    pub dirs: usize,
    pub generation: u64,
}

fn superblock(total: u64) -> Vec<u8> {
    let mut sb = vec![0u8; SECTOR];
    sb[0..8].copy_from_slice(SB_MAGIC);
    sb[8..12].copy_from_slice(&VERSION.to_le_bytes());
    sb[16..24].copy_from_slice(&total.to_le_bytes());
    sb[24..28].copy_from_slice(&(DIR_SECTORS as u32).to_le_bytes());
    sb[32..40].copy_from_slice(&DATA_START.to_le_bytes());
    let c = crc32(&sb[..SECTOR - 4]);
    sb[SECTOR - 4..].copy_from_slice(&c.to_le_bytes());
    sb
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
        let mut map = BTreeMap::new();
        map.insert(ROOT, Inode::dir(0o755, now_secs()));
        let meta = encode_meta(&[(ROOT, &map[&ROOT])], ROOT + 1);
        let msect = sectors_for(meta.len() as u64);
        let mut padded = meta.clone();
        padded.resize(msect as usize * SECTOR, 0);
        // metadata first, then slot B invalidated, slot A written, superblock last: a half-formatted disk has no valid superblock
        dev.write(DATA_START, &padded)?;
        dev.write(1 + DIR_SECTORS, &vec![0u8; SECTOR])?;
        let meta2 = DATA_START + msect;
        let log = (meta2 + msect, 128u64, 0u64);
        if log.0 + log.1 > total {
            return Err(StoreErr::NoSpace);
        }
        dev.write(meta2, &padded)?;
        let mcrc = crc32(&meta);
        dev.write(1, &encode_root(1, 1, DATA_START, meta2, meta.len() as u32, mcrc, ROOT + 1, log))?;
        dev.flush()?;
        dev.write(0, &superblock(total))?;
        dev.flush()?;
        let mut used = vec![(DATA_START, log.0 + log.1)];
        let free = FreeMap::new(total, &mut used);
        Ok(Store { dev, total, gen: 1, cur_slot: 0, inodes: map, next_ino: ROOT + 1, meta: (DATA_START, msect), ck: (meta.len() as u32, mcrc, ROOT + 1, 1), meta2, log, free, poisoned: false })
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
        let ver = u32::from_le_bytes(sb[8..12].try_into().unwrap());
        if crc32(&sb[..SECTOR - 4]) != c || !(ver == 1 || ver == 2) || total > dev.sectors() || total < DATA_START + 8 {
            return Err((StoreErr::Corrupt, dev));
        }
        // (generation, slot, tree, next inode, metadata extent, checkpoint info, log)
        type Cand = (u64, u8, BTreeMap<u32, Inode>, u32, (u64, u64), u64, (u32, u32, u32, u64), (u64, u64, u64));
        let mut best: Option<Cand> = None;
        for slot in 0..2u8 {
            let base = 1 + slot as u64 * DIR_SECTORS;
            let mut first = vec![0u8; SECTOR];
            if let Err(e) = dev.read(base, &mut first) {
                return Err((e.into(), dev));
            }
            let is3 = &first[0..8] == ROOT3_MAGIC;
            let cand: Option<Cand> = if is3 || &first[0..8] == ROOT_MAGIC {
                let crc_end = if is3 { 72 } else { 40 };
                let ok = u32::from_le_bytes(first[crc_end..crc_end + 4].try_into().unwrap()) == crc32(&first[0..crc_end]);
                if !ok {
                    None
                } else {
                    let gen = u64::from_le_bytes(first[8..16].try_into().unwrap());
                    let mstart = u64::from_le_bytes(first[16..24].try_into().unwrap());
                    let mlen = u32::from_le_bytes(first[24..28].try_into().unwrap()) as usize;
                    let mcrc = u32::from_le_bytes(first[28..32].try_into().unwrap());
                    let rnext = u32::from_le_bytes(first[32..36].try_into().unwrap());
                    let mstart2 = if is3 { u64::from_le_bytes(first[64..72].try_into().unwrap()) } else { 0 };
                    let (ckpt_gen, log) = if is3 {
                        (
                            u64::from_le_bytes(first[40..48].try_into().unwrap()),
                            (
                                u64::from_le_bytes(first[48..56].try_into().unwrap()),
                                u32::from_le_bytes(first[56..60].try_into().unwrap()) as u64,
                                u32::from_le_bytes(first[60..64].try_into().unwrap()) as u64,
                            ),
                        )
                    } else {
                        (gen, (0, 0, 0))
                    };
                    let nsect = sectors_for(mlen as u64);
                    let log_ok = log.2 <= log.1 && (log.1 == 0 || (log.0 >= DATA_START && log.0.checked_add(log.1).map_or(false, |e| e <= total)));
                    if mlen == 0 || mlen > MAX_META_BYTES || mstart < DATA_START || mstart.checked_add(nsect).map_or(true, |e| e > total) || ckpt_gen > gen || !log_ok {
                        None
                    } else {
                        let mut buf = vec![0u8; nsect as usize * SECTOR];
                        if let Err(e) = dev.read(mstart, &mut buf) {
                            return Err((e.into(), dev));
                        }
                        buf.truncate(mlen);
                        if crc32(&buf) != mcrc && mstart2 >= DATA_START && mstart2.checked_add(nsect).map_or(false, |e| e <= total) {
                            // primary image damaged: use the mirror copy
                            buf.resize(nsect as usize * SECTOR, 0);
                            if let Err(e) = dev.read(mstart2, &mut buf) {
                                return Err((e.into(), dev));
                            }
                            buf.truncate(mlen);
                        }
                        if crc32(&buf) != mcrc {
                            None
                        } else {
                            match decode_meta_raw(&buf, total) {
                                Some((mut map, next)) if rnext == next => {
                                    // the stored counter must agree with the image; then replay the commit log on top
                                    let mut final_next = Some(next);
                                    if log.2 > 0 {
                                        let mut lb = vec![0u8; log.2 as usize * SECTOR];
                                        if let Err(e) = dev.read(log.0, &mut lb) {
                                            return Err((e.into(), dev));
                                        }
                                        final_next = replay_log(&mut map, &lb, ckpt_gen, gen, total, next);
                                    } else if gen != ckpt_gen {
                                        final_next = None;
                                    }
                                    final_next.and_then(|n| validate_tree(&map).then_some((gen, slot, map, n, (mstart, nsect), mstart2, (mlen as u32, mcrc, next, ckpt_gen), log)))
                                }
                                _ => None,
                            }
                        }
                    }
                }
            } else if &first[0..8] == DIR_MAGIC {
                // v1 flat directory
                let mut img = vec![0u8; DIR_BYTES];
                if let Err(e) = dev.read(base, &mut img) {
                    return Err((e.into(), dev));
                }
                decode_dir_v1(&img, total).map(|(g, files)| {
                    let (map, next) = tree_from_v1(&files);
                    (g, slot, map, next, (0, 0), 0, (0, 0, 0, 0), (0, 0, 0))
                })
            } else {
                None
            };
            if let Some(c) = cand {
                if best.as_ref().map_or(true, |b| c.0 > b.0) {
                    best = Some(c);
                }
            }
        }
        match best {
            Some((gen, cur_slot, inodes, next_ino, meta, meta2, ck, log)) => {
                let mut used = used_list(&inodes, meta, meta2, log);
                let free = FreeMap::new(total, &mut used);
                Ok(Store { dev, total, gen, cur_slot, inodes, next_ino, meta, ck, meta2, log, free, poisoned: false })
            }
            None => Err((StoreErr::Corrupt, dev)),
        }
    }

    pub fn stats(&self) -> StoreStats {
        let mut used = self.meta.1 + if self.meta2 != 0 { self.meta.1 } else { 0 } + self.log.1;
        let (mut files, mut dirs) = (0, 0);
        for i in self.inodes.values() {
            match i.kind {
                Kind::File => {
                    files += 1;
                    used += i.extents.iter().map(|e| e.1 as u64).sum::<u64>();
                }
                Kind::Dir => dirs += 1,
                Kind::Symlink => files += 1,
            }
        }
        StoreStats { total_bytes: self.total * SECTOR as u64, data_bytes: (self.total - DATA_START) * SECTOR as u64, used_bytes: used * SECTOR as u64, files, dirs: dirs - 1, generation: self.gen }
    }

    fn check_writable(&self) -> Result<(), StoreErr> {
        if self.dev.read_only() || self.poisoned {
            Err(StoreErr::Io(BlkErr::ReadOnly))
        } else {
            Ok(())
        }
    }

    /// `(generation of the current checkpoint image, log sectors used, log capacity in sectors)`.
    pub fn log_state(&self) -> (u64, u64, u64) {
        (self.ck.3, self.log.2, self.log.1)
    }

    /// Free space in bytes (sectors not referenced by the committed tree).
    pub fn free_bytes(&self) -> u64 {
        self.free.free_sectors() * SECTOR as u64
    }

    /// Commit the staged overlay as the next generation (see the module docs for the ordering). `fresh` are the
    /// extents this operation allocated: they go back to the free map if the commit fails before the root record.
    fn commit(&mut self, ov: BTreeMap<u32, Option<Inode>>, next_ino: u32, fresh: &[(u64, u32)]) -> Result<(), StoreErr> {
        match self.commit_inner(ov, next_ino) {
            Ok(()) => Ok(()),
            Err((e, started)) => {
                if started {
                    self.poisoned = true;
                } else {
                    self.free.give_ext(fresh);
                }
                Err(e)
            }
        }
    }

    fn commit_inner(&mut self, ov: BTreeMap<u32, Option<Inode>>, next_ino: u32) -> Result<(), (StoreErr, bool)> {
        // Fast path: append the changes to the commit log (one sector-aligned record + the root record) instead of
        // rewriting the whole metadata image. A checkpoint (the full image) is made when the log is full.
        if self.meta.1 > 0 && self.log.1 > 0 {
            let payload = encode_delta(&ov, &self.inodes, next_ino);
            let rs = sectors_for((LOG_HDR + payload.len()) as u64);
            if payload.len() <= LOG_PAYLOAD_MAX && rs <= self.log.1 / 2 && self.log.2 + rs <= self.log.1 {
                return self.commit_delta(ov, next_ino, payload, rs);
            }
        }
        let mut merged: Vec<(u32, &Inode)> = Vec::with_capacity(self.inodes.len() + ov.len());
        for (k, v) in &self.inodes {
            if !ov.contains_key(k) {
                merged.push((*k, v));
            }
        }
        for (k, v) in &ov {
            if let Some(i) = v {
                merged.push((*k, i));
            }
        }
        merged.sort_by_key(|m| m.0);
        if merged.len() > MAX_FILES {
            return Err((StoreErr::TooManyFiles, false));
        }
        let mut meta = encode_meta(&merged, next_ino);
        drop(merged);
        if meta.len() > MAX_META_BYTES {
            return Err((StoreErr::NoSpace, false));
        }
        let mlen = meta.len();
        let mcrc = crc32(&meta);
        let msect = sectors_for(mlen as u64);
        let mstart = self.free.take(msect, 1).ok_or((StoreErr::NoSpace, false))?[0].0;
        // mirror copy of the image (if the disk is too full for it, the checkpoint is a single copy)
        let mstart2 = self.free.take(msect, 1).map_or(0, |v| v[0].0);
        // a fresh, empty commit log next to the new checkpoint (none if the disk is too full: then every commit is a checkpoint)
        let want_log = (msect / 4).clamp(128, 8192);
        let log = match self.free.take(want_log, 1) {
            Some(v) => (v[0].0, want_log, 0u64),
            None => (0, 0, 0),
        };
        meta.resize(msect as usize * SECTOR, 0);
        let new_gen = self.gen + 1;
        let slot = 1 - self.cur_slot;
        let pre = (|| -> Result<(), StoreErr> {
            self.dev.flush()?; // file data first
            self.dev.write(mstart, &meta)?;
            if mstart2 != 0 {
                self.dev.write(mstart2, &meta)?;
            }
            self.dev.flush()?; // then the metadata image
            Ok(())
        })();
        if let Err(e) = pre {
            self.free.give(mstart, mstart + msect);
            if mstart2 != 0 {
                self.free.give(mstart2, mstart2 + msect);
            }
            if log.1 > 0 {
                self.free.give(log.0, log.0 + log.1);
            }
            return Err((e, false));
        }
        let root = (|| -> Result<(), StoreErr> {
            self.dev.write(1 + slot as u64 * DIR_SECTORS, &encode_root(new_gen, new_gen, mstart, mstart2, mlen as u32, mcrc, next_ino, log))?;
            self.dev.flush()?; // the root record commits
            Ok(())
        })();
        if let Err(e) = root {
            return Err((e, true));
        }
        // the new root is durable: what the old tree referenced and the new one does not becomes free
        let mut freed: Vec<(u64, u64)> = Vec::new();
        for (k, v) in &ov {
            if let Some(old) = self.inodes.get(k) {
                if !old.extents.is_empty() {
                    let new_ex: &[(u64, u32)] = match v {
                        Some(i) => &i.extents,
                        None => &[],
                    };
                    freed.extend(freed_ranges(&old.extents, new_ex));
                }
            }
        }
        if self.meta.1 > 0 {
            freed.push((self.meta.0, self.meta.0 + self.meta.1));
        }
        if self.meta2 != 0 {
            freed.push((self.meta2, self.meta2 + self.meta.1));
        }
        if self.log.1 > 0 {
            freed.push((self.log.0, self.log.0 + self.log.1));
        }
        for (k, v) in ov {
            match v {
                Some(i) => {
                    self.inodes.insert(k, i);
                }
                None => {
                    self.inodes.remove(&k);
                }
            }
        }
        for (a, b) in freed {
            self.free.give(a, b);
        }
        self.next_ino = next_ino;
        self.gen = new_gen;
        self.cur_slot = slot;
        self.meta = (mstart, msect);
        self.ck = (mlen as u32, mcrc, next_ino, new_gen);
        self.meta2 = mstart2;
        self.log = log;
        Ok(())
    }

    /// Append one record to the commit log and commit it with a new root record (same checkpoint, longer log).
    fn commit_delta(&mut self, ov: BTreeMap<u32, Option<Inode>>, next_ino: u32, payload: Vec<u8>, rs: u64) -> Result<(), (StoreErr, bool)> {
        let new_gen = self.gen + 1;
        let slot = 1 - self.cur_slot;
        let mut rec = vec![0u8; rs as usize * SECTOR];
        rec[0..4].copy_from_slice(&LOG_MAGIC.to_le_bytes());
        rec[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        rec[8..12].copy_from_slice(&crc32(&payload).to_le_bytes());
        rec[16..24].copy_from_slice(&new_gen.to_le_bytes());
        rec[LOG_HDR..LOG_HDR + payload.len()].copy_from_slice(&payload);
        let pre = (|| -> Result<(), StoreErr> {
            self.dev.flush()?; // file data first
            self.dev.write(self.log.0 + self.log.2, &rec)?;
            self.dev.flush()?; // then the log record (beyond the committed end: the old root ignores it)
            Ok(())
        })();
        if let Err(e) = pre {
            return Err((e, false));
        }
        let new_log = (self.log.0, self.log.1, self.log.2 + rs);
        let root = (|| -> Result<(), StoreErr> {
            self.dev.write(1 + slot as u64 * DIR_SECTORS, &encode_root(new_gen, self.ck.3, self.meta.0, self.meta2, self.ck.0, self.ck.1, self.ck.2, new_log))?;
            self.dev.flush()?;
            Ok(())
        })();
        if let Err(e) = root {
            return Err((e, true));
        }
        let mut freed: Vec<(u64, u64)> = Vec::new();
        for (k, v) in &ov {
            if let Some(old) = self.inodes.get(k) {
                if !old.extents.is_empty() {
                    let new_ex: &[(u64, u32)] = match v {
                        Some(i) => &i.extents,
                        None => &[],
                    };
                    freed.extend(freed_ranges(&old.extents, new_ex));
                }
            }
        }
        for (k, v) in ov {
            match v {
                Some(i) => {
                    self.inodes.insert(k, i);
                }
                None => {
                    self.inodes.remove(&k);
                }
            }
        }
        for (a, b) in freed {
            self.free.give(a, b);
        }
        self.next_ino = next_ino;
        self.gen = new_gen;
        self.cur_slot = slot;
        self.log = new_log;
        Ok(())
    }

    /// Read all bytes of a file inode (CRC verified). Only for files up to `MAX_INMEM_BYTES`.
    fn read_inode(dev: &mut D, i: &Inode) -> Result<Vec<u8>, StoreErr> {
        if i.size == 0 {
            return Ok(Vec::new());
        }
        if i.size > MAX_INMEM_BYTES as u64 {
            return Err(StoreErr::TooLarge);
        }
        let nsect = sectors_for(i.size);
        let mut out = vec![0u8; nsect as usize * SECTOR];
        read_sectors(dev, &i.extents, 0, nsect, &mut out)?;
        out.truncate(i.size as usize);
        if i.chunks.is_empty() {
            if crc32(&out) != i.crc {
                return Err(StoreErr::Corrupt);
            }
        } else {
            for (k, c) in out.chunks(CHUNK).enumerate() {
                if crc32(c) != i.chunks[k] {
                    return Err(StoreErr::Corrupt);
                }
            }
        }
        Ok(out)
    }

    /// Read `buf.len()` bytes at `off` (fewer at end of file), verifying the CRC of every 64 KiB chunk touched.
    /// Whole chunks inside the range are read straight into `buf`; only the partial chunks at the ends use a temporary.
    fn read_range(dev: &mut D, i: &Inode, off: u64, buf: &mut [u8]) -> Result<usize, StoreErr> {
        if off >= i.size || buf.is_empty() {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(i.size - off) as usize;
        let buf = &mut buf[..n];
        if i.chunks.is_empty() {
            // legacy file (one whole-file CRC): verify it all, then slice
            let all = Self::read_inode(dev, i)?;
            buf.copy_from_slice(&all[off as usize..off as usize + n]);
            return Ok(n);
        }
        let end = off + n as u64;
        let full = |k: u64| (k + 1) * CHUNK_U <= i.size && (k + 1) * CHUNK_U <= end;
        let mut pos = off;
        let mut tmp: Vec<u8> = Vec::new();
        while pos < end {
            let c = pos / CHUNK_U;
            let cstart = c * CHUNK_U;
            if pos == cstart && full(c) {
                let mut last = c;
                while full(last + 1) {
                    last += 1;
                }
                let bytes = ((last - c + 1) * CHUNK_U) as usize;
                let dst = &mut buf[(pos - off) as usize..(pos - off) as usize + bytes];
                read_sectors(dev, &i.extents, c * CHUNK_SECT, (last - c + 1) * CHUNK_SECT, dst)?;
                for (k, piece) in dst.chunks(CHUNK).enumerate() {
                    if crc32(piece) != i.chunks[(c as usize) + k] {
                        return Err(StoreErr::Corrupt);
                    }
                }
                pos += bytes as u64;
            } else {
                let valid = (cstart + CHUNK_U).min(i.size) - cstart;
                let nsect = sectors_for(valid);
                tmp.clear();
                tmp.resize(nsect as usize * SECTOR, 0);
                read_sectors(dev, &i.extents, c * CHUNK_SECT, nsect, &mut tmp)?;
                if crc32(&tmp[..valid as usize]) != i.chunks[c as usize] {
                    return Err(StoreErr::Corrupt);
                }
                let lo = pos - cstart;
                let hi = (end - cstart).min(valid);
                buf[(pos - off) as usize..(pos - off + hi - lo) as usize].copy_from_slice(&tmp[lo as usize..hi as usize]);
                pos += hi - lo;
            }
        }
        Ok(n)
    }

    // ------------------------------------------------------------ queries ---

    pub fn stat(&self, path: &str, follow: bool) -> Result<Stat, StoreErr> {
        let tx = Tx::new(&self.inodes, self.next_ino);
        let ino = walk(&tx, path, follow)?;
        Ok(tx.get(ino).ok_or(StoreErr::Corrupt)?.stat(ino))
    }

    pub fn readdir(&self, path: &str) -> Result<Vec<DirEntry>, StoreErr> {
        let tx = Tx::new(&self.inodes, self.next_ino);
        let ino = walk(&tx, path, true)?;
        let d = tx.get(ino).ok_or(StoreErr::Corrupt)?;
        if d.kind != Kind::Dir {
            return Err(StoreErr::NotDir);
        }
        let mut out = Vec::with_capacity(d.entries.len());
        for (name, &c) in &d.entries {
            let ci = tx.get(c).ok_or(StoreErr::Corrupt)?;
            out.push(DirEntry { name: name.clone(), kind: ci.kind, size: ci.size, ino: c });
        }
        Ok(out)
    }

    /// Canonical path of an existing entry (symlinks expanded; the last one only when `follow`).
    pub fn realpath(&self, path: &str, follow: bool) -> Result<String, StoreErr> {
        let tx = Tx::new(&self.inodes, self.next_ino);
        walk_full(&tx, path, follow).map(|r| r.1.join("/"))
    }

    /// Canonical path for a file that may not exist yet: the parent must exist, the last name is kept as is.
    pub fn realpath_new(&self, path: &str) -> Result<String, StoreErr> {
        let tx = Tx::new(&self.inodes, self.next_ino);
        let (parent, name) = walk_parent(&tx, path)?;
        let mut comps = comps_of(path);
        comps.pop_back();
        let pp: Vec<String> = comps.into_iter().collect();
        let (pi, mut names) = walk_full(&tx, &pp.join("/"), true)?;
        debug_assert_eq!(pi, parent);
        names.push(name);
        Ok(names.join("/"))
    }

    pub fn readlink(&self, path: &str) -> Result<String, StoreErr> {
        let tx = Tx::new(&self.inodes, self.next_ino);
        let ino = walk(&tx, path, false)?;
        let i = tx.get(ino).ok_or(StoreErr::Corrupt)?;
        if i.kind != Kind::Symlink {
            return Err(StoreErr::Invalid);
        }
        Ok(i.target.clone())
    }

    /// Read a whole file (symlinks followed).
    pub fn read(&mut self, path: &str) -> Result<Vec<u8>, StoreErr> {
        let inode = {
            let tx = Tx::new(&self.inodes, self.next_ino);
            let ino = walk(&tx, path, true)?;
            let i = tx.get(ino).ok_or(StoreErr::Corrupt)?;
            match i.kind {
                Kind::Dir => return Err(StoreErr::IsDir),
                Kind::Symlink => return Err(StoreErr::Invalid),
                Kind::File => i.clone(),
            }
        };
        Self::read_inode(&mut self.dev, &inode)
    }

    /// Read up to `buf.len()` bytes of a file at byte offset `off`; returns the number of bytes read (0 at or past
    /// the end). Only the 64 KiB chunks that overlap the range are read and verified.
    pub fn read_at(&mut self, path: &str, off: u64, buf: &mut [u8]) -> Result<usize, StoreErr> {
        let ino = {
            let tx = Tx::new(&self.inodes, self.next_ino);
            walk(&tx, path, true)?
        };
        let i = self.inodes.get(&ino).ok_or(StoreErr::Corrupt)?;
        match i.kind {
            Kind::Dir => return Err(StoreErr::IsDir),
            Kind::Symlink => return Err(StoreErr::Invalid),
            Kind::File => {}
        }
        Self::read_range(&mut self.dev, i, off, buf)
    }

    /// Files directly in the root directory (the flat v1 view).
    pub fn list(&self) -> Vec<Entry> {
        let Some(root) = self.inodes.get(&ROOT) else { return Vec::new() };
        let mut out = Vec::new();
        for (name, c) in &root.entries {
            if let Some(i) = self.inodes.get(c) {
                if i.kind == Kind::File {
                    out.push(Entry { name: name.clone(), start: i.extents.first().map_or(0, |e| e.0), size: i.size, crc: i.crc });
                }
            }
        }
        out
    }

    // ------------------------------------------------------------ mutations ---

    /// Create or atomically replace the file `path` (the parent directory must exist). Mode and ownership of an
    /// existing file are kept. At most `MAX_INMEM_BYTES`; bigger files are built with `write_at`.
    pub fn write(&mut self, path: &str, data: &[u8]) -> Result<(), StoreErr> {
        self.check_writable()?;
        if data.len() > MAX_INMEM_BYTES {
            return Err(StoreErr::TooLarge);
        }
        let now = now_secs();
        let mut tx = Tx::new(&self.inodes, self.next_ino);
        let existing = match walk(&tx, path, true) {
            Ok(ino) => {
                let i = tx.get(ino).ok_or(StoreErr::Corrupt)?;
                match i.kind {
                    Kind::Dir => return Err(StoreErr::IsDir),
                    Kind::Symlink => return Err(StoreErr::Invalid),
                    Kind::File => Some((ino, i.mode)),
                }
            }
            Err(StoreErr::NotFound) => None,
            Err(e) => return Err(e),
        };
        let (parent, name) = walk_parent(&tx, path)?;
        if existing.is_none() && tx.get(parent).ok_or(StoreErr::Corrupt)?.entries.contains_key(&name) {
            return Err(StoreErr::NotFound); // a dangling symlink: creating through it is not supported
        }
        // data goes straight from the caller's buffer to free extents of the committed state
        let nsect = sectors_for(data.len() as u64);
        let extents = self.free.take(nsect, ALLOC_FRAGS).ok_or(StoreErr::NoSpace)?;
        if let Err(e) = write_data(&mut self.dev, &extents, data) {
            self.free.give_ext(&extents);
            return Err(e);
        }
        let chunks = chunk_crcs(data);
        let crc = table_crc(&chunks);
        match existing {
            Some((ino, mode)) => {
                tx.put(ino, Inode::file(mode, now, data.len() as u64, crc, extents.clone(), chunks));
            }
            None => {
                let ino = match tx.fresh() {
                    Ok(n) => n,
                    Err(e) => {
                        self.free.give_ext(&extents);
                        return Err(e);
                    }
                };
                tx.put(ino, Inode::file(0o644, now, data.len() as u64, crc, extents.clone(), chunks));
                let mut p = tx.get(parent).ok_or(StoreErr::Corrupt)?.clone();
                p.entries.insert(name, ino);
                p.mtime = now;
                tx.put(parent, p);
            }
        }
        let (ov, nx) = tx.finish();
        self.commit(ov, nx, &extents)
    }

    /// Write `data` at byte offset `off` (creating the file if it does not exist; a gap past the end reads as
    /// zeros). Copy-on-write at 64 KiB chunk granularity: only the chunks the range touches are rewritten into
    /// free space, the rest of the file is not read or written. One atomic commit.
    pub fn write_at(&mut self, path: &str, off: u64, data: &[u8]) -> Result<(), StoreErr> {
        if data.is_empty() {
            return Ok(());
        }
        self.modify(path, off, data, None)
    }

    /// Set the size of an existing file (shrinking frees the tail; growing zero-fills).
    pub fn truncate(&mut self, path: &str, len: u64) -> Result<(), StoreErr> {
        self.modify(path, 0, &[], Some(len))
    }

    fn modify(&mut self, path: &str, off: u64, data: &[u8], set_len: Option<u64>) -> Result<(), StoreErr> {
        self.check_writable()?;
        let end = off.checked_add(data.len() as u64).ok_or(StoreErr::TooLarge)?;
        if end > MAX_FILE_BYTES as u64 || set_len.map_or(false, |l| l > MAX_FILE_BYTES as u64) {
            return Err(StoreErr::TooLarge);
        }
        let lookup = |inodes: &BTreeMap<u32, Inode>, next: u32| {
            let tx = Tx::new(inodes, next);
            walk(&tx, path, true)
        };
        let ino = match lookup(&self.inodes, self.next_ino) {
            Ok(n) => n,
            Err(StoreErr::NotFound) if set_len.is_none() => {
                self.write(path, &[])?;
                lookup(&self.inodes, self.next_ino)?
            }
            Err(e) => return Err(e),
        };
        let (mode, osize, oext, mut ochunks, legacy) = {
            let i = self.inodes.get(&ino).ok_or(StoreErr::Corrupt)?;
            match i.kind {
                Kind::Dir => return Err(StoreErr::IsDir),
                Kind::Symlink => return Err(StoreErr::Invalid),
                Kind::File => {}
            }
            (i.mode, i.size, i.extents.clone(), i.chunks.clone(), i.chunks.is_empty() && i.size > 0)
        };
        if legacy {
            // a v2 file has one whole-file CRC: verify it once and derive the chunk table
            let i = self.inodes.get(&ino).ok_or(StoreErr::Corrupt)?;
            let all = Self::read_inode(&mut self.dev, i)?;
            ochunks = chunk_crcs(&all);
        }
        let now = now_secs();
        let new_size = match set_len {
            Some(l) => l,
            None => osize.max(end),
        };
        let mut ov: BTreeMap<u32, Option<Inode>> = BTreeMap::new();

        if new_size < osize {
            // ---- shrink: keep a prefix of the extents; only the new last chunk's CRC changes
            let keep = sectors_for(new_size);
            let (left, _) = split_extents(&oext, keep);
            ochunks.truncate(new_size.div_ceil(CHUNK_U) as usize);
            if new_size % CHUNK_U != 0 {
                let c = new_size / CHUNK_U;
                let cstart = c * CHUNK_U;
                let old_valid = (cstart + CHUNK_U).min(osize) - cstart;
                let nsect = sectors_for(old_valid);
                let mut tmp = vec![0u8; nsect as usize * SECTOR];
                let old_crc = {
                    let i = self.inodes.get(&ino).ok_or(StoreErr::Corrupt)?;
                    if i.chunks.is_empty() { None } else { Some(i.chunks[c as usize]) }
                };
                read_sectors(&mut self.dev, &oext, c * CHUNK_SECT, nsect, &mut tmp)?;
                if let Some(oc) = old_crc {
                    if crc32(&tmp[..old_valid as usize]) != oc {
                        return Err(StoreErr::Corrupt);
                    }
                }
                ochunks[c as usize] = crc32(&tmp[..(new_size - cstart) as usize]);
            }
            let tc = table_crc(&ochunks);
            ov.insert(ino, Some(Inode::file(mode, now, new_size, tc, merge_adjacent(left), ochunks)));
            return self.commit(ov, self.next_ino, &[]);
        }

        // ---- grow / overwrite: [wlo, whi) is the byte range that has to be materialised
        let (wlo, whi) = if data.is_empty() { (osize, new_size) } else { (off.min(osize), end) };
        if whi <= wlo {
            return Ok(());
        }
        let c0 = wlo / CHUNK_U;
        let c1 = (whi - 1) / CHUNK_U;
        let reg_start = c0 * CHUNK_U;
        let reg_end = ((c1 + 1) * CHUNK_U).min(new_size);
        let nsec = sectors_for(reg_end - reg_start);
        let new_ex = self.free.take(nsec, ALLOC_FRAGS).ok_or(StoreErr::NoSpace)?;
        let crcs = match build_region(&mut self.dev, &oext, &ochunks, osize, &new_ex, c0, c1, new_size, off, data) {
            Ok(c) => c,
            Err(e) => {
                self.free.give_ext(&new_ex);
                return Err(e);
            }
        };
        let (left, rest) = split_extents(&oext, c0 * CHUNK_SECT);
        let (_, right) = split_extents(&rest, (c1 + 1 - c0) * CHUNK_SECT);
        let mut all = left;
        all.extend_from_slice(&new_ex);
        all.extend(right);
        let extents = merge_adjacent(all);
        let mut chunks: Vec<u32> = ochunks[..(c0 as usize).min(ochunks.len())].to_vec();
        chunks.extend_from_slice(&crcs);
        if ((c1 + 1) as usize) < ochunks.len() {
            chunks.extend_from_slice(&ochunks[(c1 + 1) as usize..]);
        }
        let total_sect: u64 = extents.iter().map(|e| e.1 as u64).sum();
        if extents.len() > MAX_EXTENTS || total_sect != sectors_for(new_size) || chunks.len() as u64 != new_size.div_ceil(CHUNK_U) {
            self.free.give_ext(&new_ex);
            return Err(if extents.len() > MAX_EXTENTS { StoreErr::NoSpace } else { StoreErr::Corrupt });
        }
        let tc = table_crc(&chunks);
        ov.insert(ino, Some(Inode::file(mode, now, new_size, tc, extents, chunks)));
        self.commit(ov, self.next_ino, &new_ex)
    }

    pub fn mkdir(&mut self, path: &str) -> Result<(), StoreErr> {
        self.check_writable()?;
        let now = now_secs();
        let mut tx = Tx::new(&self.inodes, self.next_ino);
        let (parent, name) = walk_parent(&tx, path)?;
        if tx.get(parent).ok_or(StoreErr::Corrupt)?.entries.contains_key(&name) {
            return Err(StoreErr::Exists);
        }
        let ino = tx.fresh()?;
        tx.put(ino, Inode::dir(0o755, now));
        let mut p = tx.get(parent).ok_or(StoreErr::Corrupt)?.clone();
        p.entries.insert(name, ino);
        p.mtime = now;
        tx.put(parent, p);
        let (ov, nx) = tx.finish();
        self.commit(ov, nx, &[])
    }

    pub fn rmdir(&mut self, path: &str) -> Result<(), StoreErr> {
        self.check_writable()?;
        let now = now_secs();
        let mut tx = Tx::new(&self.inodes, self.next_ino);
        let (parent, name) = walk_parent(&tx, path)?;
        let ino = *tx.get(parent).ok_or(StoreErr::Corrupt)?.entries.get(&name).ok_or(StoreErr::NotFound)?;
        let d = tx.get(ino).ok_or(StoreErr::Corrupt)?;
        if d.kind != Kind::Dir {
            return Err(StoreErr::NotDir);
        }
        if !d.entries.is_empty() {
            return Err(StoreErr::NotEmpty);
        }
        let mut p = tx.get(parent).ok_or(StoreErr::Corrupt)?.clone();
        p.entries.remove(&name);
        p.mtime = now;
        tx.put(parent, p);
        tx.del(ino);
        let (ov, nx) = tx.finish();
        self.commit(ov, nx, &[])
    }

    /// Remove a file or symlink (not a directory).
    pub fn unlink(&mut self, path: &str) -> Result<(), StoreErr> {
        self.check_writable()?;
        let now = now_secs();
        let mut tx = Tx::new(&self.inodes, self.next_ino);
        let (parent, name) = walk_parent(&tx, path)?;
        let ino = *tx.get(parent).ok_or(StoreErr::Corrupt)?.entries.get(&name).ok_or(StoreErr::NotFound)?;
        if tx.get(ino).ok_or(StoreErr::Corrupt)?.kind == Kind::Dir {
            return Err(StoreErr::IsDir);
        }
        let mut p = tx.get(parent).ok_or(StoreErr::Corrupt)?.clone();
        p.entries.remove(&name);
        p.mtime = now;
        tx.put(parent, p);
        tx.del(ino);
        let (ov, nx) = tx.finish();
        self.commit(ov, nx, &[])
    }

    /// v1 name for `unlink`.
    pub fn delete(&mut self, path: &str) -> Result<(), StoreErr> {
        self.unlink(path)
    }

    /// Atomic rename (one commit). A file replaces a file or symlink, a directory replaces an empty directory.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), StoreErr> {
        self.check_writable()?;
        let now = now_secs();
        let mut tx = Tx::new(&self.inodes, self.next_ino);
        let (fp, fname) = walk_parent(&tx, from)?;
        let ino = *tx.get(fp).ok_or(StoreErr::Corrupt)?.entries.get(&fname).ok_or(StoreErr::NotFound)?;
        let (tp, tname) = walk_parent(&tx, to)?;
        let moving_dir = tx.get(ino).ok_or(StoreErr::Corrupt)?.kind == Kind::Dir;
        if moving_dir && contains_dir(&tx, ino, tp) {
            return Err(StoreErr::Invalid);
        }
        let replaced = tx.get(tp).ok_or(StoreErr::Corrupt)?.entries.get(&tname).copied();
        if let Some(t) = replaced {
            if t == ino {
                return Ok(());
            }
            let ti = tx.get(t).ok_or(StoreErr::Corrupt)?;
            match (moving_dir, ti.kind) {
                (true, Kind::Dir) => {
                    if !ti.entries.is_empty() {
                        return Err(StoreErr::NotEmpty);
                    }
                }
                (true, _) => return Err(StoreErr::NotDir),
                (false, Kind::Dir) => return Err(StoreErr::IsDir),
                (false, _) => {}
            }
        }
        let mut f = tx.get(fp).ok_or(StoreErr::Corrupt)?.clone();
        f.entries.remove(&fname);
        f.mtime = now;
        tx.put(fp, f);
        let mut t = tx.get(tp).ok_or(StoreErr::Corrupt)?.clone();
        t.entries.insert(tname, ino);
        t.mtime = now;
        tx.put(tp, t);
        if let Some(old) = replaced {
            tx.del(old);
        }
        let (ov, nx) = tx.finish();
        self.commit(ov, nx, &[])
    }

    pub fn symlink(&mut self, target: &str, path: &str) -> Result<(), StoreErr> {
        self.check_writable()?;
        if target.is_empty() || target.len() > SYMLINK_MAX || target.bytes().any(|b| b == 0) {
            return Err(StoreErr::BadName);
        }
        let now = now_secs();
        let mut tx = Tx::new(&self.inodes, self.next_ino);
        let (parent, name) = walk_parent(&tx, path)?;
        if tx.get(parent).ok_or(StoreErr::Corrupt)?.entries.contains_key(&name) {
            return Err(StoreErr::Exists);
        }
        let ino = tx.fresh()?;
        tx.put(ino, Inode::symlink(target, now));
        let mut p = tx.get(parent).ok_or(StoreErr::Corrupt)?.clone();
        p.entries.insert(name, ino);
        p.mtime = now;
        tx.put(parent, p);
        let (ov, nx) = tx.finish();
        self.commit(ov, nx, &[])
    }

    /// Change the permission bits (stored and reported by `stat`; they do not gate access, capabilities do).
    pub fn chmod(&mut self, path: &str, mode: u16) -> Result<(), StoreErr> {
        self.check_writable()?;
        let mut tx = Tx::new(&self.inodes, self.next_ino);
        let ino = walk(&tx, path, true)?;
        let mut i = tx.get(ino).ok_or(StoreErr::Corrupt)?.clone();
        i.mode = mode & 0o7777;
        tx.put(ino, i);
        let (ov, nx) = tx.finish();
        self.commit(ov, nx, &[])
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

/// Build a v1 store image (flat directory, `DLXDIR01` slot A, superblock version 1) for the migration tests.
#[cfg(feature = "selftest")]
pub fn format_v1_for_test(dev: &mut RamDisk, files: &[(&str, &[u8])]) {
    let total = dev.sectors();
    let mut dir = vec![0u8; DIR_BYTES];
    dir[0..8].copy_from_slice(DIR_MAGIC);
    dir[8..16].copy_from_slice(&1u64.to_le_bytes());
    dir[16..20].copy_from_slice(&(files.len() as u32).to_le_bytes());
    let mut pos = DATA_START;
    for (i, (name, data)) in files.iter().enumerate() {
        let o = 32 + i * V1_ENTRY_SIZE;
        dir[o..o + name.len()].copy_from_slice(name.as_bytes());
        dir[o + 48..o + 56].copy_from_slice(&pos.to_le_bytes());
        dir[o + 56..o + 60].copy_from_slice(&(data.len() as u32).to_le_bytes());
        dir[o + 60..o + 64].copy_from_slice(&crc32(data).to_le_bytes());
        let n = sectors_for(data.len() as u64);
        let mut padded = data.to_vec();
        padded.resize(n as usize * SECTOR, 0);
        if n > 0 {
            dev.write(pos, &padded).unwrap();
        }
        pos += n;
    }
    let c = crc32(&dir);
    dir[20..24].copy_from_slice(&c.to_le_bytes());
    dev.write(1, &dir).unwrap();
    dev.write(1 + DIR_SECTORS, &vec![0u8; SECTOR]).unwrap();
    let mut sb = superblock(total);
    sb[8..12].copy_from_slice(&1u32.to_le_bytes());
    let c = crc32(&sb[..SECTOR - 4]);
    sb[SECTOR - 4..].copy_from_slice(&c.to_le_bytes());
    dev.write(0, &sb).unwrap();
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
