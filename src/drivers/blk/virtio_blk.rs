//! virtio-blk driver (VirtIO 1.x modern transport, polled, one request in flight).
//!
//! Every request is a 3-descriptor chain: header (device reads) -> data -> status byte (device writes).
//! Completion is polled with an iteration bound (interrupts may be disabled inside syscalls, so the
//! tick counter cannot be used as a clock). A timeout leaves the device in an unknown state: the driver
//! resets it and refuses further I/O (fail-stop rather than risk silent corruption).

use x86_64::structures::paging::{PhysFrame, Size4KiB};

use super::{BlkErr, SECTOR};
use crate::drivers::pci::{self, PciDevice};
use crate::drivers::virtio::{self, Transport, VirtQueue};
use crate::mm::{frame, vmm};

const F_VERSION_1: u64 = 1 << 32;
const F_RO: u64 = 1 << 5;
const F_FLUSH: u64 = 1 << 9;
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;
const QSZ: u16 = 8;
/// Largest transfer per request: one 4 KiB bounce frame (8 sectors).
pub const MAX_SECTORS_PER_REQ: u64 = 8;
const SPIN_LIMIT: u64 = 400_000_000;

pub struct VirtioBlk {
    t: Transport,
    q: VirtQueue,
    /// frame 0: request header (16 B) + status byte at 16; frame 1: data bounce buffer
    hdr: PhysFrame<Size4KiB>,
    data: PhysFrame<Size4KiB>,
    capacity: u64,
    read_only: bool,
    flush: bool,
    failed: bool,
    pub reads: u64,
    pub writes: u64,
}

impl VirtioBlk {
    pub fn probe(d: &PciDevice) -> Result<VirtioBlk, &'static str> {
        pci::enable_bus_master(d.bdf);
        let t = Transport::new(d)?;
        t.negotiate(F_VERSION_1 | F_RO | F_FLUSH)?;
        // device config: capacity u64 at offset 0 (len >= 6 was checked; blk needs 8, read defensively below)
        // SAFETY: virtio-blk device config starts with the 64-bit capacity in 512-byte sectors.
        let capacity = unsafe { core::ptr::read_volatile(t.device_cfg as *const u64) };
        let feats_ro = Self::device_features(&t) & F_RO != 0;
        let flush = Self::device_features(&t) & F_FLUSH != 0;
        let mut q = VirtQueue::new(0, QSZ).ok_or("blk ring alloc")?;
        t.enable_queue(0, &q)?;
        q.set_notify(t.notify_ptr(0));
        t.driver_ok();
        let hdr = frame::allocate_frame().ok_or("blk hdr alloc")?;
        let data = frame::allocate_frame().ok_or("blk data alloc")?;
        if capacity == 0 {
            return Err("virtio-blk reports zero capacity");
        }
        Ok(VirtioBlk { t, q, hdr, data, capacity, read_only: feats_ro, flush, failed: false, reads: 0, writes: 0 })
    }

    fn device_features(t: &Transport) -> u64 {
        // Offered features were already validated by `negotiate`; re-read them through the common config is not
        // exposed, so approximate from the status: use the accepted subset recorded by the device after FEATURES_OK.
        // (QEMU honours F_RO/F_FLUSH only when offered, and `negotiate` accepts exactly offered & wanted.)
        t.accepted()
    }

    pub fn capacity_sectors(&self) -> u64 {
        self.capacity
    }
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }
    pub fn is_failed(&self) -> bool {
        self.failed
    }

    fn request(&mut self, ty: u32, sector: u64, nsec: u64, write_data: Option<&[u8]>, read_buf: Option<&mut [u8]>) -> Result<(), BlkErr> {
        if self.failed {
            return Err(BlkErr::Io);
        }
        if ty != T_FLUSH {
            if nsec == 0 || nsec > MAX_SECTORS_PER_REQ {
                return Err(BlkErr::Invalid);
            }
            if sector.checked_add(nsec).map_or(true, |e| e > self.capacity) {
                return Err(BlkErr::OutOfRange);
            }
        }
        if ty == T_OUT && self.read_only {
            return Err(BlkErr::ReadOnly);
        }
        let h = vmm::phys_to_virt(self.hdr.start_address());
        let dptr = vmm::phys_to_virt(self.data.start_address());
        let len = (nsec as usize) * SECTOR;
        // SAFETY: both frames are exclusively owned HHDM-mapped DMA memory; sizes are bounded above.
        unsafe {
            core::ptr::write_volatile(h as *mut u32, ty);
            core::ptr::write_volatile(h.add(4) as *mut u32, 0);
            core::ptr::write_volatile(h.add(8) as *mut u64, sector);
            core::ptr::write_volatile(h.add(16), 0xFF); // status sentinel
            if let Some(w) = write_data {
                core::ptr::copy_nonoverlapping(w.as_ptr(), dptr, len.min(w.len()));
            }
        }
        let hp = self.hdr.start_address().as_u64();
        let dp = self.data.start_address().as_u64();
        if ty == T_FLUSH {
            self.q.post_chain(&[(hp, 16, false), (hp + 16, 1, true)]);
        } else {
            self.q.post_chain(&[(hp, 16, false), (dp, len as u32, ty == T_IN), (hp + 16, 1, true)]);
        }
        self.q.notify();
        let mut spins = 0u64;
        loop {
            if self.q.poll_used().is_some() {
                break;
            }
            spins += 1;
            if spins > SPIN_LIMIT {
                self.failed = true;
                self.t.reset();
                return Err(BlkErr::Timeout);
            }
            core::hint::spin_loop();
        }
        // SAFETY: status byte written by the device inside our header frame.
        let st = unsafe { core::ptr::read_volatile(h.add(16)) };
        if st != 0 {
            return Err(BlkErr::Io);
        }
        if let Some(r) = read_buf {
            // SAFETY: the device filled `len` bytes of the bounce frame.
            unsafe { core::ptr::copy_nonoverlapping(dptr, r.as_mut_ptr(), len.min(r.len())) };
        }
        Ok(())
    }

    /// Read `buf.len() / 512` sectors (buf length must be a multiple of 512).
    pub fn read(&mut self, mut sector: u64, buf: &mut [u8]) -> Result<(), BlkErr> {
        if buf.len() % SECTOR != 0 {
            return Err(BlkErr::Invalid);
        }
        for chunk in buf.chunks_mut(MAX_SECTORS_PER_REQ as usize * SECTOR) {
            let n = (chunk.len() / SECTOR) as u64;
            self.request(T_IN, sector, n, None, Some(chunk))?;
            sector += n;
            self.reads += n;
        }
        Ok(())
    }

    pub fn write(&mut self, mut sector: u64, buf: &[u8]) -> Result<(), BlkErr> {
        if buf.len() % SECTOR != 0 {
            return Err(BlkErr::Invalid);
        }
        for chunk in buf.chunks(MAX_SECTORS_PER_REQ as usize * SECTOR) {
            let n = (chunk.len() / SECTOR) as u64;
            self.request(T_OUT, sector, n, Some(chunk), None)?;
            sector += n;
            self.writes += n;
        }
        Ok(())
    }

    /// Ask the device to make all completed writes durable (no-op if the device has no flush feature).
    pub fn flush(&mut self) -> Result<(), BlkErr> {
        if !self.flush {
            return Ok(());
        }
        self.request(T_FLUSH, 0, 0, None, None)
    }
}

pub fn probe_first() -> Option<Result<VirtioBlk, &'static str>> {
    virtio::find_devices(0x1042, 0x1001).first().map(|d| VirtioBlk::probe(d))
}
