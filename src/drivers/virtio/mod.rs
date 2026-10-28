//! VirtIO 1.x modern PCI transport + split virtqueues (polled, no interrupts).
//!
//! A device can be *probed* (reset, feature negotiation, MAC read) without being
//! *started*: until `DRIVER_OK` is written the device cannot move a single packet.
//! The networking layer uses that to keep the NIC inert while no `NetGrant` exists.

use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use crate::drivers::pci::{self, Bar, PciDevice};
use crate::mm::{frame, vmm};

pub const VENDOR: u16 = 0x1AF4;

pub const ST_ACK: u8 = 1;
pub const ST_DRIVER: u8 = 2;
pub const ST_DRIVER_OK: u8 = 4;
pub const ST_FEATURES_OK: u8 = 8;
pub const ST_FAILED: u8 = 128;

const CAP_COMMON: u8 = 1;
const CAP_NOTIFY: u8 = 2;
const CAP_ISR: u8 = 3;
const CAP_DEVICE: u8 = 4;

/// Mapped modern-transport register windows of one device.
pub struct Transport {
    accepted: core::cell::Cell<u64>,
    common: *mut u8,
    notify: *mut u8,
    notify_mult: u32,
    pub isr: *mut u8,
    pub device_cfg: *mut u8,
}

// SAFETY: the pointers are uncached MMIO mappings owned by the single driver instance.
unsafe impl Send for Transport {}

macro_rules! reg {
    ($name:ident, $setter:ident, $ty:ty, $off:expr) => {
        fn $name(&self) -> $ty {
            // SAFETY: `$off` is inside the mapped common-config structure (VirtIO 1.x 4.1.4.3).
            unsafe { core::ptr::read_volatile(self.common.add($off) as *const $ty) }
        }
        fn $setter(&self, v: $ty) {
            // SAFETY: as above.
            unsafe { core::ptr::write_volatile(self.common.add($off) as *mut $ty, v) }
        }
    };
}

impl Transport {
    reg!(dev_feat_sel_r, set_dev_feat_sel, u32, 0x00);
    reg!(dev_feat, _set_dev_feat, u32, 0x04);
    reg!(_drv_feat_sel_r, set_drv_feat_sel, u32, 0x08);
    reg!(_drv_feat_r, set_drv_feat, u32, 0x0C);
    reg!(num_queues, _set_nq, u16, 0x12);
    reg!(status, set_status, u8, 0x14);
    reg!(_qsel_r, set_qsel, u16, 0x16);
    reg!(qsize, set_qsize, u16, 0x18);
    reg!(_qen_r, set_qen, u16, 0x1C);
    reg!(qnotify_off, _set_qno, u16, 0x1E);
    reg!(_qdesc_r, set_qdesc, u64, 0x20);
    reg!(_qdrv_r, set_qdrv, u64, 0x28);
    reg!(_qdev_r, set_qdev, u64, 0x30);

    /// Locate and map the four capability windows. Requires bus mastering to be enabled by the caller.
    pub fn new(d: &PciDevice) -> Result<Transport, &'static str> {
        let mut caps: [Option<(u8, u32, u32)>; 5] = [None; 5];
        let mut notify_mult = 0u32;
        let status = pci::cfg_read16(d.bdf, 6);
        if status & (1 << 4) == 0 {
            return Err("no PCI capability list");
        }
        let mut ptr = pci::cfg_read8(d.bdf, 0x34) & !3;
        let mut guard = 0;
        while ptr >= 0x40 && guard < 48 {
            guard += 1;
            let id = pci::cfg_read8(d.bdf, ptr as u16);
            let next = pci::cfg_read8(d.bdf, ptr as u16 + 1);
            if id == 0x09 {
                let cfg_type = pci::cfg_read8(d.bdf, ptr as u16 + 3);
                let bar = pci::cfg_read8(d.bdf, ptr as u16 + 4);
                let off = pci::cfg_read32(d.bdf, ptr as u16 + 8);
                let len = pci::cfg_read32(d.bdf, ptr as u16 + 12);
                if (1..=4).contains(&cfg_type) && bar < 6 && caps[cfg_type as usize].is_none() {
                    caps[cfg_type as usize] = Some((bar, off, len));
                    if cfg_type == CAP_NOTIFY {
                        notify_mult = pci::cfg_read32(d.bdf, ptr as u16 + 16);
                    }
                }
            }
            ptr = next & !3;
        }
        let map = |ty: u8, min_len: u32| -> Result<*mut u8, &'static str> {
            let (bar, off, len) = caps[ty as usize].ok_or("missing virtio capability")?;
            if len < min_len {
                return Err("virtio capability too small");
            }
            match d.bars[bar as usize] {
                Bar::Mem { base, size, .. } if base != 0 => {
                    let end = (off as u64).checked_add(len as u64).ok_or("bad cap range")?;
                    if end > size {
                        return Err("virtio capability outside BAR");
                    }
                    vmm::map_mmio(base + off as u64, len as usize).ok_or("mmio map failed")
                }
                _ => Err("virtio BAR not assigned"),
            }
        };
        Ok(Transport {
            accepted: core::cell::Cell::new(0),
            common: map(CAP_COMMON, 0x38)?,
            notify: map(CAP_NOTIFY, 2)?,
            notify_mult,
            isr: map(CAP_ISR, 1)?,
            device_cfg: map(CAP_DEVICE, 6)?,
        })
    }

    pub fn reset(&self) {
        self.set_status(0);
        for _ in 0..1_000_000 {
            if self.status() == 0 {
                return;
            }
            core::hint::spin_loop();
        }
    }

    /// Reset, ACK, DRIVER, negotiate exactly `wanted` (bit 32 = VERSION_1 must be included), FEATURES_OK.
    pub fn negotiate(&self, wanted: u64) -> Result<(), &'static str> {
        self.reset();
        self.set_status(ST_ACK);
        self.set_status(ST_ACK | ST_DRIVER);
        let mut offered = 0u64;
        for sel in 0..2u32 {
            self.set_dev_feat_sel(sel);
            offered |= (self.dev_feat() as u64) << (32 * sel);
        }
        if offered & (1 << 32) == 0 {
            self.set_status(ST_FAILED);
            return Err("device does not offer VIRTIO_F_VERSION_1");
        }
        let accept = offered & wanted;
        if accept & (1 << 32) == 0 {
            return Err("VERSION_1 not accepted");
        }
        for sel in 0..2u32 {
            self.set_drv_feat_sel(sel);
            self.set_drv_feat((accept >> (32 * sel)) as u32);
        }
        self.accepted.set(accept);
        self.set_status(ST_ACK | ST_DRIVER | ST_FEATURES_OK);
        if self.status() & ST_FEATURES_OK == 0 {
            self.set_status(ST_FAILED);
            return Err("device rejected features");
        }
        Ok(())
    }

    /// Feature bits accepted by the last successful `negotiate`.
    pub fn accepted(&self) -> u64 {
        self.accepted.get()
    }

    pub fn driver_ok(&self) {
        self.set_status(ST_ACK | ST_DRIVER | ST_FEATURES_OK | ST_DRIVER_OK);
    }

    pub fn read_status(&self) -> u8 {
        self.status()
    }

    /// Program and enable queue `idx` using the ring memory of `q`.
    pub fn enable_queue(&self, idx: u16, q: &VirtQueue) -> Result<(), &'static str> {
        self.set_qsel(idx);
        let max = self.qsize();
        if max == 0 || q.size > max {
            return Err("queue unavailable or too large");
        }
        self.set_qsize(q.size);
        self.set_qdesc(q.desc_phys);
        self.set_qdrv(q.avail_phys);
        self.set_qdev(q.used_phys);
        let no = self.qnotify_off() as u64;
        let _ = no;
        self.set_qen(1);
        Ok(())
    }

    pub fn notify_ptr(&self, idx: u16) -> *mut u16 {
        self.set_qsel(idx);
        let off = self.qnotify_off() as usize * self.notify_mult as usize;
        // SAFETY: offset computed from the device-provided notify multiplier; the notify window
        // was mapped with the length advertised by the capability.
        unsafe { self.notify.add(off) as *mut u16 }
    }
}

/// Split virtqueue with one descriptor per buffer (descriptor index == buffer slot).
pub struct VirtQueue {
    pub size: u16,
    base: PhysFrame<Size4KiB>,
    frames: usize,
    desc: *mut u8,
    avail: *mut u8,
    used: *mut u8,
    pub desc_phys: u64,
    pub avail_phys: u64,
    pub used_phys: u64,
    avail_idx: u16,
    last_used: u16,
    notify: *mut u16,
    index: u16,
}

// SAFETY: raw pointers reference DMA memory owned exclusively by this queue.
unsafe impl Send for VirtQueue {}

impl VirtQueue {
    /// Allocate ring memory for `size` (power of two <= 128) descriptors.
    pub fn new(index: u16, size: u16) -> Option<VirtQueue> {
        if !size.is_power_of_two() || size > 128 {
            return None;
        }
        // desc (16*N) + avail (6+2N) share page 0; used (6+8N) gets page 1.
        let base = frame::allocate_contiguous(2, 1)?;
        let v = vmm::phys_to_virt(base.start_address());
        // SAFETY: freshly allocated, exclusively owned, HHDM-mapped frames.
        unsafe { core::ptr::write_bytes(v, 0, 8192) };
        let p = base.start_address().as_u64();
        let q = VirtQueue {
            size,
            base,
            frames: 2,
            desc: v,
            // SAFETY: offsets stay inside the 8 KiB allocation (16*128 + 6 + 2*128 < 4096).
            avail: unsafe { v.add(16 * size as usize) },
            used: unsafe { v.add(4096) },
            desc_phys: p,
            avail_phys: p + 16 * size as u64,
            used_phys: p + 4096,
            avail_idx: 0,
            last_used: 0,
            notify: core::ptr::null_mut(),
            index,
        };
        // VRING_AVAIL_F_NO_INTERRUPT: we poll.
        // SAFETY: avail flags field is inside the ring memory.
        unsafe { core::ptr::write_volatile(q.avail as *mut u16, 1) };
        Some(q)
    }

    pub fn set_notify(&mut self, p: *mut u16) {
        self.notify = p;
    }

    /// Reset ring indices and memory (after a device reset).
    pub fn reset(&mut self) {
        // SAFETY: the queue owns these 8 KiB; the device is reset so it no longer accesses them.
        unsafe { core::ptr::write_bytes(self.desc, 0, 8192) };
        self.avail_idx = 0;
        self.last_used = 0;
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(self.avail as *mut u16, 1) };
    }

    /// Publish buffer `slot` (physical address/length). `device_writes` marks RX buffers.
    pub fn post(&mut self, slot: u16, phys: u64, len: u32, device_writes: bool) {
        debug_assert!(slot < self.size);
        let d = (slot as usize) * 16;
        // SAFETY: descriptor `slot` is inside the table; ring entry index is masked by size.
        unsafe {
            core::ptr::write_volatile(self.desc.add(d) as *mut u64, phys);
            core::ptr::write_volatile(self.desc.add(d + 8) as *mut u32, len);
            core::ptr::write_volatile(self.desc.add(d + 12) as *mut u16, if device_writes { 2 } else { 0 });
            core::ptr::write_volatile(self.desc.add(d + 14) as *mut u16, 0);
            let ring = self.avail.add(4 + 2 * (self.avail_idx % self.size) as usize) as *mut u16;
            core::ptr::write_volatile(ring, slot);
        }
        fence(Ordering::SeqCst);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        // SAFETY: avail.idx is at offset 2.
        unsafe { core::ptr::write_volatile(self.avail.add(2) as *mut u16, self.avail_idx) };
        fence(Ordering::SeqCst);
    }

    /// Publish one request made of chained descriptors `0..segs.len()` (head = descriptor 0).
    /// `segs` = (phys, len, device_writes). Only one chain may be in flight (polled, synchronous use).
    pub fn post_chain(&mut self, segs: &[(u64, u32, bool)]) {
        debug_assert!(!segs.is_empty() && segs.len() <= self.size as usize);
        let n = segs.len();
        for (i, &(phys, len, w)) in segs.iter().enumerate() {
            let d = i * 16;
            let flags: u16 = (if w { 2 } else { 0 }) | (if i + 1 < n { 1 } else { 0 });
            // SAFETY: descriptor `i` is inside the table; the ring entry index is masked by the queue size.
            unsafe {
                core::ptr::write_volatile(self.desc.add(d) as *mut u64, phys);
                core::ptr::write_volatile(self.desc.add(d + 8) as *mut u32, len);
                core::ptr::write_volatile(self.desc.add(d + 12) as *mut u16, flags);
                core::ptr::write_volatile(self.desc.add(d + 14) as *mut u16, (i + 1) as u16);
            }
        }
        // SAFETY: avail ring entry and idx are inside the ring memory.
        unsafe {
            let ring = self.avail.add(4 + 2 * (self.avail_idx % self.size) as usize) as *mut u16;
            core::ptr::write_volatile(ring, 0);
        }
        fence(Ordering::SeqCst);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        // SAFETY: avail.idx is at offset 2.
        unsafe { core::ptr::write_volatile(self.avail.add(2) as *mut u16, self.avail_idx) };
        fence(Ordering::SeqCst);
    }

    pub fn notify(&self) {
        if !self.notify.is_null() {
            // SAFETY: notify pointer comes from `Transport::notify_ptr`.
            unsafe { core::ptr::write_volatile(self.notify, self.index) };
        }
    }

    /// Pop one completed buffer: `(slot, bytes_written_by_device)`.
    pub fn poll_used(&mut self) -> Option<(u16, u32)> {
        // SAFETY: used.idx at offset 2; ring entries are 8 bytes starting at offset 4.
        let idx = unsafe { core::ptr::read_volatile(self.used.add(2) as *const u16) };
        if idx == self.last_used {
            return None;
        }
        fence(Ordering::SeqCst);
        let e = (self.last_used % self.size) as usize;
        // SAFETY: entry index is masked by the queue size.
        let (id, len) = unsafe {
            (
                core::ptr::read_volatile(self.used.add(4 + 8 * e) as *const u32),
                core::ptr::read_volatile(self.used.add(8 + 8 * e) as *const u32),
            )
        };
        self.last_used = self.last_used.wrapping_add(1);
        if id >= self.size as u32 {
            return None; // corrupt device index: ignore rather than index out of range
        }
        Some((id as u16, len))
    }
}

impl Drop for VirtQueue {
    fn drop(&mut self) {
        frame::deallocate_contiguous(self.base, self.frames);
    }
}

/// Find virtio PCI functions of a given modern (0x1040+t) or transitional device id.
pub fn find_devices(modern_id: u16, transitional_id: u16) -> Vec<&'static PciDevice> {
    pci::devices().iter().filter(|d| d.vendor == VENDOR && (d.device == modern_id || d.device == transitional_id)).collect()
}
