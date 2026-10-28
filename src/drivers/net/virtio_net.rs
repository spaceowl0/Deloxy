//! virtio-net driver (VirtIO 1.x, polled). `probe` leaves the device inert; `start` brings it up.

use alloc::vec::Vec;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use crate::drivers::pci::{self, PciDevice};
use crate::drivers::virtio::{self, Transport, VirtQueue};
use crate::mm::{frame, vmm};

const F_MAC: u64 = 1 << 5;
const F_VERSION_1: u64 = 1 << 32;
const HDR: usize = 12; // virtio_net_hdr with VERSION_1 (num_buffers present)
const QSZ: u16 = 32;
pub const MAX_FRAME: usize = 1514;

pub struct VirtioNet {
    t: Transport,
    mac: [u8; 6],
    rx: Option<VirtQueue>,
    tx: Option<VirtQueue>,
    rx_bufs: Vec<PhysFrame<Size4KiB>>,
    tx_bufs: Vec<PhysFrame<Size4KiB>>,
    tx_free: Vec<u16>,
    running: bool,
    pub tx_frames: u64,
    pub rx_frames: u64,
}

impl VirtioNet {
    /// Reset the device and negotiate features. The device is NOT started: no queues, no DRIVER_OK.
    pub fn probe(d: &PciDevice) -> Result<VirtioNet, &'static str> {
        pci::enable_bus_master(d.bdf);
        let t = Transport::new(d)?;
        t.negotiate(F_VERSION_1 | F_MAC)?;
        let mut mac = [0u8; 6];
        for (i, m) in mac.iter_mut().enumerate() {
            // SAFETY: device config space holds the 6-byte MAC at offset 0 (len checked >= 6 in Transport::new).
            *m = unsafe { core::ptr::read_volatile(t.device_cfg.add(i)) };
        }
        // Park the device again: reset leaves it inert until `start`.
        t.reset();
        Ok(VirtioNet { t, mac, rx: None, tx: None, rx_bufs: Vec::new(), tx_bufs: Vec::new(), tx_free: Vec::new(), running: false, tx_frames: 0, rx_frames: 0 })
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }
    pub fn is_running(&self) -> bool {
        self.running
    }
    /// Raw device status register (0 while inert).
    pub fn device_status(&self) -> u8 {
        self.t.read_status()
    }

    /// Set up both queues, post RX buffers and set DRIVER_OK.
    pub fn start(&mut self) -> Result<(), &'static str> {
        if self.running {
            return Ok(());
        }
        self.t.negotiate(F_VERSION_1 | F_MAC)?;
        if self.rx.is_none() {
            self.rx = Some(VirtQueue::new(0, QSZ).ok_or("rx ring alloc")?);
            self.tx = Some(VirtQueue::new(1, QSZ).ok_or("tx ring alloc")?);
            for _ in 0..QSZ {
                self.rx_bufs.push(frame::allocate_frame().ok_or("rx buffer alloc")?);
                self.tx_bufs.push(frame::allocate_frame().ok_or("tx buffer alloc")?);
            }
        }
        let (rx, tx) = (self.rx.as_mut().unwrap(), self.tx.as_mut().unwrap());
        rx.reset();
        tx.reset();
        self.t.enable_queue(0, rx)?;
        self.t.enable_queue(1, tx)?;
        rx.set_notify(self.t.notify_ptr(0));
        tx.set_notify(self.t.notify_ptr(1));
        for (i, f) in self.rx_bufs.iter().enumerate() {
            rx.post(i as u16, f.start_address().as_u64(), 2048, true);
        }
        self.tx_free = (0..QSZ).rev().collect();
        self.t.driver_ok();
        rx.notify();
        self.running = true;
        Ok(())
    }

    /// Reset the device: it can no longer send or receive anything.
    pub fn stop(&mut self) {
        self.t.reset();
        self.running = false;
    }

    pub fn can_send(&mut self) -> bool {
        self.reclaim_tx();
        self.running && !self.tx_free.is_empty()
    }

    fn reclaim_tx(&mut self) {
        if let Some(tx) = self.tx.as_mut() {
            while let Some((slot, _)) = tx.poll_used() {
                if !self.tx_free.contains(&slot) {
                    self.tx_free.push(slot);
                }
            }
        }
    }

    /// Queue one Ethernet frame (<= 1514 bytes). Returns false when the ring is full or the NIC is stopped.
    pub fn send(&mut self, frame_bytes: &[u8]) -> bool {
        if !self.running || frame_bytes.len() > MAX_FRAME {
            return false;
        }
        self.reclaim_tx();
        let Some(slot) = self.tx_free.pop() else { return false };
        let buf = self.tx_bufs[slot as usize];
        let v = vmm::phys_to_virt(buf.start_address());
        // SAFETY: the TX buffer frame is owned by this driver, HHDM-mapped, 4096 bytes; HDR+len <= 1526.
        unsafe {
            core::ptr::write_bytes(v, 0, HDR);
            core::ptr::copy_nonoverlapping(frame_bytes.as_ptr(), v.add(HDR), frame_bytes.len());
        }
        let tx = self.tx.as_mut().unwrap();
        tx.post(slot, buf.start_address().as_u64(), (HDR + frame_bytes.len()) as u32, false);
        tx.notify();
        self.tx_frames += 1;
        true
    }

    /// Copy the next received frame into `out`; returns its length.
    pub fn recv(&mut self, out: &mut [u8; MAX_FRAME]) -> Option<usize> {
        if !self.running {
            return None;
        }
        let rx = self.rx.as_mut()?;
        let (slot, len) = rx.poll_used()?;
        let buf = self.rx_bufs[slot as usize];
        let total = len as usize;
        let mut n = None;
        if total > HDR && total - HDR <= MAX_FRAME && total <= 2048 {
            let v = vmm::phys_to_virt(buf.start_address());
            // SAFETY: the device wrote `total` <= 2048 bytes into this driver-owned frame.
            unsafe { core::ptr::copy_nonoverlapping(v.add(HDR), out.as_mut_ptr(), total - HDR) };
            n = Some(total - HDR);
            self.rx_frames += 1;
        }
        rx.post(slot, buf.start_address().as_u64(), 2048, true);
        rx.notify();
        n
    }
}

/// Find and probe the first virtio-net function (modern 0x1041 or transitional 0x1000).
pub fn probe_first() -> Option<Result<VirtioNet, &'static str>> {
    virtio::find_devices(0x1041, 0x1000).first().map(|d| VirtioNet::probe(d))
}
