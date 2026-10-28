//! Intel PRO/1000 (e1000 / 82540EM family) driver: the default NIC of VirtualBox and a common one in VMware, QEMU
//! (`-device e1000`) and Hyper-V gen1 legacy adapters. Legacy descriptor format, polled, 32 RX + 32 TX descriptors.
//! Like virtio-net: `probe` resets the device and leaves it inert (receiver and transmitter disabled, bus master
//! off); `start` brings it up; `stop` resets it.

use alloc::vec::Vec;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use super::MAX_FRAME;
use crate::drivers::pci::{self, Bar, PciDevice};
use crate::mm::{frame, vmm};

const RING: usize = 32;
const BUF: usize = 2048;

// registers
const CTRL: usize = 0x0000;
const STATUS: usize = 0x0008;
const IMC: usize = 0x00D8;
const RCTL: usize = 0x0100;
const TCTL: usize = 0x0400;
const TIPG: usize = 0x0410;
const RDBAL: usize = 0x2800;
const RDBAH: usize = 0x2804;
const RDLEN: usize = 0x2808;
const RDH: usize = 0x2810;
const RDT: usize = 0x2818;
const TDBAL: usize = 0x3800;
const TDBAH: usize = 0x3804;
const TDLEN: usize = 0x3808;
const TDH: usize = 0x3810;
const TDT: usize = 0x3818;
const MTA: usize = 0x5200;
const RAL0: usize = 0x5400;
const RAH0: usize = 0x5404;

const CTRL_SLU: u32 = 1 << 6;
const CTRL_RST: u32 = 1 << 26;
const RCTL_EN: u32 = 1 << 1;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_SECRC: u32 = 1 << 26;
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
const TX_CMD: u8 = 0x01 | 0x02 | 0x08; // EOP | IFCS | RS

/// PCI device ids handled (82540/82543/82544/82545/82546/82541/82547 families, 82574L, I217/I218-class "e1000e" in legacy mode).
pub const IDS: &[u16] = &[0x1000, 0x1001, 0x1004, 0x1008, 0x1009, 0x100C, 0x100D, 0x100E, 0x100F, 0x1010, 0x1011, 0x1012, 0x1013, 0x1014, 0x1015, 0x1016, 0x1017, 0x1018, 0x1019, 0x101A, 0x101D, 0x101E, 0x1026, 0x1027, 0x1028, 0x10D3, 0x153A, 0x1539];

pub struct E1000 {
    regs: *mut u8,
    bdf: pci::Bdf,
    mac: [u8; 6],
    rx_ring: Option<PhysFrame<Size4KiB>>,
    tx_ring: Option<PhysFrame<Size4KiB>>,
    rx_bufs: Vec<PhysFrame<Size4KiB>>,
    tx_bufs: Vec<PhysFrame<Size4KiB>>,
    rx_next: usize,
    tx_tail: usize,
    running: bool,
    pub tx_frames: u64,
    pub rx_frames: u64,
}

// SAFETY: the MMIO pointer is only used through `&mut self`/`&self` methods guarded by the NET lock.
unsafe impl Send for E1000 {}

impl E1000 {
    fn rd(&self, r: usize) -> u32 {
        // SAFETY: `regs` maps the 128 KiB register BAR; `r` is a valid register offset below that.
        unsafe { core::ptr::read_volatile(self.regs.add(r) as *const u32) }
    }
    fn wr(&self, r: usize, v: u32) {
        // SAFETY: as in `rd`.
        unsafe { core::ptr::write_volatile(self.regs.add(r) as *mut u32, v) }
    }

    fn reset(&self) {
        self.wr(IMC, 0xFFFF_FFFF);
        self.wr(RCTL, 0);
        self.wr(TCTL, 0);
        self.wr(CTRL, self.rd(CTRL) | CTRL_RST);
        for _ in 0..100_000 {
            if self.rd(CTRL) & CTRL_RST == 0 {
                break;
            }
            core::hint::spin_loop();
        }
        self.wr(IMC, 0xFFFF_FFFF); // interrupts stay masked: polled driver
        let _ = self.rd(0xC0); // ICR read clears pending causes
    }

    pub fn probe(d: &PciDevice) -> Result<E1000, &'static str> {
        let Bar::Mem { base, size, .. } = d.bars[0] else { return Err("e1000: BAR0 is not memory") };
        pci::enable_bus_master(d.bdf);
        let regs = vmm::map_mmio(base, (size as usize).clamp(0x20000, 0x40000)).ok_or("e1000: mmio map failed")?;
        let mut n = E1000 { regs, bdf: d.bdf, mac: [0; 6], rx_ring: None, tx_ring: None, rx_bufs: Vec::new(), tx_bufs: Vec::new(), rx_next: 0, tx_tail: 0, running: false, tx_frames: 0, rx_frames: 0 };
        n.reset();
        let (lo, hi) = (n.rd(RAL0), n.rd(RAH0));
        n.mac = [lo as u8, (lo >> 8) as u8, (lo >> 16) as u8, (lo >> 24) as u8, hi as u8, (hi >> 8) as u8];
        if n.mac == [0; 6] {
            return Err("e1000: no MAC address in the receive-address registers");
        }
        // inert: no bus mastering until start()
        let cmd = pci::cfg_read16(n.bdf, 4);
        pci::cfg_write16(n.bdf, 4, cmd & !0x4);
        Ok(n)
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }
    pub fn is_running(&self) -> bool {
        self.running
    }
    pub fn device_status(&self) -> u8 {
        if self.running { 1 } else { 0 }
    }
    /// Link up (STATUS.LU)?
    pub fn link_up(&self) -> bool {
        self.rd(STATUS) & 2 != 0
    }

    fn ring_ptr(f: &PhysFrame<Size4KiB>) -> *mut u8 {
        vmm::phys_to_virt(f.start_address())
    }

    pub fn start(&mut self) -> Result<(), &'static str> {
        if self.running {
            return Ok(());
        }
        if self.rx_ring.is_none() {
            self.rx_ring = Some(frame::allocate_frame().ok_or("e1000: ring alloc")?);
            self.tx_ring = Some(frame::allocate_frame().ok_or("e1000: ring alloc")?);
            for _ in 0..RING {
                self.rx_bufs.push(frame::allocate_frame().ok_or("e1000: rx buffer alloc")?);
                self.tx_bufs.push(frame::allocate_frame().ok_or("e1000: tx buffer alloc")?);
            }
        }
        let cmd = pci::cfg_read16(self.bdf, 4);
        pci::cfg_write16(self.bdf, 4, cmd | 0x6);
        self.reset();
        self.wr(CTRL, self.rd(CTRL) | CTRL_SLU);
        for i in 0..128 {
            self.wr(MTA + i * 4, 0);
        }
        // receive address 0 = our MAC (valid bit in RAH)
        let m = self.mac;
        self.wr(RAL0, m[0] as u32 | (m[1] as u32) << 8 | (m[2] as u32) << 16 | (m[3] as u32) << 24);
        self.wr(RAH0, m[4] as u32 | (m[5] as u32) << 8 | 1 << 31);
        let rx = Self::ring_ptr(self.rx_ring.as_ref().unwrap());
        let tx = Self::ring_ptr(self.tx_ring.as_ref().unwrap());
        // SAFETY: both rings are driver-owned, HHDM-mapped 4 KiB frames; 32 descriptors x 16 bytes fit.
        unsafe {
            core::ptr::write_bytes(rx, 0, 4096);
            core::ptr::write_bytes(tx, 0, 4096);
            for i in 0..RING {
                let d = rx.add(i * 16) as *mut u64;
                *d = self.rx_bufs[i].start_address().as_u64();
                let t = tx.add(i * 16) as *mut u64;
                *t = self.tx_bufs[i].start_address().as_u64();
                *(tx.add(i * 16 + 12)) = 1; // status DD: descriptor free
            }
        }
        let rxp = self.rx_ring.as_ref().unwrap().start_address().as_u64();
        let txp = self.tx_ring.as_ref().unwrap().start_address().as_u64();
        self.wr(RDBAL, rxp as u32);
        self.wr(RDBAH, (rxp >> 32) as u32);
        self.wr(RDLEN, (RING * 16) as u32);
        self.wr(RDH, 0);
        self.wr(RDT, (RING - 1) as u32);
        self.wr(TDBAL, txp as u32);
        self.wr(TDBAH, (txp >> 32) as u32);
        self.wr(TDLEN, (RING * 16) as u32);
        self.wr(TDH, 0);
        self.wr(TDT, 0);
        self.wr(TIPG, 0x0060_200A);
        self.wr(TCTL, TCTL_EN | TCTL_PSP | (0x0F << 4) | (0x40 << 12));
        self.wr(RCTL, RCTL_EN | RCTL_BAM | RCTL_SECRC); // unicast to our MAC + broadcast; no promiscuous mode
        self.rx_next = 0;
        self.tx_tail = 0;
        self.running = true;
        Ok(())
    }

    pub fn stop(&mut self) {
        self.reset();
        let cmd = pci::cfg_read16(self.bdf, 4);
        pci::cfg_write16(self.bdf, 4, cmd & !0x4);
        self.running = false;
    }

    pub fn can_send(&mut self) -> bool {
        if !self.running {
            return false;
        }
        let tx = Self::ring_ptr(self.tx_ring.as_ref().unwrap());
        // SAFETY: descriptor status byte of an in-range ring entry.
        unsafe { core::ptr::read_volatile(tx.add(self.tx_tail * 16 + 12)) & 1 != 0 }
    }

    pub fn send(&mut self, f: &[u8]) -> bool {
        if !self.can_send() || f.len() > MAX_FRAME || f.len() < 14 {
            return false;
        }
        let i = self.tx_tail;
        let tx = Self::ring_ptr(self.tx_ring.as_ref().unwrap());
        let buf = vmm::phys_to_virt(self.tx_bufs[i].start_address());
        let len = f.len().max(60); // the MAC pads to 60 itself only with IFCS+pad; pad explicitly
        // SAFETY: driver-owned buffer (4096 B) and descriptor; len <= 1514.
        unsafe {
            core::ptr::write_bytes(buf, 0, len);
            core::ptr::copy_nonoverlapping(f.as_ptr(), buf, f.len());
            let d = tx.add(i * 16);
            *(d.add(8) as *mut u16) = len as u16;
            *d.add(11) = TX_CMD;
            core::ptr::write_volatile(d.add(12), 0); // clear DD
        }
        self.tx_tail = (i + 1) % RING;
        self.wr(TDT, self.tx_tail as u32);
        self.tx_frames += 1;
        true
    }

    pub fn recv(&mut self, out: &mut [u8; MAX_FRAME]) -> Option<usize> {
        if !self.running {
            return None;
        }
        let i = self.rx_next;
        let rx = Self::ring_ptr(self.rx_ring.as_ref().unwrap());
        // SAFETY: descriptor i is within the ring; the device sets DD after writing the buffer.
        let (status, len) = unsafe { (core::ptr::read_volatile(rx.add(i * 16 + 12)), core::ptr::read_volatile(rx.add(i * 16 + 8) as *const u16)) };
        if status & 1 == 0 {
            return None;
        }
        let len = len as usize;
        let mut n = None;
        if status & 2 != 0 && len >= 14 && len <= MAX_FRAME && len <= BUF {
            let b = vmm::phys_to_virt(self.rx_bufs[i].start_address());
            // SAFETY: the device wrote `len` <= 2048 bytes into this driver-owned frame.
            unsafe { core::ptr::copy_nonoverlapping(b, out.as_mut_ptr(), len) };
            n = Some(len);
            self.rx_frames += 1;
        }
        // give the descriptor back
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(rx.add(i * 16 + 12), 0) };
        self.wr(RDT, i as u32);
        self.rx_next = (i + 1) % RING;
        n
    }
}

pub fn probe_first() -> Option<Result<E1000, &'static str>> {
    pci::devices().iter().find(|d| d.vendor == 0x8086 && d.class == 2 && IDS.contains(&d.device)).map(E1000::probe)
}
