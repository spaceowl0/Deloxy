//! AHCI (SATA) driver: the default disk controller of VirtualBox, VMware, Hyper-V gen1 (via IDE/SATA) and almost all
//! real PCs. Polled, one command slot, 48-bit LBA DMA through a 4 KiB bounce buffer, first SATA disk only.
//! `probe` only reads (IDENTIFY); it never writes anything to the disk.

use x86_64::structures::paging::{PhysFrame, Size4KiB};

use super::{BlkErr, SECTOR};
use crate::drivers::pci::{self, Bar, PciDevice};
use crate::mm::{frame, vmm};

const PORT_BASE: usize = 0x100;
const CMD_ST: u32 = 1 << 0;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;
const BOUNCE_SECTORS: usize = 8; // 4 KiB

pub struct Ahci {
    abar: *mut u8,
    port: usize,
    clb: PhysFrame<Size4KiB>,
    fis: PhysFrame<Size4KiB>,
    ctba: PhysFrame<Size4KiB>,
    bounce: PhysFrame<Size4KiB>,
    sectors: u64,
    failed: bool,
}

// SAFETY: accessed only under the store's lock.
unsafe impl Send for Ahci {}

fn zeroed() -> Option<PhysFrame<Size4KiB>> {
    let f = frame::allocate_frame()?;
    // SAFETY: fresh HHDM-mapped frame we own.
    unsafe { core::ptr::write_bytes(vmm::phys_to_virt(f.start_address()), 0, 4096) };
    Some(f)
}
fn pa(f: &PhysFrame<Size4KiB>) -> u64 {
    f.start_address().as_u64()
}
fn va(f: &PhysFrame<Size4KiB>) -> *mut u8 {
    vmm::phys_to_virt(f.start_address())
}
fn spin(n: u32) {
    for _ in 0..n {
        core::hint::spin_loop();
    }
}

impl Ahci {
    fn rd(&self, off: usize) -> u32 {
        // SAFETY: `off` is within the mapped ABAR (HBA + 32 ports x 0x80).
        unsafe { core::ptr::read_volatile(self.abar.add(off) as *const u32) }
    }
    fn wr(&self, off: usize, v: u32) {
        // SAFETY: as in `rd`.
        unsafe { core::ptr::write_volatile(self.abar.add(off) as *mut u32, v) }
    }
    fn prd(&self, r: usize) -> u32 {
        self.rd(PORT_BASE + self.port * 0x80 + r)
    }
    fn pwr(&self, r: usize, v: u32) {
        self.wr(PORT_BASE + self.port * 0x80 + r, v)
    }

    fn stop_port(&self) {
        self.pwr(0x18, self.prd(0x18) & !(CMD_ST));
        for _ in 0..500_000 {
            if self.prd(0x18) & CMD_CR == 0 {
                break;
            }
            spin(50);
        }
        self.pwr(0x18, self.prd(0x18) & !CMD_FRE);
        for _ in 0..500_000 {
            if self.prd(0x18) & CMD_FR == 0 {
                break;
            }
            spin(50);
        }
    }

    pub fn probe(d: &PciDevice) -> Result<Option<Ahci>, &'static str> {
        let Bar::Mem { base, size, .. } = d.bars[5] else { return Err("ahci: ABAR is not memory") };
        pci::enable_bus_master(d.bdf);
        let abar = vmm::map_mmio(base, (size as usize).clamp(0x1100, 0x2000)).ok_or("ahci: mmio map")?;
        let rd = |o: usize| unsafe { core::ptr::read_volatile(abar.add(o) as *const u32) };
        let wr = |o: usize, v: u32| unsafe { core::ptr::write_volatile(abar.add(o) as *mut u32, v) };
        // BIOS/OS handoff (HBA 1.2+)
        if rd(0x10) >= 0x0001_0200 && rd(0x24) & 1 != 0 {
            wr(0x28, rd(0x28) | 2);
            for _ in 0..2000 {
                if rd(0x28) & 1 == 0 {
                    break;
                }
                spin(20_000);
            }
        }
        wr(0x04, rd(0x04) | (1 << 31)); // GHC.AE
        let pi = rd(0x0C);
        for port in 0..32usize {
            if pi & (1 << port) == 0 {
                continue;
            }
            let base = PORT_BASE + port * 0x80;
            let ssts = rd(base + 0x28);
            // device present and PHY up, and it is an ATA disk (not ATAPI / port multiplier / enclosure)
            if ssts & 0xF != 3 || (ssts >> 8) & 0xF != 1 || rd(base + 0x24) != 0x0000_0101 {
                continue;
            }
            let mut a = Ahci { abar, port, clb: zeroed().ok_or("ahci: alloc")?, fis: zeroed().ok_or("ahci: alloc")?, ctba: zeroed().ok_or("ahci: alloc")?, bounce: zeroed().ok_or("ahci: alloc")?, sectors: 0, failed: false };
            a.stop_port();
            a.pwr(0x00, pa(&a.clb) as u32);
            a.pwr(0x04, (pa(&a.clb) >> 32) as u32);
            a.pwr(0x08, pa(&a.fis) as u32);
            a.pwr(0x0C, (pa(&a.fis) >> 32) as u32);
            a.pwr(0x30, 0xFFFF_FFFF); // SERR
            a.pwr(0x10, 0xFFFF_FFFF); // IS
            a.pwr(0x14, 0); // no interrupts: polled
            a.pwr(0x18, a.prd(0x18) | CMD_FRE);
            a.pwr(0x18, a.prd(0x18) | CMD_ST);
            // IDENTIFY DEVICE
            if a.command(0xEC, 0, 1, false, true).is_err() {
                continue;
            }
            let mut id = [0u16; 256];
            // SAFETY: the device wrote 512 bytes into the bounce frame.
            unsafe { core::ptr::copy_nonoverlapping(va(&a.bounce) as *const u16, id.as_mut_ptr(), 256) };
            let lba48 = id[83] & (1 << 10) != 0;
            let sectors = if lba48 { (id[100] as u64) | (id[101] as u64) << 16 | (id[102] as u64) << 32 | (id[103] as u64) << 48 } else { (id[60] as u64) | (id[61] as u64) << 16 };
            // only 512-byte logical sectors (word 106 bit 12 = longer logical sectors)
            if id[106] & (1 << 14) != 0 && id[106] & (1 << 12) != 0 {
                return Err("ahci: disk has non-512-byte logical sectors");
            }
            if !lba48 || sectors == 0 {
                return Err("ahci: disk without 48-bit LBA is not supported");
            }
            a.sectors = sectors;
            return Ok(Some(a));
        }
        Ok(None)
    }

    /// Issue one command through slot 0 and wait for completion. `data` = a data phase of `count` sectors in the
    /// bounce buffer (`write` = host -> device).
    fn command(&mut self, cmd: u8, lba: u64, count: usize, write: bool, data: bool) -> Result<(), BlkErr> {
        if self.failed {
            return Err(BlkErr::Io);
        }
        // wait for the device to be idle
        for _ in 0..200_000 {
            if self.prd(0x20) & 0x88 == 0 {
                break;
            }
            spin(50);
        }
        // SAFETY: command list/table are driver-owned 4 KiB frames; header 0 is 32 bytes, the table needs 0x80 + 16.
        unsafe {
            let h = va(&self.clb) as *mut u32;
            *h = 5 | if write { 1 << 6 } else { 0 } | if data { 1 << 16 } else { 0 }; // CFL=5 dwords, W, PRDTL
            *h.add(1) = 0;
            *h.add(2) = pa(&self.ctba) as u32;
            *h.add(3) = (pa(&self.ctba) >> 32) as u32;
            let t = va(&self.ctba);
            core::ptr::write_bytes(t, 0, 0x90);
            *t = 0x27; // H2D register FIS
            *t.add(1) = 0x80; // command
            *t.add(2) = cmd;
            *t.add(7) = 0x40; // LBA mode
            *t.add(4) = lba as u8;
            *t.add(5) = (lba >> 8) as u8;
            *t.add(6) = (lba >> 16) as u8;
            *t.add(8) = (lba >> 24) as u8;
            *t.add(9) = (lba >> 32) as u8;
            *t.add(10) = (lba >> 40) as u8;
            *t.add(12) = count as u8;
            *t.add(13) = (count >> 8) as u8;
            if data {
                let p = t.add(0x80) as *mut u32;
                *p = pa(&self.bounce) as u32;
                *p.add(1) = (pa(&self.bounce) >> 32) as u32;
                *p.add(3) = (count * SECTOR - 1) as u32;
            }
        }
        self.pwr(0x10, 0xFFFF_FFFF);
        self.pwr(0x38, 1); // CI slot 0
        for _ in 0..4_000_000 {
            if self.prd(0x38) & 1 == 0 {
                break;
            }
            if self.prd(0x10) & (1 << 30) != 0 {
                break; // task file error
            }
            spin(50);
        }
        if self.prd(0x38) & 1 != 0 || self.prd(0x10) & (1 << 30) != 0 || self.prd(0x20) & 1 != 0 {
            self.failed = true;
            return Err(BlkErr::Io);
        }
        Ok(())
    }

    pub fn capacity_sectors(&self) -> u64 {
        self.sectors
    }
    pub fn is_failed(&self) -> bool {
        self.failed
    }

    pub fn read(&mut self, mut sector: u64, buf: &mut [u8]) -> Result<(), BlkErr> {
        if buf.len() % SECTOR != 0 || sector.checked_add((buf.len() / SECTOR) as u64).map_or(true, |e| e > self.sectors) {
            return Err(BlkErr::OutOfRange);
        }
        for chunk in buf.chunks_mut(BOUNCE_SECTORS * SECTOR) {
            let n = chunk.len() / SECTOR;
            self.command(0x25, sector, n, false, true)?; // READ DMA EXT
            // SAFETY: the device filled n sectors of the bounce frame.
            unsafe { core::ptr::copy_nonoverlapping(va(&self.bounce), chunk.as_mut_ptr(), chunk.len()) };
            sector += n as u64;
        }
        Ok(())
    }

    pub fn write(&mut self, mut sector: u64, buf: &[u8]) -> Result<(), BlkErr> {
        if buf.len() % SECTOR != 0 || sector.checked_add((buf.len() / SECTOR) as u64).map_or(true, |e| e > self.sectors) {
            return Err(BlkErr::OutOfRange);
        }
        for chunk in buf.chunks(BOUNCE_SECTORS * SECTOR) {
            let n = chunk.len() / SECTOR;
            // SAFETY: bounce frame is 4 KiB >= chunk.len().
            unsafe { core::ptr::copy_nonoverlapping(chunk.as_ptr(), va(&self.bounce), chunk.len()) };
            self.command(0x35, sector, n, true, true)?; // WRITE DMA EXT
            sector += n as u64;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), BlkErr> {
        self.command(0xEA, 0, 0, false, false) // FLUSH CACHE EXT
    }
}

pub fn probe_first() -> Option<Result<Ahci, &'static str>> {
    for d in pci::devices().iter().filter(|d| d.class == 0x01 && d.subclass == 0x06 && d.prog_if == 0x01) {
        match Ahci::probe(d) {
            Ok(Some(a)) => return Some(Ok(a)),
            Ok(None) => continue,
            Err(e) => return Some(Err(e)),
        }
    }
    None
}
