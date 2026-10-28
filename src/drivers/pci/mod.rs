//! PCI enumeration: ACPI MCFG (ECAM) with a legacy 0xCF8/0xCFC fallback, BAR sizing.
//!
//! Only bus walking and config access live here; drivers (virtio) claim devices from
//! [`devices`]. Port access is confined to this module.

use alloc::vec::Vec;
use log::{info, warn};
use spin::Once;
use x86_64::instructions::port::Port;

use crate::sync::IrqMutex;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Bdf {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bar {
    None,
    Io { base: u32, size: u32 },
    Mem { base: u64, size: u64, prefetch: bool, is64: bool },
}

#[derive(Clone, Debug)]
pub struct PciDevice {
    pub bdf: Bdf,
    pub vendor: u16,
    pub device: u16,
    pub revision: u8,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub header_type: u8,
    pub bars: [Bar; 6],
    pub irq_line: u8,
}

struct Cfg {
    /// ECAM windows copied from ACPI: (base, start_bus, end_bus)
    windows: [(u64, u8, u8); 4],
    nwindows: usize,
    /// Mapped 1 MiB ECAM page-run per bus (0 = not mapped yet).
    bus_map: [usize; 256],
    use_ecam: bool,
}

static CFG: IrqMutex<Cfg> = IrqMutex::new(Cfg { windows: [(0, 0, 0); 4], nwindows: 0, bus_map: [0; 256], use_ecam: false });
static DEVICES: Once<Vec<PciDevice>> = Once::new();

fn legacy_read(b: Bdf, off: u16) -> u32 {
    let addr = 0x8000_0000u32 | (b.bus as u32) << 16 | (b.dev as u32) << 11 | (b.func as u32) << 8 | (off as u32 & 0xFC);
    // SAFETY: 0xCF8/0xCFC are the architectural PCI config mechanism #1 ports; the caller
    // holds the CFG lock so the address/data pair is atomic.
    unsafe {
        Port::<u32>::new(0xCF8).write(addr);
        Port::<u32>::new(0xCFC).read()
    }
}

fn legacy_write(b: Bdf, off: u16, v: u32) {
    let addr = 0x8000_0000u32 | (b.bus as u32) << 16 | (b.dev as u32) << 11 | (b.func as u32) << 8 | (off as u32 & 0xFC);
    // SAFETY: see `legacy_read`.
    unsafe {
        Port::<u32>::new(0xCF8).write(addr);
        Port::<u32>::new(0xCFC).write(v);
    }
}

impl Cfg {
    fn ecam_ptr(&mut self, b: Bdf, off: u16) -> Option<*mut u32> {
        if !self.use_ecam || off >= 4096 {
            return None;
        }
        let base = match self.bus_map[b.bus as usize] {
            0 => {
                let (wbase, wstart) = self.windows[..self.nwindows]
                    .iter()
                    .find(|w| b.bus >= w.1 && b.bus <= w.2)
                    .map(|w| (w.0, w.1))?;
                let phys = wbase.checked_add((b.bus - wstart) as u64 * (1 << 20))?;
                let v = crate::mm::vmm::map_mmio(phys, 1 << 20)? as usize;
                self.bus_map[b.bus as usize] = v;
                v
            }
            v => v,
        };
        Some((base + ((b.dev as usize) << 15 | (b.func as usize) << 12 | (off as usize & 0xFFC))) as *mut u32)
    }
    fn read(&mut self, b: Bdf, off: u16) -> u32 {
        match self.ecam_ptr(b, off) {
            // SAFETY: pointer is inside an ECAM window mapped uncached by `ecam_ptr`.
            Some(p) => unsafe { core::ptr::read_volatile(p) },
            None => legacy_read(b, off),
        }
    }
    fn write(&mut self, b: Bdf, off: u16, v: u32) {
        match self.ecam_ptr(b, off) {
            // SAFETY: see `read`.
            Some(p) => unsafe { core::ptr::write_volatile(p, v) },
            None => legacy_write(b, off, v),
        }
    }
}

pub fn cfg_read32(b: Bdf, off: u16) -> u32 {
    CFG.lock().read(b, off)
}
pub fn cfg_write32(b: Bdf, off: u16, v: u32) {
    CFG.lock().write(b, off, v)
}
pub fn cfg_read16(b: Bdf, off: u16) -> u16 {
    (cfg_read32(b, off & !3) >> ((off & 2) * 8)) as u16
}
pub fn cfg_read8(b: Bdf, off: u16) -> u8 {
    (cfg_read32(b, off & !3) >> ((off & 3) * 8)) as u8
}
pub fn cfg_write16(b: Bdf, off: u16, v: u16) {
    let mut c = CFG.lock();
    let sh = (off & 2) * 8;
    let old = c.read(b, off & !3);
    c.write(b, off & !3, (old & !(0xFFFFu32 << sh)) | (v as u32) << sh);
}
/// Legacy-mechanism read, independent of ECAM (used by the self test to cross-check).
pub fn legacy_read32(b: Bdf, off: u16) -> u32 {
    let _g = CFG.lock();
    legacy_read(b, off)
}
pub fn using_ecam() -> bool {
    CFG.lock().use_ecam
}

fn size_bar(b: Bdf, idx: usize) -> (Bar, usize) {
    let off = 0x10 + 4 * idx as u16;
    let raw = cfg_read32(b, off);
    cfg_write32(b, off, 0xFFFF_FFFF);
    let probe = cfg_read32(b, off);
    cfg_write32(b, off, raw);
    if probe == 0 {
        return (Bar::None, 1);
    }
    if raw & 1 == 1 {
        let mask = probe & 0xFFFF_FFFC;
        let size = (!mask).wrapping_add(1) & 0xFFFF;
        return (Bar::Io { base: raw & 0xFFFF_FFFC, size }, 1);
    }
    let is64 = (raw >> 1) & 3 == 2;
    let prefetch = raw & 8 != 0;
    if is64 && idx < 5 {
        let off_hi = off + 4;
        let raw_hi = cfg_read32(b, off_hi);
        cfg_write32(b, off_hi, 0xFFFF_FFFF);
        let probe_hi = cfg_read32(b, off_hi);
        cfg_write32(b, off_hi, raw_hi);
        let mask = (probe_hi as u64) << 32 | (probe & 0xFFFF_FFF0) as u64;
        let size = (!mask).wrapping_add(1);
        let base = (raw_hi as u64) << 32 | (raw & 0xFFFF_FFF0) as u64;
        (Bar::Mem { base, size, prefetch, is64: true }, 2)
    } else {
        let mask = probe & 0xFFFF_FFF0;
        let size = (!mask).wrapping_add(1) as u64;
        (Bar::Mem { base: (raw & 0xFFFF_FFF0) as u64, size, prefetch, is64: false }, 1)
    }
}

fn probe_function(b: Bdf, out: &mut Vec<PciDevice>, todo: &mut Vec<u8>) {
    let id = cfg_read32(b, 0);
    if id & 0xFFFF == 0xFFFF {
        return;
    }
    let cr = cfg_read32(b, 8);
    let header_type = cfg_read8(b, 0x0E) & 0x7F;
    let mut bars = [Bar::None; 6];
    if header_type == 0 || header_type == 1 {
        // Disable decoding while sizing, then restore.
        let cmd = cfg_read16(b, 4);
        cfg_write16(b, 4, cmd & !0x7);
        let nbars = if header_type == 0 { 6 } else { 2 };
        let mut i = 0;
        while i < nbars {
            let (bar, used) = size_bar(b, i);
            bars[i] = bar;
            i += used;
        }
        cfg_write16(b, 4, cmd);
    }
    if header_type == 1 {
        let secondary = cfg_read8(b, 0x19);
        if secondary != 0 && !todo.contains(&secondary) {
            todo.push(secondary);
        }
    }
    out.push(PciDevice {
        bdf: b,
        vendor: id as u16,
        device: (id >> 16) as u16,
        revision: cr as u8,
        prog_if: (cr >> 8) as u8,
        subclass: (cr >> 16) as u8,
        class: (cr >> 24) as u8,
        header_type,
        bars,
        irq_line: cfg_read8(b, 0x3C),
    });
}

/// Enumerate the bus hierarchy and log every function.
pub fn init() {
    if let Some(acpi) = crate::arch::x86_64::acpi::info() {
        let mut c = CFG.lock();
        for e in acpi.mcfg() {
            if e.segment == 0 && c.nwindows < 4 {
                let n = c.nwindows;
                c.windows[n] = (e.base, e.start_bus, e.end_bus);
                c.nwindows += 1;
            }
        }
        c.use_ecam = c.nwindows > 0;
    }
    info!("pci: config access via {}", if using_ecam() { "ECAM (ACPI MCFG)" } else { "legacy ports 0xCF8/0xCFC" });

    let mut devs = Vec::new();
    let mut todo: Vec<u8> = alloc::vec![0];
    let mut scanned: Vec<u8> = Vec::new();
    while let Some(bus) = todo.pop() {
        if scanned.contains(&bus) {
            continue;
        }
        scanned.push(bus);
        for dev in 0..32u8 {
            let f0 = Bdf { bus, dev, func: 0 };
            if cfg_read32(f0, 0) & 0xFFFF == 0xFFFF {
                continue;
            }
            let multi = cfg_read8(f0, 0x0E) & 0x80 != 0;
            for func in 0..if multi { 8 } else { 1 } {
                probe_function(Bdf { bus, dev, func }, &mut devs, &mut todo);
            }
        }
    }
    for d in &devs {
        info!(
            "pci: {:02x}:{:02x}.{} {:04x}:{:04x} class {:02x}:{:02x} irq {}",
            d.bdf.bus, d.bdf.dev, d.bdf.func, d.vendor, d.device, d.class, d.subclass, d.irq_line
        );
        for (i, b) in d.bars.iter().enumerate() {
            match *b {
                Bar::Mem { base, size, is64, .. } => info!("pci:     BAR{} mem {:#x} size {:#x}{}", i, base, size, if is64 { " (64-bit)" } else { "" }),
                Bar::Io { base, size } => info!("pci:     BAR{} io  {:#x} size {:#x}", i, base, size),
                Bar::None => {}
            }
        }
    }
    if devs.is_empty() {
        warn!("pci: no devices found");
    }
    info!("pci: {} function(s) on {} bus(es)", devs.len(), scanned.len());
    DEVICES.call_once(|| devs);
}

pub fn devices() -> &'static [PciDevice] {
    DEVICES.get().map(|v| v.as_slice()).unwrap_or(&[])
}

pub fn find(vendor: u16, device: u16) -> Option<&'static PciDevice> {
    devices().iter().find(|d| d.vendor == vendor && d.device == device)
}

/// Enable memory decoding and bus mastering (needed for DMA) on a device.
pub fn enable_bus_master(b: Bdf) {
    let cmd = cfg_read16(b, 4);
    cfg_write16(b, 4, cmd | 0x2 | 0x4); // memory space + bus master
}
