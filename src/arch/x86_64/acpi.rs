//! Minimal ACPI parser: RSDP -> RSDT/XSDT -> MADT (interrupt controller topology).
//! No heap use; all results live in fixed-size arrays.

use core::ptr::read_unaligned;

use spin::Once;

#[derive(Clone, Copy, Default, Debug)]
pub struct IoApicInfo {
    pub id: u8,
    pub address: u32,
    pub gsi_base: u32,
}

#[derive(Clone, Copy, Default, Debug)]
pub struct IrqOverride {
    pub source_irq: u8,
    pub gsi: u32,
    pub flags: u16,
}

/// One PCIe ECAM window from the ACPI MCFG table.
#[derive(Clone, Copy, Default, Debug)]
pub struct McfgEntry {
    pub base: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

#[derive(Debug)]
pub struct AcpiInfo {
    pub mcfg: [McfgEntry; 4],
    pub mcfg_count: usize,
    pub lapic_address: u64,
    pub cpu_count: u32,
    pub ioapics: [IoApicInfo; 4],
    pub ioapic_count: usize,
    pub overrides: [IrqOverride; 16],
    pub override_count: usize,
}

static INFO: Once<AcpiInfo> = Once::new();

pub fn info() -> Option<&'static AcpiInfo> {
    INFO.get()
}

impl AcpiInfo {
    pub fn mcfg(&self) -> &[McfgEntry] {
        &self.mcfg[..self.mcfg_count]
    }
    pub fn ioapics(&self) -> &[IoApicInfo] {
        &self.ioapics[..self.ioapic_count]
    }
    /// Resolve an ISA IRQ to (GSI, flags). Defaults to identity, bus-default flags.
    pub fn resolve_isa_irq(&self, irq: u8) -> (u32, u16) {
        for o in &self.overrides[..self.override_count] {
            if o.source_irq == irq {
                return (o.gsi, o.flags);
            }
        }
        (irq as u32, 0)
    }
}

unsafe fn rd<T: Copy>(addr: u64) -> T {
    read_unaligned(addr as *const T)
}

/// Map `len` bytes of physical memory (ACPI tables live in BIOS/reserved areas that
/// Limine's HHDM does not cover) and return the virtual address.
unsafe fn map(phys: u64, len: usize) -> Option<u64> {
    crate::mm::vmm::map_mmio(phys, len).map(|p| p as u64)
}

/// Parse ACPI tables.
///
/// `rsdp` is the address handed over by Limine; it may be physical or an
/// HHDM-virtual address depending on the base revision, so both are accepted.
/// Every table is mapped on demand, so no HHDM coverage of ACPI memory is assumed.
///
/// # Safety
/// `rsdp` must come from the bootloader; `vmm::init` must have run.
pub unsafe fn init(rsdp: u64, hhdm: u64) -> Option<&'static AcpiInfo> {
    let rsdp_phys = if rsdp >= hhdm { rsdp - hhdm } else { rsdp };
    let rsdp_v = map(rsdp_phys, 36)?;

    let sig: [u8; 8] = rd(rsdp_v);
    if &sig != b"RSD PTR " {
        return None;
    }
    let revision: u8 = rd(rsdp_v + 15);
    let rsdt_addr: u32 = rd(rsdp_v + 16);
    let xsdt_addr: u64 = if revision >= 2 { rd(rsdp_v + 24) } else { 0 };

    let (root, entry_size) = if xsdt_addr != 0 {
        (xsdt_addr, 8u64)
    } else {
        (rsdt_addr as u64, 4u64)
    };
    let root_len: u32 = rd(map(root, 36)? + 4);
    let root_v = map(root, root_len as usize)?;
    let entries = (root_len as u64).saturating_sub(36) / entry_size;

    let mut madt: Option<(u64, u32)> = None;
    let mut mcfg: Option<(u64, u32)> = None;
    for i in 0..entries {
        let p: u64 = if entry_size == 8 {
            rd(root_v + 36 + i * 8)
        } else {
            rd::<u32>(root_v + 36 + i * 4) as u64
        };
        let hdr = map(p, 36)?;
        let tsig: [u8; 4] = rd(hdr);
        let len: u32 = rd(hdr + 4);
        if &tsig == b"APIC" && madt.is_none() {
            madt = Some((p, len));
        } else if &tsig == b"MCFG" && mcfg.is_none() {
            mcfg = Some((p, len));
        }
    }
    let (mp, ml) = madt?;
    let mut info = parse_madt(map(mp, ml as usize)?);
    if let Some((cp, cl)) = mcfg {
        if cl >= 44 {
            parse_mcfg(map(cp, cl as usize)?, cl, &mut info);
        }
    }
    Some(INFO.call_once(|| info))
}

/// MCFG: 36-byte header, 8 reserved bytes, then 16-byte allocation entries.
unsafe fn parse_mcfg(t: u64, len: u32, info: &mut AcpiInfo) {
    let n = ((len - 44) / 16) as usize;
    for i in 0..n.min(4) {
        let e = t + 44 + i as u64 * 16;
        info.mcfg[i] = McfgEntry {
            base: rd(e),
            segment: rd(e + 8),
            start_bus: rd(e + 10),
            end_bus: rd(e + 11),
        };
        info.mcfg_count += 1;
    }
}

unsafe fn parse_madt(t: u64) -> AcpiInfo {
    let len: u32 = rd(t + 4);
    let mut info = AcpiInfo {
        mcfg: [McfgEntry::default(); 4],
        mcfg_count: 0,
        lapic_address: rd::<u32>(t + 36) as u64,
        cpu_count: 0,
        ioapics: [IoApicInfo::default(); 4],
        ioapic_count: 0,
        overrides: [IrqOverride::default(); 16],
        override_count: 0,
    };
    let mut off = 44u64;
    while off + 2 <= len as u64 {
        let etype: u8 = rd(t + off);
        let elen: u8 = rd(t + off + 1);
        if elen < 2 {
            break;
        }
        match etype {
            0 => {
                let flags: u32 = rd(t + off + 4);
                if flags & 0b11 != 0 {
                    info.cpu_count += 1;
                }
            }
            1 if info.ioapic_count < 4 => {
                info.ioapics[info.ioapic_count] = IoApicInfo {
                    id: rd(t + off + 2),
                    address: rd(t + off + 4),
                    gsi_base: rd(t + off + 8),
                };
                info.ioapic_count += 1;
            }
            2 if info.override_count < 16 => {
                info.overrides[info.override_count] = IrqOverride {
                    source_irq: rd(t + off + 3),
                    gsi: rd(t + off + 4),
                    flags: rd(t + off + 8),
                };
                info.override_count += 1;
            }
            5 => info.lapic_address = rd(t + off + 4),
            _ => {}
        }
        off += elen as u64;
    }
    info
}
