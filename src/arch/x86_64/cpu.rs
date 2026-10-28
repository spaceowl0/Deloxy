//! CPU identification via CPUID.

use core::arch::x86_64::{__cpuid, __cpuid_count, CpuidResult};

pub struct CpuInfo {
    pub vendor: [u8; 12],
    pub brand: [u8; 48],
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    pub has_apic: bool,
    pub has_nx: bool,
    pub has_x2apic: bool,
    pub has_sse2: bool,
    pub has_pge: bool,
    pub has_smep: bool,
    pub has_smap: bool,
}

#[allow(unused_unsafe)]
fn cpuid(leaf: u32) -> CpuidResult {
    // SAFETY: CPUID is available on every x86_64 CPU and has no side effects.
    unsafe { __cpuid(leaf) }
}

#[allow(unused_unsafe)]
fn cpuid_count(leaf: u32, sub: u32) -> CpuidResult {
    // SAFETY: see `cpuid`.
    unsafe { __cpuid_count(leaf, sub) }
}

pub fn detect() -> CpuInfo {
    let l0 = cpuid(0);
    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&l0.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&l0.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&l0.ecx.to_le_bytes());

    let l1 = cpuid(1);
    let stepping = l1.eax & 0xF;
    let mut model = (l1.eax >> 4) & 0xF;
    let mut family = (l1.eax >> 8) & 0xF;
    if family == 0xF {
        family += (l1.eax >> 20) & 0xFF;
    }
    if family == 0x6 || family >= 0xF {
        model += ((l1.eax >> 16) & 0xF) << 4;
    }

    let max_ext = cpuid(0x8000_0000).eax;
    let mut brand = [0u8; 48];
    if max_ext >= 0x8000_0004 {
        for i in 0..3u32 {
            let r = cpuid(0x8000_0002 + i);
            let o = (i * 16) as usize;
            brand[o..o + 4].copy_from_slice(&r.eax.to_le_bytes());
            brand[o + 4..o + 8].copy_from_slice(&r.ebx.to_le_bytes());
            brand[o + 8..o + 12].copy_from_slice(&r.ecx.to_le_bytes());
            brand[o + 12..o + 16].copy_from_slice(&r.edx.to_le_bytes());
        }
    }
    let l7 = if l0.eax >= 7 { cpuid_count(7, 0) } else { CpuidResult { eax: 0, ebx: 0, ecx: 0, edx: 0 } };
    let has_nx = max_ext >= 0x8000_0001 && cpuid(0x8000_0001).edx & (1 << 20) != 0;

    CpuInfo {
        vendor,
        brand,
        family,
        model,
        stepping,
        has_apic: l1.edx & (1 << 9) != 0,
        has_x2apic: l1.ecx & (1 << 21) != 0,
        has_sse2: l1.edx & (1 << 26) != 0,
        has_pge: l1.edx & (1 << 13) != 0,
        has_nx,
        has_smep: l7.ebx & (1 << 7) != 0,
        has_smap: l7.ebx & (1 << 20) != 0,
    }
}

impl CpuInfo {
    pub fn vendor_str(&self) -> &str {
        core::str::from_utf8(&self.vendor).unwrap_or("?")
    }
    pub fn brand_str(&self) -> &str {
        core::str::from_utf8(&self.brand)
            .unwrap_or("?")
            .trim_matches(|c: char| c == '\0' || c == ' ')
    }
}
