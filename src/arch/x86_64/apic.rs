//! Local APIC (xAPIC MMIO mode) with PIT-calibrated periodic timer, plus IOAPIC routing.

use core::sync::atomic::{AtomicUsize, Ordering};

use x86_64::instructions::port::Port;
use x86_64::registers::model_specific::Msr;

use crate::mm::vmm;

const IA32_APIC_BASE: u32 = 0x1B;

const REG_ID: usize = 0x20;
const REG_TPR: usize = 0x80;
const REG_EOI: usize = 0xB0;
const REG_SVR: usize = 0xF0;
const REG_LVT_TIMER: usize = 0x320;
const REG_TIMER_INIT: usize = 0x380;
const REG_TIMER_CUR: usize = 0x390;
const REG_TIMER_DIV: usize = 0x3E0;

static LAPIC_VIRT: AtomicUsize = AtomicUsize::new(0);

fn lapic_read(reg: usize) -> u32 {
    let base = LAPIC_VIRT.load(Ordering::Relaxed);
    debug_assert!(base != 0);
    // SAFETY: `base` is the uncached mapping of the LAPIC register page created
    // in `init`; `reg` is a valid 16-byte aligned register offset < 4096.
    unsafe { core::ptr::read_volatile((base + reg) as *const u32) }
}

fn lapic_write(reg: usize, val: u32) {
    let base = LAPIC_VIRT.load(Ordering::Relaxed);
    debug_assert!(base != 0);
    // SAFETY: see `lapic_read`.
    unsafe { core::ptr::write_volatile((base + reg) as *mut u32, val) }
}

/// Enable the BSP's local APIC and map its registers.
pub fn init(spurious_vector: u8) -> Result<(), &'static str> {
    let mut msr = Msr::new(IA32_APIC_BASE);
    // SAFETY: IA32_APIC_BASE (0x1B) exists on every CPU with an APIC (checked by
    // the caller via CPUID). We clear the x2APIC bit and set the global-enable bit.
    let phys = unsafe {
        let v = msr.read();
        let base = v & 0x000F_FFFF_FFFF_F000;
        msr.write(base); // fully disable (also leaves x2APIC mode if firmware set it)
        msr.write(base | (1 << 11)); // enable in xAPIC mode
        base
    };
    let virt = vmm::map_mmio(phys, 4096).ok_or("failed to map LAPIC MMIO")?;
    LAPIC_VIRT.store(virt as usize, Ordering::Relaxed);

    lapic_write(REG_TPR, 0);
    lapic_write(REG_SVR, 0x100 | spurious_vector as u32);
    Ok(())
}

pub fn id() -> u32 {
    lapic_read(REG_ID) >> 24
}

pub fn eoi() {
    lapic_write(REG_EOI, 0);
}

/// Measure LAPIC timer ticks per millisecond (divider 16) against PIT channel 2.
fn calibrate_ticks_per_ms() -> u32 {
    // SAFETY: fixed legacy PC ports: 0x61 (system control B: gate/speaker),
    // 0x42 (PIT ch2 data), 0x43 (PIT command). We disable the speaker output,
    // program a one-shot ~10ms countdown and poll OUT2 (bit 5 of port 0x61).
    unsafe {
        let mut p61 = Port::<u8>::new(0x61);
        let mut cmd = Port::<u8>::new(0x43);
        let mut ch2 = Port::<u8>::new(0x42);

        let v = p61.read();
        p61.write((v & !0x02) | 0x01);
        cmd.write(0b1011_0000); // ch2, lobyte/hibyte, mode 0, binary
        let count: u16 = 11932; // 1_193_182 Hz / 100 = 10 ms
        ch2.write(count as u8);
        ch2.write((count >> 8) as u8);

        lapic_write(REG_TIMER_DIV, 0x3); // divide by 16
        lapic_write(REG_LVT_TIMER, 1 << 16); // masked one-shot
        lapic_write(REG_TIMER_INIT, 0xFFFF_FFFF);

        let mut spins = 0u64;
        while p61.read() & 0x20 == 0 {
            spins += 1;
            if spins > 200_000_000 {
                lapic_write(REG_TIMER_INIT, 0);
                return 100_000; // fallback guess
            }
        }
        let elapsed = 0xFFFF_FFFFu32.wrapping_sub(lapic_read(REG_TIMER_CUR));
        lapic_write(REG_TIMER_INIT, 0);
        (elapsed / 10).max(1)
    }
}

/// Busy-wait `ms` (<= 50) milliseconds using PIT channel 2 (independent reference clock).
pub fn pit_delay_ms(ms: u32) {
    debug_assert!(ms >= 1 && ms <= 50);
    // SAFETY: same fixed legacy PIT/system-control ports as in `calibrate_ticks_per_ms`.
    unsafe {
        let mut p61 = Port::<u8>::new(0x61);
        let mut cmd = Port::<u8>::new(0x43);
        let mut ch2 = Port::<u8>::new(0x42);
        let v = p61.read();
        p61.write((v & !0x02) | 0x01);
        cmd.write(0b1011_0000);
        let count = (1193 * ms) as u16;
        ch2.write(count as u8);
        ch2.write((count >> 8) as u8);
        while p61.read() & 0x20 == 0 {
            core::hint::spin_loop();
        }
    }
}

/// Start the periodic timer at `hz` on `vector`. Returns the calibrated ticks/ms.
pub fn start_timer(vector: u8, hz: u64) -> u32 {
    let per_ms = calibrate_ticks_per_ms();
    let initial = (per_ms as u64 * 1000 / hz).max(1) as u32;
    lapic_write(REG_TIMER_DIV, 0x3);
    lapic_write(REG_LVT_TIMER, vector as u32 | (1 << 17)); // periodic
    lapic_write(REG_TIMER_INIT, initial);
    per_ms
}

// ---------------------------------------------------------------- IOAPIC ---

fn ioapic_read(base: usize, reg: u32) -> u32 {
    // SAFETY: `base` is a mapped IOAPIC page; IOREGSEL at +0, IOWIN at +0x10.
    unsafe {
        core::ptr::write_volatile(base as *mut u32, reg);
        core::ptr::read_volatile((base + 0x10) as *const u32)
    }
}

fn ioapic_write(base: usize, reg: u32, val: u32) {
    // SAFETY: see `ioapic_read`.
    unsafe {
        core::ptr::write_volatile(base as *mut u32, reg);
        core::ptr::write_volatile((base + 0x10) as *mut u32, val);
    }
}

/// Route an ISA IRQ (e.g. 1 = keyboard) to `vector` on the boot CPU.
pub fn route_isa_irq(irq: u8, vector: u8) -> Result<(), &'static str> {
    let acpi = super::acpi::info().ok_or("no ACPI MADT")?;
    let (gsi, flags) = acpi.resolve_isa_irq(irq);

    // Pick the IOAPIC whose GSI range contains `gsi`.
    let io = acpi
        .ioapics()
        .iter()
        .filter(|a| a.gsi_base <= gsi)
        .max_by_key(|a| a.gsi_base)
        .ok_or("no IOAPIC for GSI")?;
    let base = vmm::map_mmio(io.address as u64, 4096).ok_or("failed to map IOAPIC")? as usize;

    let pin = gsi - io.gsi_base;
    let polarity_low = (flags & 0b11) == 0b11;
    let level = ((flags >> 2) & 0b11) == 0b11;

    let mut low = vector as u32;
    if polarity_low {
        low |= 1 << 13;
    }
    if level {
        low |= 1 << 15;
    }
    let high = id() << 24;
    ioapic_write(base, 0x10 + pin * 2 + 1, high);
    ioapic_write(base, 0x10 + pin * 2, low); // unmasked
    let _ = ioapic_read(base, 0x01); // read version (posts the writes)
    Ok(())
}
