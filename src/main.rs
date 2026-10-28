#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

mod abi;
mod arch;
mod audit;
mod boot;
mod cap;
mod drivers;
mod exec;
mod fs;
mod gfx;
mod init;
mod ipc;
mod mm;
mod net;
mod rand;
mod perm;
#[cfg(feature = "selftest")]
mod selftest;
mod store;
mod sync;
mod sys;
mod task;
mod time;
mod tty;
mod upd;
mod wm;

use core::panic::PanicInfo;

use limine::memory_map::EntryType;
use limine::request::{FramebufferRequest, HhdmRequest, MemoryMapRequest, ModuleRequest, RequestsEndMarker, RequestsStartMarker, RsdpRequest};
use limine::BaseRevision;
use log::{error, info, warn, LevelFilter};

#[used]
#[link_section = ".requests"]
static BASE_REVISION: BaseRevision = BaseRevision::new();

#[used]
#[link_section = ".requests"]
static MEMMAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

#[used]
#[link_section = ".requests"]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
#[link_section = ".requests"]
static FB_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[used]
#[link_section = ".requests"]
static MODULE_REQUEST: ModuleRequest = ModuleRequest::new();

#[used]
#[link_section = ".requests"]
static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

#[used]
#[link_section = ".requests_start_marker"]
static REQUESTS_START: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[link_section = ".requests_end_marker"]
static REQUESTS_END: RequestsEndMarker = RequestsEndMarker::new();

const BANNER: &str = r"
  ____       _
 |  _ \  ___| | _____  ___   _
 | | | |/ _ \ |/ _ \ \/ / | | |
 | |_| |  __/ | (_) >  <| |_| |
 |____/ \___|_|\___/_/\_\\__, |
                         |___/
        Deloxy Kernel v0.1.0-alpha
";

fn mib(bytes: u64) -> u64 {
    bytes / (1024 * 1024)
}

/// Kernel entry, reached from the `_start` stub in `boot.rs` on the kernel's own stack.
pub extern "C" fn kmain() -> ! {
    drivers::serial::init_logger(LevelFilter::Trace);
    init_framebuffer();
    serial_println!("{}", BANNER);

    if !BASE_REVISION.is_supported() {
        error!("Limine base revision not supported by bootloader");
        arch::x86_64::hlt_loop();
    }
    info!("Booted via Limine (higher-half long mode)");

    arch::x86_64::init();
    info!("GDT, TSS (IST0 = #DF stack) and IDT loaded");

    let cpu = arch::x86_64::cpu::detect();
    info!(
        "CPU: {} '{}' fam {} model {} step {}",
        cpu.vendor_str(),
        cpu.brand_str(),
        cpu.family,
        cpu.model,
        cpu.stepping
    );
    info!(
        "  features: apic={} x2apic={} nx={} sse2={} smep={} smap={}",
        cpu.has_apic, cpu.has_x2apic, cpu.has_nx, cpu.has_sse2, cpu.has_smep, cpu.has_smap
    );

    let memmap = MEMMAP_REQUEST.get_response().expect("no Limine memory map response");
    let hhdm = HHDM_REQUEST.get_response().expect("no Limine HHDM response").offset();
    info!("HHDM offset: {:#x}", hhdm);

    let (mut usable, mut boot, mut acpi, mut reserved) = (0u64, 0u64, 0u64, 0u64);
    for e in memmap.entries() {
        let t = e.entry_type;
        if t == EntryType::USABLE {
            usable += e.length;
        } else if t == EntryType::BOOTLOADER_RECLAIMABLE {
            boot += e.length;
        } else if t == EntryType::ACPI_RECLAIMABLE || t == EntryType::ACPI_NVS {
            acpi += e.length;
        } else {
            reserved += e.length;
        }
    }
    info!("Memory map: {} entries", memmap.entries().len());
    info!("  usable             : {} MiB", mib(usable));
    info!("  bootloader reclaim : {} MiB", mib(boot));
    info!("  ACPI               : {} MiB", mib(acpi));
    info!("  reserved/other     : {} MiB", mib(reserved));

    let regions = memmap
        .entries()
        .iter()
        .filter(|e| e.entry_type == EntryType::USABLE)
        .map(|e| (e.base, e.length));

    // SAFETY: Limine USABLE entries are free RAM and the HHDM maps all of it
    // read/write; this is the sole call to frame::init.
    if !unsafe { mm::frame::init(regions, hhdm) } {
        error!("frame allocator init failed");
        arch::x86_64::hlt_loop();
    }
    let (total, free) = mm::frame::stats();
    info!("Frame allocator: {} frames tracked, {} free ({} MiB)", total, free, free * 4096 / (1024 * 1024));

    mm::vmm::init(hhdm, cpu.has_smep);
    info!("VMM: own PML4 active (NX, WP{} enabled)", if cpu.has_smep { ", SMEP" } else { "" });

    mm::heap::init();
    let hs = mm::heap::stats();
    info!("Heap: {} KiB mapped at {:#x}", hs.mapped / 1024, mm::layout::KERNEL_HEAP);

    // Interrupt controllers: retire the 8259 PIC, parse ACPI, enable the LAPIC.
    arch::x86_64::pic::disable();
    match RSDP_REQUEST.get_response() {
        // SAFETY: the RSDP address comes from Limine and the HHDM maps ACPI memory.
        Some(r) => match unsafe { arch::x86_64::acpi::init(r.address() as u64, hhdm) } {
            Some(a) => info!(
                "ACPI MADT: {} CPU(s), LAPIC @ {:#x}, {} IOAPIC(s), {} IRQ override(s)",
                a.cpu_count,
                a.lapic_address,
                a.ioapic_count,
                a.override_count
            ),
            None => warn!("ACPI: MADT not found"),
        },
        None => warn!("no RSDP from bootloader"),
    }
    if !cpu.has_apic {
        error!("CPU has no local APIC");
        arch::x86_64::hlt_loop();
    }
    arch::x86_64::apic::init(arch::x86_64::idt::SPURIOUS_VECTOR).expect("LAPIC init failed");
    info!("LAPIC enabled (id {})", arch::x86_64::apic::id());

    match drivers::input::ps2::init() {
        Ok(r) => {
            info!("PS/2: keyboard={} mouse={}", r.keyboard, r.mouse);
            if r.keyboard {
                if let Err(e) = arch::x86_64::apic::route_isa_irq(1, arch::x86_64::idt::KBD_VECTOR) {
                    warn!("keyboard IRQ routing failed: {}", e);
                }
            }
            if r.mouse {
                if let Err(e) = arch::x86_64::apic::route_isa_irq(12, arch::x86_64::idt::MOUSE_VECTOR) {
                    warn!("mouse IRQ routing failed: {}", e);
                }
            }
        }
        Err(e) => warn!("PS/2 init failed: {}", e),
    }

    init_initramfs();
    init_rootfs();
    drivers::pci::init();
    rand::probe_virtio_rng();
    rand::init();
    net::init();
    store::init();
    perm::init();
    upd::recover();

    arch::x86_64::syscall::init();
    task::init();
    info!("Scheduler ready (round-robin, {} ms quantum); SYSCALL/SYSRET armed", task::sched::QUANTUM_TICKS);

    if net::has_nic() {
        task::spawn_kernel("net", net::run).expect("spawn net");
        task::spawn_kernel("sigtimer", abi::signals::timer_thread).expect("spawn sigtimer");
    }

    if drivers::usb::present() {
        task::spawn_kernel("usb", drivers::usb::run).expect("spawn usb");
    }

    #[cfg(feature = "selftest")]
    {
        selftest::run_mm();
        task::spawn_kernel("selftest", selftest::run_tasks).expect("spawn selftest");
    }
    #[cfg(not(feature = "selftest"))]
    {
        task::spawn_kernel("compositor", || wm::server::run()).expect("spawn compositor");
        task::spawn_kernel("tty-rx", tty::run_serial_poller).expect("spawn tty poller");
        match init::spawn_shell() {
            Ok(p) => info!("deloxy-sh started (pid {})", p.pid),
            Err(e) => warn!("shell not started: {}", e),
        }
    }

    let per_ms = arch::x86_64::apic::start_timer(arch::x86_64::idt::TIMER_VECTOR, time::TICK_HZ);
    info!("LAPIC timer: {} kHz bus/16, {} Hz tick", per_ms, time::TICK_HZ);

    // Idle loop: the boot context becomes the idle thread.
    loop {
        x86_64::instructions::interrupts::enable_and_hlt();
        task::sched::reap();
    }
}

/// Parse the second boot module (if present) as the hierarchical read-only root filesystem.
fn init_rootfs() {
    let Some(resp) = MODULE_REQUEST.get_response() else { return };
    let Some(m) = resp.modules().get(1) else {
        info!("rootfs: no second boot module (hierarchical tree unavailable)");
        return;
    };
    // SAFETY: the bootloader maps module memory (HHDM) for the lifetime of the kernel and never modifies it.
    let data: &'static [u8] = unsafe { core::slice::from_raw_parts(m.addr(), m.size() as usize) };
    match fs::rootfs::install(data) {
        Ok(n) => info!("rootfs: {} node(s), {} KiB", n, data.len() / 1024),
        Err(e) => error!("rootfs: invalid archive: {:?}", e),
    }
}

/// Parse the first boot module as the read-only initramfs (USTAR).
fn init_initramfs() {
    let Some(resp) = MODULE_REQUEST.get_response() else {
        warn!("initramfs: no boot module (limine.conf needs module_path); shell unavailable");
        return;
    };
    let Some(m) = resp.modules().first() else {
        warn!("initramfs: module list empty");
        return;
    };
    // SAFETY: Limine keeps the module memory mapped (HHDM) and reserved for the kernel's lifetime.
    let data: &'static [u8] = unsafe { core::slice::from_raw_parts(m.addr(), m.size() as usize) };
    match fs::install(data) {
        Ok(n) => info!("initramfs: {} file(s), {} KiB", n, data.len() / 1024),
        Err(e) => error!("initramfs: invalid archive: {:?}", e),
    }
}

/// Publish the Limine framebuffer (if any) and start mirroring the log onto it.
fn init_framebuffer() {
    use drivers::fb::{self, FbInfo};
    let Some(resp) = FB_REQUEST.get_response() else { return };
    let Some(f) = resp.framebuffers().next() else { return };
    if f.bpp() != 32 {
        return;
    }
    fb::set(FbInfo {
        addr: f.addr() as usize,
        width: f.width() as usize,
        height: f.height() as usize,
        pitch: f.pitch() as usize,
        bpp: f.bpp(),
        r_shift: f.red_mask_shift(),
        g_shift: f.green_mask_shift(),
        b_shift: f.blue_mask_shift(),
    });
    fb::console::init();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // SAFETY: we halt permanently below, so a lock held by interrupted code
    // can never be released by it.
    unsafe { drivers::serial::force_unlock() };
    error!("KERNEL PANIC: {}", info);
    boot::backtrace(boot::current_rbp());
    #[cfg(feature = "selftest")]
    arch::x86_64::qemu_exit(0x11);
    #[cfg(not(feature = "selftest"))]
    arch::x86_64::hlt_loop()
}
