pub mod acpi;
pub mod apic;
pub mod context;
pub mod cpu;
pub mod gdt;
pub mod idt;
pub mod pic;
pub mod syscall;

/// Initialise all CPU descriptor tables (GDT/TSS first, then IDT).
pub fn init() {
    gdt::init();
    idt::init();
}

/// Disable interrupts and halt the CPU forever.
pub fn hlt_loop() -> ! {
    x86_64::instructions::interrupts::disable();
    loop {
        x86_64::instructions::hlt();
    }
}

/// Terminate QEMU through the `isa-debug-exit` device (`-device isa-debug-exit,iobase=0xf4,iosize=4`).
/// QEMU's process exit status becomes `(code << 1) | 1`.
#[cfg(feature = "selftest")]
pub fn qemu_exit(code: u32) -> ! {
    // SAFETY: port 0xF4 is only meaningful when the isa-debug-exit device is
    // present (QEMU test runs); elsewhere the write is ignored.
    unsafe { x86_64::instructions::port::Port::<u32>::new(0xF4).write(code) };
    hlt_loop()
}

/// Power off (QEMU/Bochs ACPI port 0x604, then 0xB004) or reboot (keyboard-controller reset). Never returns.
pub fn power(reboot: bool) -> ! {
    use x86_64::instructions::port::Port;
    // SAFETY: fixed legacy ports: 0x604/0xB004 are the emulated ACPI PM1a shutdown ports (ignored on other
    // hardware), 0x64 command 0xFE pulses the CPU reset line. The caller proved authority via a Power capability.
    unsafe {
        if reboot {
            Port::<u8>::new(0x64).write(0xFE);
        } else {
            Port::<u16>::new(0x604).write(0x2000);
            Port::<u16>::new(0xB004).write(0x2000);
        }
    }
    // Fallback if the platform ignored us: halt.
    hlt_loop()
}
