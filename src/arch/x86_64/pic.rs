//! Legacy 8259 PIC: remapped out of the exception range and fully masked, since
//! the LAPIC/IOAPIC take over interrupt delivery.

use x86_64::instructions::port::Port;

fn io_wait() {
    // SAFETY: port 0x80 is the conventional POST/diagnostic port; writing is a
    // harmless ~1us delay on PC-compatible hardware.
    unsafe { Port::<u8>::new(0x80).write(0) };
}

pub fn disable() {
    // SAFETY: standard 8259A initialisation sequence on the fixed legacy ports
    // 0x20/0x21 (master) and 0xA0/0xA1 (slave). Only touches the PIC.
    unsafe {
        let mut c1 = Port::<u8>::new(0x20);
        let mut d1 = Port::<u8>::new(0x21);
        let mut c2 = Port::<u8>::new(0xA0);
        let mut d2 = Port::<u8>::new(0xA1);
        c1.write(0x11);
        io_wait();
        c2.write(0x11);
        io_wait();
        d1.write(0x20); // master vectors 0x20..0x27
        io_wait();
        d2.write(0x28); // slave vectors 0x28..0x2F
        io_wait();
        d1.write(0x04);
        io_wait();
        d2.write(0x02);
        io_wait();
        d1.write(0x01);
        io_wait();
        d2.write(0x01);
        io_wait();
        d1.write(0xFF); // mask everything
        d2.write(0xFF);
    }
}
