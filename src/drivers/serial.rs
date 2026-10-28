//! UART 16550 driver (COM1) and `log` backend.

use core::fmt::{self, Write};

use log::{Level, LevelFilter, Log, Metadata, Record};
use crate::sync::IrqMutex;
use x86_64::instructions::port::Port;

pub const COM1_BASE: u16 = 0x3F8;

/// A 16550-compatible UART addressed through legacy port I/O.
pub struct SerialPort {
    data: Port<u8>,       // +0 (DLAB=0: data, DLAB=1: divisor low)
    int_enable: Port<u8>, // +1 (DLAB=1: divisor high)
    fifo_ctrl: Port<u8>,  // +2
    line_ctrl: Port<u8>,  // +3
    modem_ctrl: Port<u8>, // +4
    line_status: Port<u8>, // +5
}

impl SerialPort {
    /// # Safety
    /// `base` must be the I/O base of a real 16550-compatible UART, and no other
    /// code may drive the same UART concurrently except through this object.
    pub const unsafe fn new(base: u16) -> Self {
        Self {
            data: Port::new(base),
            int_enable: Port::new(base + 1),
            fifo_ctrl: Port::new(base + 2),
            line_ctrl: Port::new(base + 3),
            modem_ctrl: Port::new(base + 4),
            line_status: Port::new(base + 5),
        }
    }

    /// Program the UART for 115200 8N1 with FIFOs, after a loopback self-test.
    pub fn init(&mut self) -> Result<(), ()> {
        // SAFETY: `self` was constructed via `unsafe new`, so the caller already
        // guaranteed these ports belong to a 16550 UART. Every write below is
        // a documented 16550 register access; none touch memory.
        unsafe {
            self.int_enable.write(0x00); // disable UART interrupts
            self.line_ctrl.write(0x80); // DLAB on
            self.data.write(0x01); // divisor = 1 -> 115200 baud
            self.int_enable.write(0x00);
            self.line_ctrl.write(0x03); // DLAB off, 8 bits, no parity, 1 stop
            self.fifo_ctrl.write(0xC7); // enable FIFO, clear, 14-byte threshold
            self.modem_ctrl.write(0x1E); // loopback mode for self-test
            self.data.write(0xAE);
            if self.data.read() != 0xAE {
                return Err(());
            }
            self.modem_ctrl.write(0x0F); // normal operation, OUT1/OUT2, RTS/DTR
        }
        Ok(())
    }

    fn send_byte(&mut self, byte: u8) {
        // SAFETY: reading LSR and writing THR are side-effect-safe UART accesses
        // (see `new` invariants). We only write after THR-empty (bit 5) is set.
        unsafe {
            while self.line_status.read() & 0x20 == 0 {
                core::hint::spin_loop();
            }
            self.data.write(byte);
        }
    }
}

impl Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                self.send_byte(b'\r');
            }
            self.send_byte(b);
        }
        crate::drivers::fb::console::write_str(s);
        Ok(())
    }
}

/// Global COM1 instance.
// SAFETY: 0x3F8 is the architecturally standard COM1 base on PC hardware/QEMU.
pub static SERIAL1: IrqMutex<SerialPort> = IrqMutex::new(unsafe { SerialPort::new(COM1_BASE) });

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    let _ = SERIAL1.lock().write_fmt(args);
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => { $crate::drivers::serial::_print(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! serial_println {
    () => { $crate::serial_print!("\n") };
    ($($arg:tt)*) => { $crate::serial_print!("{}\n", format_args!($($arg)*)) };
}

/// Forcibly release the serial lock. Used only by fatal fault/panic paths.
///
/// # Safety
/// Only call when the current CPU will never resume the interrupted code that
/// may hold the lock (i.e. we are about to halt). Otherwise the lock's
/// mutual-exclusion guarantee is broken.
pub unsafe fn force_unlock() {
    SERIAL1.force_unlock();
}

struct SerialLogger;

impl Log for SerialLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let color = match record.level() {
            Level::Error => "\x1b[31m",
            Level::Warn => "\x1b[33m",
            Level::Info => "\x1b[32m",
            Level::Debug => "\x1b[36m",
            Level::Trace => "\x1b[90m",
        };
        _print(format_args!(
            "{}[{:<5}]\x1b[0m {}: {}\n",
            color,
            record.level(),
            record.target(),
            record.args()
        ));
    }

    fn flush(&self) {}
}

static LOGGER: SerialLogger = SerialLogger;

/// Initialise COM1 and install the global logger.
pub fn init_logger(level: LevelFilter) {
    let ok = SERIAL1.lock().init().is_ok();
    if !ok {
        // No working UART: nothing sensible to log to. Leave logging disabled.
        return;
    }
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(level);
}
