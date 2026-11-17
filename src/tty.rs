//! Kernel TTY: one byte-stream console shared by the shell (through `Tty` capabilities).
//!
//! Input is fed by the COM1 receive poller (and by the deloxy-de terminal window); output goes to the
//! serial port + boot console and is mirrored into a bounded capture ring that the terminal window and
//! the self tests read.

use alloc::collections::VecDeque;
use x86_64::instructions::port::Port;

use crate::sync::IrqMutex;

const IN_CAP: usize = 4096;
const OUT_CAP: usize = 64 * 1024;

struct Inner {
    input: VecDeque<u8>,
    out: VecDeque<u8>,
    out_total: u64,
}

static TTY: IrqMutex<Inner> = IrqMutex::new(Inner { input: VecDeque::new(), out: VecDeque::new(), out_total: 0 });

/// Queue input bytes (dropped when the queue is full).
/// Foreground process group of the console. `u64::MAX` = no job-control shell has claimed it yet (legacy: Ctrl-C reaches
/// the programs the shell started); `0` = the shell itself owns the terminal; otherwise a process group id.
static FG_PGID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

pub fn foreground() -> u64 {
    FG_PGID.load(core::sync::atomic::Ordering::Relaxed)
}

pub fn set_foreground(pgid: u64) {
    FG_PGID.store(pgid, core::sync::atomic::Ordering::Relaxed);
}

pub fn push_input(bytes: &[u8]) {
    // Ctrl-C interrupts, Ctrl-Z stops the foreground job (instead of being typed into it)
    let mut filtered: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let bytes = if bytes.contains(&0x03) || bytes.contains(&0x1A) {
        for &b in bytes {
            if b == 0x03 && crate::abi::signals::interrupt_foreground() {
                write(b"^C\r\n");
            } else if b == 0x1A && crate::abi::signals::stop_foreground() {
                write(b"^Z\r\n");
            } else {
                filtered.push(b);
            }
        }
        &filtered[..]
    } else {
        bytes
    };
    let mut t = TTY.lock();
    for &b in bytes {
        if t.input.len() < IN_CAP {
            t.input.push_back(b);
        }
    }
}

pub fn read_input(out: &mut [u8]) -> usize {
    let mut t = TTY.lock();
    let mut n = 0;
    while n < out.len() {
        match t.input.pop_front() {
            Some(b) => {
                out[n] = b;
                n += 1;
            }
            None => break,
        }
    }
    n
}

pub fn has_input() -> bool {
    !TTY.lock().input.is_empty()
}

/// Write shell output: serial + screen console + capture ring.
pub fn write(bytes: &[u8]) {
    {
        let mut t = TTY.lock();
        for &b in bytes {
            if t.out.len() >= OUT_CAP {
                t.out.pop_front();
            }
            t.out.push_back(b);
        }
        t.out_total += bytes.len() as u64;
    }
    // Lossy conversion keeps the log path simple; the shell only emits ASCII + UTF-8.
    let mut buf = [0u8; 128];
    for chunk in bytes.chunks(buf.len()) {
        buf[..chunk.len()].copy_from_slice(chunk);
        match core::str::from_utf8(&buf[..chunk.len()]) {
            Ok(s) => crate::serial_print!("{}", s),
            Err(_) => {
                for &b in chunk {
                    crate::serial_print!("{}", if b.is_ascii() { b as char } else { '?' });
                }
            }
        }
    }
}

/// Total bytes ever written (the terminal window uses this to notice new output).
pub fn out_total() -> u64 {
    TTY.lock().out_total
}

/// Copy captured output starting at absolute position `from` (clamped to what is still buffered).
pub fn read_output(from: u64, out: &mut [u8]) -> (usize, u64) {
    let t = TTY.lock();
    let oldest = t.out_total - t.out.len() as u64;
    let start = from.max(oldest);
    let skip = (start - oldest) as usize;
    let n = out.len().min(t.out.len().saturating_sub(skip));
    for i in 0..n {
        out[i] = t.out[skip + i];
    }
    (n, start + n as u64)
}

/// Poll COM1 for received bytes (no interrupt needed; the poller thread calls this every few ms).
pub fn poll_serial() {
    // SAFETY: COM1 line-status (0x3FD) and data (0x3F8) ports; read-only status check, then a data read
    // only when the "data ready" bit is set. The serial driver owns initialisation.
    unsafe {
        let mut lsr = Port::<u8>::new(0x3FD);
        let mut data = Port::<u8>::new(0x3F8);
        let mut got = [0u8; 32];
        let mut n = 0;
        while n < got.len() && lsr.read() & 1 != 0 {
            got[n] = data.read();
            n += 1;
        }
        if n > 0 {
            push_input(&got[..n]);
        }
    }
}

/// Kernel thread: feeds serial input into the TTY.
pub fn run_serial_poller() {
    loop {
        poll_serial();
        crate::task::sleep_ms(4);
    }
}
