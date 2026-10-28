//! Native Deloxy syscall wrappers + tiny formatting helpers shared by native user programs (`#[path]` include).
#![allow(dead_code)]
use core::arch::asm;
use core::fmt::{self, Write};

pub const SYS_EXIT: i64 = 0;
pub const SYS_SLEEP_MS: i64 = 2;
pub const SYS_TIME_NOW: i64 = 8;
pub const SYS_CAP_DROP: i64 = 11;
pub const SYS_AUDIT_READ: i64 = 19;
pub const SYS_STAT: i64 = 20;
pub const SYS_TTY_READ: i64 = 21;
pub const SYS_TTY_WRITE: i64 = 22;
pub const SYS_FS_LIST: i64 = 23;
pub const SYS_FS_OPEN: i64 = 24;
pub const SYS_FILE_READ: i64 = 25;
pub const SYS_PROC_SPAWN: i64 = 26;
pub const SYS_PROC_WAIT: i64 = 27;
pub const SYS_PROC_LIST: i64 = 28;
pub const SYS_CAP_LIST: i64 = 29;
pub const SYS_NET_GRANT: i64 = 30;
pub const SYS_UPD: i64 = 31;
pub const SYS_POWER: i64 = 32;
pub const SYS_STORE_LIST: i64 = 33;
pub const SYS_STORE_OPEN: i64 = 34;
pub const SYS_STORE_WRITE: i64 = 35;
pub const SYS_STORE_CTL: i64 = 36;
pub const SYS_PERM: i64 = 37;
pub const SYS_MMAP_ANON: i64 = 4;

pub const INFO_BASE: usize = 0x30_0000;

#[inline(always)]
pub unsafe fn sc(nr: i64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret: i64;
    asm!("syscall", inlateout("rax") nr => ret,
        in("rdi") a0, in("rsi") a1, in("rdx") a2, in("r10") a3, in("r8") a4, in("r9") a5,
        lateout("rcx") _, lateout("r11") _, options(nostack));
    ret
}

pub fn exit(code: i64) -> ! {
    // SAFETY: SYS_EXIT takes only an integer.
    unsafe { sc(SYS_EXIT, code as u64, 0, 0, 0, 0, 0) };
    loop {}
}
pub fn sleep_ms(ms: u64) {
    // SAFETY: integer argument only.
    unsafe { sc(SYS_SLEEP_MS, ms, 0, 0, 0, 0, 0) };
}
pub fn now_ms() -> u64 {
    // SAFETY: no arguments.
    unsafe { sc(SYS_TIME_NOW, 0, 0, 0, 0, 0, 0) as u64 }
}
pub fn cap_drop(h: u64) -> i64 {
    // SAFETY: integer argument only.
    unsafe { sc(SYS_CAP_DROP, h, 0, 0, 0, 0, 0) }
}
pub fn tty_write(h: u64, b: &[u8]) {
    for c in b.chunks(500) {
        // SAFETY: pointer/len describe a live slice.
        unsafe { sc(SYS_TTY_WRITE, h, c.as_ptr() as u64, c.len() as u64, 0, 0, 0) };
    }
}
/// Blocks until at least one byte is available (timeout `u64::MAX`) or the timeout (ms) passes (returns 0).
pub fn tty_read(h: u64, b: &mut [u8], timeout_ms: u64) -> i64 {
    // SAFETY: pointer/len describe a live mutable slice.
    unsafe { sc(SYS_TTY_READ, h, b.as_mut_ptr() as u64, b.len() as u64, timeout_ms, 0, 0) }
}

pub struct CapRec {
    pub handle: u64,
    pub kind: u32,
    pub rights: u32,
}
pub fn cap_list(i: u64) -> Option<CapRec> {
    let mut b = [0u8; 16];
    // SAFETY: `b` is a live 16-byte buffer.
    let r = unsafe { sc(SYS_CAP_LIST, i, b.as_mut_ptr() as u64, 0, 0, 0, 0) };
    if r < 0 {
        return None;
    }
    Some(CapRec { handle: u64::from_le_bytes(b[0..8].try_into().unwrap()), kind: u32::from_le_bytes(b[8..12].try_into().unwrap()), rights: u32::from_le_bytes(b[12..16].try_into().unwrap()) })
}
/// Handle of the first capability of `kind` (kinds: see `cap::CapObject::kind`).
pub fn find_cap(kind: u32) -> u64 {
    let mut i = 0;
    while let Some(c) = cap_list(i) {
        if c.kind == kind {
            return c.handle;
        }
        i += 1;
    }
    0
}
pub fn kind_name(k: u32) -> &'static str {
    match k {
        1 => "memory",
        2 => "channel",
        3 => "ioport",
        4 => "audit",
        5 => "process-id",
        6 => "console",
        7 => "net-grant",
        8 => "net-admin",
        9 => "dir",
        10 => "file",
        11 => "spawn",
        12 => "tty",
        13 => "sys",
        14 => "power",
        15 => "proc",
        16 => "store",
        17 => "store-file",
        18 => "policy",
        _ => "?",
    }
}

/// Startup arguments (NUL-separated) from the info page.
pub fn args() -> &'static [u8] {
    // SAFETY: the kernel maps the info page read-only at INFO_BASE for every native process it starts with
    // `exec::spawn`; word 8 holds the args length (<= 1024) and the bytes start at offset 128.
    unsafe {
        let n = core::ptr::read((INFO_BASE + 64) as *const u64) as usize;
        core::slice::from_raw_parts((INFO_BASE + 128) as *const u8, n.min(1024))
    }
}
pub fn info_handle(i: usize) -> u64 {
    // SAFETY: as above; handles live at words 3..8.
    unsafe { core::ptr::read((INFO_BASE + 24 + 8 * i) as *const u64) }
}

/// Buffered formatter writing to the tty capability `h`.
pub struct Out {
    pub h: u64,
    buf: [u8; 256],
    n: usize,
}
impl Out {
    pub fn new(h: u64) -> Out {
        Out { h, buf: [0; 256], n: 0 }
    }
    pub fn flush(&mut self) {
        if self.n > 0 {
            tty_write(self.h, &self.buf[..self.n]);
            self.n = 0;
        }
    }
}
impl Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.n == self.buf.len() {
                self.flush();
            }
            self.buf[self.n] = b;
            self.n += 1;
        }
        Ok(())
    }
}
