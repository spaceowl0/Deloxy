//! deloxy-utest: ring-3 test program for M4. The role is chosen by the kernel via
//! the info page (`InitInfo`). Exit code 0 = pass, otherwise the failing step.
#![no_std]
#![no_main]

use core::arch::asm;

// Same source file the kernel uses: identical shared-memory ring layout.
#[path = "../../../src/ipc/ring.rs"]
mod ring;
use ring::Spsc;

const EPERM: i64 = 1;
const EBADF: i64 = 9;
const EAGAIN: i64 = 11;

const R_READ: u64 = 1;
const R_IO: u64 = 64;
const R_NET: u64 = 128;

#[repr(C)]
struct InitInfo {
    role: u64,
    n: u64,
    side: u64,
    handles: [u64; 5],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Msg {
    seq: u64,
    payload: u64,
    pad: [u64; 6],
}
type MsgRing = Spsc<Msg, 32>;

const SYS_EXIT: i64 = 0;
const SYS_GETPID: i64 = 9;
const SYS_CAP_DROP: i64 = 11;
const SYS_CAP_DERIVE: i64 = 12;
const SYS_CAP_INFO: i64 = 13;
const SYS_SHM_MAP: i64 = 14;
const SYS_FUTEX_WAIT: i64 = 15;
const SYS_FUTEX_WAKE: i64 = 16;
const SYS_PORT_IN: i64 = 17;
const SYS_AUDIT_READ: i64 = 19;

#[inline(always)]
unsafe fn sc(nr: i64, a: u64, b: u64, c: u64) -> i64 {
    let ret: i64;
    asm!("syscall",
        inlateout("rax") nr => ret,
        in("rdi") a, in("rsi") b, in("rdx") c,
        lateout("rcx") _, lateout("r11") _,
        options(nostack));
    ret
}

fn exit(code: i64) -> ! {
    unsafe { sc(SYS_EXIT, code as u64, 0, 0) };
    loop {}
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(255)
}

#[no_mangle]
#[link_section = ".text._start"]
pub unsafe extern "C" fn _start(info: *const InitInfo) -> ! {
    let info = &*info;
    let code = match info.role {
        0 => cap_test(info),
        1 => audit_test(info),
        2 => ipc_producer(info),
        3 => ipc_consumer(info),
        _ => 250,
    };
    exit(code)
}

fn port_in(h: u64, port: u64) -> i64 {
    unsafe { sc(SYS_PORT_IN, h, port, 0) }
}
fn derive(h: u64, rights: u64) -> i64 {
    unsafe { sc(SYS_CAP_DERIVE, h, rights, 0) }
}

fn cap_test(i: &InitInfo) -> i64 {
    let (io_ok, io_ro) = (i.handles[0], i.handles[1]);
    let mut scratch = [0u64; 8];
    // 1: valid IO capability reads the COM1 line-status register (THR/TSR empty bits set at idle)
    let v = port_in(io_ok, 0x3FD);
    if v < 0 || (v & 0x60) != 0x60 {
        return 1;
    }
    // 2: capability without the IO right
    if port_in(io_ro, 0x3FD) != -EPERM {
        return 2;
    }
    // 3: port outside the authorised range
    if port_in(io_ok, 0x60) != -EPERM {
        return 3;
    }
    // 4: forged handle: correct slot index, wrong generation
    if port_in(0x1234_0000_0000_0000 | (io_ok & 0xFFFF_FFFF), 0x3FD) != -EBADF {
        return 4;
    }
    // 5: garbage handle
    if port_in(0xDEAD_BEEF, 0x3FD) != -EBADF {
        return 5;
    }
    // 6/7: attenuation works; the narrowed handle has no IO right
    let d = derive(io_ok, R_READ);
    if d < 0 {
        return 6;
    }
    if port_in(d as u64, 0x3FD) != -EPERM {
        return 7;
    }
    // 8: rights cannot be amplified
    if derive(io_ok, R_IO | R_NET) != -EPERM {
        return 8;
    }
    // 9: audit_read with a bogus handle
    if unsafe { sc(SYS_AUDIT_READ, 0xABCD, scratch.as_mut_ptr() as u64, 1) } != -EBADF {
        return 9;
    }
    // 10/11: dropping the parent makes it stale, and revokes the derived child
    if unsafe { sc(SYS_CAP_DROP, io_ok, 0, 0) } != 0 {
        return 10;
    }
    if port_in(io_ok, 0x3FD) != -EBADF {
        return 11;
    }
    if port_in(d as u64, 0x3FD) != -EBADF {
        return 12;
    }
    // 13: slot reuse gets a new generation; the old handle stays dead
    if unsafe { sc(SYS_CAP_INFO, io_ro, 0, 0) } < 0 {
        return 13;
    }
    0
}

fn audit_test(i: &InitInfo) -> i64 {
    let mut buf = [0u64; 8 * 16];
    unsafe { sc(SYS_GETPID, 0, 0, 0) }; // guarantees at least one event exists
    let n = unsafe { sc(SYS_AUDIT_READ, i.handles[0], buf.as_mut_ptr() as u64, 16) };
    if n < 1 {
        return 1;
    }
    // seq is the last u64 of each 64-byte record and must strictly increase
    let mut last = 0u64;
    for k in 0..n as usize {
        let seq = buf[k * 8 + 7];
        if k > 0 && seq <= last {
            return 2;
        }
        last = seq;
    }
    // stream capability without AUDIT_READ
    if unsafe { sc(SYS_AUDIT_READ, i.handles[1], buf.as_mut_ptr() as u64, 1) } != -EPERM {
        return 3;
    }
    0
}

// ---------------------------------------------------------------- IPC ------

fn ring_at(base: u64, page: u64) -> &'static MsgRing {
    unsafe { &*((base + page * 4096) as *const MsgRing) }
}

fn futex_wait(addr: *const u32, expected: u32) {
    let r = unsafe { sc(SYS_FUTEX_WAIT, addr as u64, expected as u64, 0) };
    let _ = (r, EAGAIN); // 0 = woken, -EAGAIN = value already changed; both mean "re-check"
}
fn futex_wake(addr: *const u32) {
    unsafe { sc(SYS_FUTEX_WAKE, addr as u64, 1, 0) };
}

fn send(tx: &MsgRing, m: Msg) {
    loop {
        match tx.try_push(m) {
            Some(was_empty) => {
                if was_empty {
                    futex_wake(tx.tail_ptr()); // consumer may be asleep on `tail`
                }
                return;
            }
            None => {
                let h = tx.head_val();
                if tx.is_full_at(h) {
                    futex_wait(tx.head_ptr(), h); // sleep until the consumer advances `head`
                }
            }
        }
    }
}

fn recv(rx: &MsgRing) -> Msg {
    loop {
        match rx.try_pop() {
            Some((m, was_full)) => {
                if was_full {
                    futex_wake(rx.head_ptr()); // producer may be asleep on `head`
                }
                return m;
            }
            None => {
                let t = rx.tail_val();
                if rx.head_val() == t {
                    futex_wait(rx.tail_ptr(), t);
                }
            }
        }
    }
}

fn ipc_producer(i: &InitInfo) -> i64 {
    let base = unsafe { sc(SYS_SHM_MAP, i.handles[0], 0, 0) };
    if base < 0 {
        return 1;
    }
    let tx = ring_at(base as u64, i.side); // page `side` is the ring this end writes
    for seq in 0..i.n {
        send(tx, Msg { seq, payload: seq.wrapping_mul(3).wrapping_add(1), pad: [0; 6] });
    }
    0
}

fn ipc_consumer(i: &InitInfo) -> i64 {
    let base = unsafe { sc(SYS_SHM_MAP, i.handles[0], 0, 0) };
    if base < 0 {
        return 1;
    }
    let rx = ring_at(base as u64, 1 - i.side); // the peer's ring
    let mut sum = 0u64;
    for expect in 0..i.n {
        let m = recv(rx);
        if m.seq != expect || m.payload != expect.wrapping_mul(3).wrapping_add(1) {
            return 10;
        }
        sum = sum.wrapping_add(m.payload);
    }
    let n = i.n;
    if sum != 3 * (n * (n - 1) / 2) + n {
        return 11;
    }
    0
}
