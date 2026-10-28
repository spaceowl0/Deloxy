//! `deloxy-audit`: lockless kernel event stream.
//!
//! Producers never block, allocate or take locks: they push into a static SPSC
//! ring and bump a drop counter when it is full. There is one producer at a time
//! on this single-CPU kernel (every producer runs with interrupts off: syscalls
//! and exception handlers); SMP will need one ring per CPU. The consumer is the
//! holder of an `AuditStream` capability (or kernel code) - one at a time.

use crate::ipc::ring::Spsc;

pub const EV_SYSCALL: u16 = 1;
pub const EV_CAP_DENIED: u16 = 2;
pub const EV_PROC_SPAWN: u16 = 3;
pub const EV_PROC_EXIT: u16 = 4;
pub const EV_FAULT: u16 = 5;
/// Network firewall decisions. `sysno` = dir | proto<<8 | reason<<16 (dir 0=out 1=in), `cap` = NetGrant id
/// (0 = infrastructure rule or no grant), `arg0` = remote IPv4 (big-endian as u32), `arg1` = remote port.
pub const EV_NET_ALLOW: u16 = 6;
pub const EV_NET_DENY: u16 = 7;

/// Stable 64-byte ABI record (also what `audit_read` copies to user space).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct AuditEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub kind: u16,
    pub flags: u16,
    pub sysno: u32,
    pub result: i64,
    pub cap: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub seq: u64,
}

const _: () = assert!(core::mem::size_of::<AuditEvent>() == 64);

static RING: Spsc<AuditEvent, 2048> = Spsc::new();
static SEQ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Record an event. Never blocks; lossy when the ring is full.
pub fn log(kind: u16, sysno: u32, cap: u64, arg0: u64, arg1: u64, result: i64) {
    let (pid, tid) = crate::task::try_current_ids();
    let ev = AuditEvent {
        ts_ns: crate::time::uptime_ms() * 1_000_000,
        pid: pid as u32,
        tid: tid as u32,
        kind,
        flags: 0,
        sysno,
        result,
        cap,
        arg0,
        arg1,
        seq: SEQ.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
    };
    RING.push_lossy(ev);
}

/// Consumer side (single consumer at a time).
pub fn pop() -> Option<AuditEvent> {
    RING.pop()
}

pub fn dropped() -> u64 {
    RING.dropped()
}

pub fn pending() -> usize {
    RING.len()
}

#[macro_export]
macro_rules! audit_log {
    ($kind:expr, $sysno:expr, $cap:expr, $a0:expr, $a1:expr, $res:expr) => {
        $crate::audit::log($kind, $sysno as u32, $cap as u64, $a0 as u64, $a1 as u64, $res as i64)
    };
}
