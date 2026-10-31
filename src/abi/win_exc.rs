//! Windows structured exception dispatch for PE processes (a pragmatic subset of SEH):
//!   * hardware faults (#PF/#GP -> 0xC0000005, #DE -> 0xC0000094, #UD -> 0xC000001D) and `RaiseException`
//!     are delivered to the vectored handlers (`AddVectoredExceptionHandler`) in order, then to the filter set with
//!     `SetUnhandledExceptionFilter`;
//!   * the handler receives a real `EXCEPTION_POINTERS` (EXCEPTION_RECORD + CONTEXT, including the FXSAVE image);
//!     `EXCEPTION_CONTINUE_EXECUTION` (-1) resumes from the (possibly edited) CONTEXT, `EXCEPTION_CONTINUE_SEARCH`
//!     (0) tries the next handler, a filter returning `EXCEPTION_EXECUTE_HANDLER` (1) ends the process with the
//!     exception code. With no handler registered nothing changes: the process dies exactly as before.
//!   * handlers run on the faulting thread's stack and *return* into a stub in the thunk page (`EXC_RET_VA`), which
//!     issues the internal `__DeloxyExcReturn` shim; that shim advances the chain or resumes through `iret_trapframe`.
//!
//! Not implemented: table-based frames (`.pdata`/UNWIND_INFO, `__try/__except`, `__C_specific_handler`),
//! `RtlUnwind`/`RtlVirtualUnwind`, `RtlCaptureContext` (still a zeroing stub), exceptions on a stack overflow.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::nt::NT_THUNK_BASE;
use crate::arch::x86_64::idt::TrapFrame;
use crate::arch::x86_64::syscall::SyscallFrame;
use crate::sys::uaccess::{copy_from_user, copy_to_user};
use crate::task::Process;

/// Stub in the thunk page that a handler returns into: `mov r10, rax; mov eax, <__DeloxyExcReturn>; syscall; ud2`.
pub const EXC_RET_VA: u64 = NT_THUNK_BASE + 0x3D00;

const CTX_LEN: u64 = 0x4D0;
const REC_LEN: u64 = 160;
const HDR_LEN: u64 = 32;
const MAGIC: u64 = 0x444C_5845_5843_3031;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
const STATUS_INT_DIVIDE_BY_ZERO: u32 = 0xC000_0094;
const NONCONTINUABLE: u32 = 1;
const KIND_SOFT: u64 = 1;
const FLAG_FILTER: u64 = 2;

#[repr(C, align(16))]
struct Fx([u8; 512]);

fn is_user(a: u64) -> bool {
    a < 0x0000_8000_0000_0000
}

pub fn exc_ret_stub(shim_nr: u32) -> [u8; 12] {
    let n = shim_nr.to_le_bytes();
    [0x49, 0x89, 0xC2, 0xB8, n[0], n[1], n[2], n[3], 0x0F, 0x05, 0x0F, 0x0B]
}

// ---- registration shims -------------------------------------------------------------------------------------------

pub fn add_veh(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    if !is_user(a[1]) || a[1] == 0 {
        return 0;
    }
    let mut g = p.foreign.lock();
    g.veh_next += 1;
    let handle = 0xEE00_0000 + g.veh_next * 0x10;
    if a[0] != 0 {
        g.veh.insert(0, (handle, a[1]));
    } else {
        g.veh.push((handle, a[1]));
    }
    handle
}

pub fn remove_veh(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    let mut g = p.foreign.lock();
    let n = g.veh.len();
    g.veh.retain(|(h, _)| *h != a[0]);
    (g.veh.len() != n) as u64
}

pub fn set_filter(p: &Arc<Process>, a: [u64; 4]) -> u64 {
    let mut g = p.foreign.lock();
    core::mem::replace(&mut g.ueh, if is_user(a[0]) { a[0] } else { 0 })
}

/// Placeholder body for the internal return shim (the real work happens in `nt::syscall`, which has the frame).
pub fn exc_return_stub(_p: &Arc<Process>, _a: [u64; 4]) -> u64 {
    0
}

/// Handler number `idx` of the chain: the vectored handlers, then the unhandled-exception filter.
fn pick(p: &Arc<Process>, idx: u64) -> Option<(u64, bool)> {
    let g = p.foreign.lock();
    let i = idx as usize;
    if i < g.veh.len() {
        Some((g.veh[i].1, false))
    } else if i == g.veh.len() && g.ueh != 0 {
        Some((g.ueh, true))
    } else {
        None
    }
}

fn user_frame_selectors() -> (u64, u64) {
    let s = crate::arch::x86_64::gdt::selectors();
    (s.user_code.0 as u64, s.user_data.0 as u64)
}

fn tf_from_syscall(f: &SyscallFrame) -> TrapFrame {
    let (cs, ss) = user_frame_selectors();
    TrapFrame {
        r15: f.r15, r14: f.r14, r13: f.r13, r12: f.r12, r11: f.rflags, r10: f.r10, r9: f.r9, r8: f.r8, rbp: f.rbp, rdi: f.rdi,
        rsi: f.rsi, rdx: f.rdx, rcx: f.rip, rbx: f.rbx, rax: f.rax, vector: 0, error: 0, rip: f.rip, cs, rflags: f.rflags,
        rsp: f.rsp, ss,
    }
}

// ---- CONTEXT <-> registers ------------------------------------------------------------------------------------------

fn put(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn get(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

fn context_from(tf: &TrapFrame) -> Vec<u8> {
    let mut c = alloc::vec![0u8; CTX_LEN as usize];
    c[0x30..0x34].copy_from_slice(&0x0010_000Fu32.to_le_bytes()); // CONTEXT_CONTROL|INTEGER|SEGMENTS|FLOATING_POINT
    c[0x38..0x3A].copy_from_slice(&(tf.cs as u16).to_le_bytes());
    c[0x42..0x44].copy_from_slice(&(tf.ss as u16).to_le_bytes());
    c[0x44..0x48].copy_from_slice(&(tf.rflags as u32).to_le_bytes());
    let regs = [
        (0x78, tf.rax), (0x80, tf.rcx), (0x88, tf.rdx), (0x90, tf.rbx), (0x98, tf.rsp), (0xA0, tf.rbp), (0xA8, tf.rsi),
        (0xB0, tf.rdi), (0xB8, tf.r8), (0xC0, tf.r9), (0xC8, tf.r10), (0xD0, tf.r11), (0xD8, tf.r12), (0xE0, tf.r13),
        (0xE8, tf.r14), (0xF0, tf.r15), (0xF8, tf.rip),
    ];
    for (o, v) in regs {
        put(&mut c, o, v);
    }
    let mut fx = Fx([0; 512]);
    // SAFETY: 16-byte aligned 512-byte buffer; CR4.OSFXSR is on for user mode (the kernel itself does not touch SSE state).
    unsafe { core::arch::asm!("fxsave64 [{}]", in(reg) fx.0.as_mut_ptr(), options(nostack)) };
    c[0x34..0x38].copy_from_slice(&fx.0[24..28]); // MxCsr
    c[0x100..0x300].copy_from_slice(&fx.0);
    c
}

/// Rebuild a `TrapFrame` from a CONTEXT image (validated) and restore the FPU/SSE state from it.
fn tf_from_context(c: &[u8]) -> Option<TrapFrame> {
    let rip = get(c, 0xF8);
    let rsp = get(c, 0x98);
    if !is_user(rip) || !is_user(rsp) || rip == 0 {
        return None;
    }
    let (cs, ss) = user_frame_selectors();
    let eflags = u32::from_le_bytes(c[0x44..0x48].try_into().unwrap()) as u64;
    let mut fx = Fx([0; 512]);
    fx.0.copy_from_slice(&c[0x100..0x300]);
    let mxcsr = u32::from_le_bytes(fx.0[24..28].try_into().unwrap()) & 0xFFBF;
    fx.0[24..28].copy_from_slice(&mxcsr.to_le_bytes());
    // SAFETY: aligned image written by FXSAVE (possibly edited by the program; reserved MXCSR bits were masked above).
    unsafe { core::arch::asm!("fxrstor64 [{}]", in(reg) fx.0.as_ptr(), options(nostack)) };
    Some(TrapFrame {
        r15: get(c, 0xF0), r14: get(c, 0xE8), r13: get(c, 0xE0), r12: get(c, 0xD8), r11: get(c, 0xD0), r10: get(c, 0xC8),
        r9: get(c, 0xC0), r8: get(c, 0xB8), rbp: get(c, 0xA0), rdi: get(c, 0xB0), rsi: get(c, 0xA8), rdx: get(c, 0x88),
        rcx: get(c, 0x80), rbx: get(c, 0x90), rax: get(c, 0x78), vector: 0, error: 0, rip, cs,
        rflags: (eflags & 0x8D5) | 0x202, rsp, ss,
    })
}

// ---- dispatch ----------------------------------------------------------------------------------------------------------

/// Build the exception frame on the user stack and aim `tf` at the first handler. `false` = nothing registered or no
/// usable stack (the caller then terminates the process as before).
fn begin(p: &Arc<Process>, tf: &mut TrapFrame, code: u32, flags: u32, addr: u64, params: &[u64], kind: u64, exit: u64) -> bool {
    let Some((target, is_filter)) = pick(p, 0) else { return false };
    let Some(top) = tf.rsp.checked_sub(128) else { return false };
    let top = top & !0xF;
    let ctx = match top.checked_sub(CTX_LEN) {
        Some(v) => v & !0xF,
        None => return false,
    };
    let rec = ctx - REC_LEN;
    let ptrs = rec - 16;
    let hdr = ptrs - HDR_LEN;
    let x = hdr - 56; // x % 16 == 8: the stack state at a function's first instruction
    if !is_user(x) {
        return false;
    }
    let mut r = [0u8; REC_LEN as usize];
    r[0..4].copy_from_slice(&code.to_le_bytes());
    r[4..8].copy_from_slice(&flags.to_le_bytes());
    r[0x10..0x18].copy_from_slice(&addr.to_le_bytes());
    let n = params.len().min(15);
    r[0x18..0x1C].copy_from_slice(&(n as u32).to_le_bytes());
    for (i, v) in params.iter().take(n).enumerate() {
        put(&mut r, 0x20 + i * 8, *v);
    }
    let mut h = [0u8; HDR_LEN as usize];
    put(&mut h, 0, MAGIC);
    put(&mut h, 8, 1); // next handler index
    put(&mut h, 16, exit);
    put(&mut h, 24, kind | if is_filter { FLAG_FILTER } else { 0 });
    let mut pt = [0u8; 16];
    put(&mut pt, 0, rec);
    put(&mut pt, 8, ctx);
    let c = context_from(tf);
    let ok = copy_to_user(p, ctx, &c).is_ok()
        && copy_to_user(p, rec, &r).is_ok()
        && copy_to_user(p, ptrs, &pt).is_ok()
        && copy_to_user(p, hdr, &h).is_ok()
        && copy_to_user(p, x, &EXC_RET_VA.to_le_bytes()).is_ok();
    if !ok {
        return false;
    }
    tf.rsp = x;
    tf.rip = target;
    tf.rcx = ptrs;
    tf.rflags = (tf.rflags & !0x400) | 0x200;
    true
}

/// A CPU fault in a PE process. `true` = `tf` now runs a handler.
pub fn deliver_fault(p: &Arc<Process>, tf: &mut TrapFrame, cr2: u64, exit: i64) -> bool {
    let (code, params): (u32, Vec<u64>) = match tf.vector {
        0 => (STATUS_INT_DIVIDE_BY_ZERO, Vec::new()),
        6 => (STATUS_ILLEGAL_INSTRUCTION, Vec::new()),
        13 => (STATUS_ACCESS_VIOLATION, alloc::vec![0, 0]),
        _ => {
            let kind = if tf.error & 0x10 != 0 { 8 } else if tf.error & 2 != 0 { 1 } else { 0 };
            (STATUS_ACCESS_VIOLATION, alloc::vec![kind, cr2])
        }
    };
    let rip = tf.rip;
    begin(p, tf, code, 0, rip, &params, 0, exit as u64)
}

/// `RaiseException(code, flags, nargs, args*)`: never returns when a handler was started.
pub fn raise(p: &Arc<Process>, f: &mut SyscallFrame, a: [u64; 4]) {
    let n = (a[2] as usize).min(15);
    let mut params: Vec<u64> = Vec::new();
    if n > 0 && a[3] != 0 {
        let mut buf = alloc::vec![0u8; n * 8];
        if copy_from_user(p, &mut buf, a[3]).is_ok() {
            for i in 0..n {
                params.push(get(&buf, i * 8));
            }
        }
    }
    let mut tf = tf_from_syscall(f);
    let rip = tf.rip;
    if begin(p, &mut tf, a[0] as u32, a[1] as u32, rip, &params, KIND_SOFT, a[0] as u32 as u64) {
        // SAFETY: tf describes valid user-mode state (rsp/rip checked in `begin`, selectors are the user segments).
        unsafe { crate::arch::x86_64::idt::iret_trapframe(&tf) }
    }
    log::warn!("win: RaiseException({:#x}) - unhandled, terminating", a[0]);
    super::vfs::flush_all(p);
    crate::task::sched::exit_process(a[0] as u32 as i64)
}

fn terminate(p: &Arc<Process>, kind: u64, exit: u64, code: u32, rip: u64) -> ! {
    if kind & KIND_SOFT != 0 {
        log::warn!("win: exception {:#x} unhandled, terminating", code);
        super::vfs::flush_all(p);
        crate::task::sched::exit_process(code as i64)
    }
    log::warn!("user fault: exception {:#x} unhandled in pid {} at rip {:#x} - killing process", code, p.pid, rip);
    crate::audit_log!(crate::audit::EV_FAULT, 0, 0, rip, code as u64, exit as i64);
    crate::task::kill_current_process(exit as i64)
}

/// The internal return shim: a handler returned `res` (its LONG result, from RAX) into `EXC_RET_VA`.
pub fn exc_return(p: &Arc<Process>, f: &mut SyscallFrame, res: u64) {
    let res = res as u32 as i32;
    let hdr = f.rsp.wrapping_add(48); // rsp = x + 8 after the handler's `ret`; hdr = x + 56
    let mut h = [0u8; HDR_LEN as usize];
    if !is_user(hdr) || copy_from_user(p, &mut h, hdr).is_err() || get(&h, 0) != MAGIC {
        crate::task::kill_current_process(crate::sys::errno::EXIT_FAULT_GP)
    }
    let mut pt = [0u8; 16];
    let _ = copy_from_user(p, &mut pt, hdr + HDR_LEN);
    let (rec, ctx) = (get(&pt, 0), get(&pt, 8));
    let mut r = [0u8; REC_LEN as usize];
    let mut c = alloc::vec![0u8; CTX_LEN as usize];
    if copy_from_user(p, &mut r, rec).is_err() || copy_from_user(p, &mut c, ctx).is_err() {
        crate::task::kill_current_process(crate::sys::errno::EXIT_FAULT_GP)
    }
    let code = u32::from_le_bytes(r[0..4].try_into().unwrap());
    let flags = u32::from_le_bytes(r[4..8].try_into().unwrap());
    let (next, exit, kind) = (get(&h, 8), get(&h, 16), get(&h, 24));
    let rip = get(&c, 0xF8);
    if res == -1 {
        if flags & NONCONTINUABLE != 0 {
            terminate(p, kind, exit, code, rip);
        }
        match tf_from_context(&c) {
            // SAFETY: validated user state, user selectors, sanitised rflags.
            Some(tf) => unsafe { crate::arch::x86_64::idt::iret_trapframe(&tf) },
            None => terminate(p, kind, exit, code, rip),
        }
    }
    if kind & FLAG_FILTER != 0 {
        // the unhandled-exception filter answered: EXECUTE_HANDLER ends the process with the exception code
        let e = if res == 1 { code as u64 } else { exit };
        if res == 1 {
            super::vfs::flush_all(p);
            crate::task::sched::exit_process(code as i64)
        }
        terminate(p, kind, e, code, rip);
    }
    // EXCEPTION_CONTINUE_SEARCH: next handler of the chain, on the same frame
    let Some((target, is_filter)) = pick(p, next) else { terminate(p, kind, exit, code, rip) };
    let x = hdr - 56;
    let mut h2 = h;
    put(&mut h2, 8, next + 1);
    put(&mut h2, 24, (kind & KIND_SOFT) | if is_filter { FLAG_FILTER } else { 0 });
    if copy_to_user(p, hdr, &h2).is_err() || copy_to_user(p, x, &EXC_RET_VA.to_le_bytes()).is_err() {
        terminate(p, kind, exit, code, rip);
    }
    let mut tf = tf_from_syscall(f);
    tf.rsp = x;
    tf.rip = target;
    tf.rcx = hdr + HDR_LEN;
    tf.rflags = (tf.rflags & !0x400) | 0x202;
    // SAFETY: x and target are user addresses (target was validated at registration).
    unsafe { crate::arch::x86_64::idt::iret_trapframe(&tf) }
}
