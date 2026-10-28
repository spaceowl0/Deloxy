//! POSIX signals and timers for Linux processes.
//!
//! * **Dispositions** (`rt_sigaction`), **masks** (`rt_sigprocmask`) and **pending sets** are per process (all threads of
//!   a process share them; any thread may take a signal).
//! * **Delivery happens when a syscall returns** (`on_syscall_exit`), and a blocked syscall is interrupted: blocking loops
//!   call `interrupted()` and return `-ERESTART` (restartable: `read`, `wait4`, `accept`... restarted when the handler
//!   has `SA_RESTART`, otherwise `EINTR`) or `-EINTR` (`nanosleep`, `poll`, `select`, `sigsuspend`: never restarted).
//!   A process spinning in user mode without making syscalls receives a *handled* signal at its next syscall; signals whose
//!   action is "terminate" are applied immediately by `kill`.
//! * **Handler frames** follow the x86-64 `rt_sigframe` layout glibc expects (`ucontext` + `siginfo`, `sa_restorer`
//!   return, FPU state saved with `fxsave`), and `rt_sigreturn` restores everything with the user-modifiable flags
//!   sanitised and the target addresses checked (a forged frame cannot make the kernel `sysret` to a non-canonical rip).
//! * **Timers:** `alarm`, `setitimer(ITIMER_REAL)` and POSIX `timer_create/settime/...` are served by the `sigtimer`
//!   kernel thread, which raises the signal when a deadline passes.
//! * `SIGCHLD` is raised to the parent when a child exits; `SIGPIPE` on writes to a pipe/socket nobody reads.
//!   Not implemented: signals from CPU faults (`SIGSEGV` still kills), process groups, `SA_ONSTACK` alternate stacks,
//!   `signalfd`, real-time signal queueing (a signal pending twice is delivered once).

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::arch::x86_64::syscall::SyscallFrame;
use crate::sys::uaccess::{copy_from_user, copy_to_user};
use crate::task::{self, Process};

pub const SIGHUP: u64 = 1;
pub const SIGINT: u64 = 2;
pub const SIGKILL: u64 = 9;
pub const SIGPIPE: u64 = 13;
pub const SIGALRM: u64 = 14;
pub const SIGTERM: u64 = 15;
pub const SIGCHLD: u64 = 17;
pub const SIGCONT: u64 = 18;
pub const SIGSTOP: u64 = 19;

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;
pub const SA_RESTART: u64 = 0x1000_0000;
pub const SA_NODEFER: u64 = 0x4000_0000;
pub const SA_RESETHAND: u64 = 0x8000_0000;
pub const SA_RESTORER: u64 = 0x0400_0000;

pub const EINTR: i64 = 4;
/// Internal "interrupted, restart if the handler asked for it" (ERESTARTSYS).
pub const ERESTART: i64 = 512;

#[derive(Clone, Copy)]
pub struct SigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}
const DEFAULT_ACTION: SigAction = SigAction { handler: SIG_DFL, flags: 0, restorer: 0, mask: 0 };

#[derive(Clone, Copy)]
pub struct PosixTimer {
    pub id: i32,
    pub signo: u8,
    pub value: u64,
    pub interval: u64,
    /// uptime deadline in ms (0 = disarmed)
    pub deadline: u64,
    pub notify: bool,
}

pub struct SigState {
    pub actions: [SigAction; 65],
    pub mask: u64,
    pub pending: u64,
    /// mask to restore after the handler of a `sigsuspend` returns
    pub saved_mask: Option<u64>,
    /// ITIMER_REAL: (deadline uptime ms, interval ms), 0 = off
    pub itimer: (u64, u64),
    pub timers: Vec<PosixTimer>,
    pub next_timer: i32,
}

impl SigState {
    pub const fn new() -> SigState {
        SigState { actions: [DEFAULT_ACTION; 65], mask: 0, pending: 0, saved_mask: None, itimer: (0, 0), timers: Vec::new(), next_timer: 1 }
    }
}

fn bit(sig: u64) -> u64 {
    1u64 << (sig - 1)
}

/// Is the default action of `sig` "ignore" (SIGCHLD, SIGURG, SIGWINCH, SIGCONT and the stop signals)?
fn default_ignored(sig: u64) -> bool {
    matches!(sig, 17 | 18 | 19 | 20 | 21 | 22 | 23 | 28)
}

/// Raise `sig` for `p`: ignored signals are dropped, the rest become pending.
pub fn raise(p: &Arc<Process>, sig: u64) {
    if sig == 0 || sig > 64 {
        return;
    }
    let mut g = p.foreign.lock();
    let a = g.sig.actions[sig as usize];
    if sig != SIGKILL && sig != SIGSTOP && (a.handler == SIG_IGN || (a.handler == SIG_DFL && default_ignored(sig))) {
        return;
    }
    g.sig.pending |= bit(sig);
}

/// `raise` for contexts that must not block (scheduler paths): gives up silently if the lock is busy.
pub fn raise_try(p: &Arc<Process>, sig: u64) {
    if sig == 0 || sig > 64 {
        return;
    }
    if let Some(mut g) = p.foreign.try_lock() {
        let a = g.sig.actions[sig as usize];
        if sig != SIGKILL && sig != SIGSTOP && (a.handler == SIG_IGN || (a.handler == SIG_DFL && default_ignored(sig))) {
            return;
        }
        g.sig.pending |= bit(sig);
    }
}

/// A signal that would interrupt a blocking syscall is pending and not blocked.
pub fn interrupted(p: &Arc<Process>) -> bool {
    let g = p.foreign.lock();
    let m = g.sig.mask & !(bit(SIGKILL) | bit(SIGSTOP));
    g.sig.pending & !m != 0
}

/// kill(2) semantics for a target process. Default-terminate signals take effect immediately (even on a process that
/// never enters the kernel); handled signals are queued for delivery at the target's next syscall return.
pub fn send(target: &Arc<Process>, sig: u64) {
    if sig == 0 || sig > 64 || target.has_exited() {
        return;
    }
    let (act, blocked) = {
        let g = target.foreign.lock();
        (g.sig.actions[sig as usize], g.sig.mask & bit(sig) != 0)
    };
    let terminates = sig == SIGKILL || (act.handler == SIG_DFL && !default_ignored(sig));
    if terminates && (sig == SIGKILL || !blocked) {
        target.foreign.lock().killed_sig = sig as u8;
        task::sched::kill_process(target, 128 + sig as i64);
        return;
    }
    raise(target, sig);
}

fn take_deliverable(p: &Arc<Process>) -> Option<(u64, SigAction, u64)> {
    let mut g = p.foreign.lock();
    let m = g.sig.mask & !(bit(SIGKILL) | bit(SIGSTOP));
    let ready = g.sig.pending & !m;
    if ready == 0 {
        return None;
    }
    let sig = ready.trailing_zeros() as u64 + 1;
    g.sig.pending &= !bit(sig);
    let act = g.sig.actions[sig as usize];
    // the mask the interrupted code must get back when the handler returns
    let old_mask = g.sig.saved_mask.take().unwrap_or(g.sig.mask);
    Some((sig, act, old_mask))
}

// ---- rt_sigaction / rt_sigprocmask / pending ----

/// rt_sigaction(sig, act*, oldact*, sigsetsize)
pub fn rt_sigaction(p: &Arc<Process>, sig: u64, act: u64, old: u64, size: u64) -> i64 {
    if sig == 0 || sig > 64 || size != 8 || (act != 0 && (sig == SIGKILL || sig == SIGSTOP)) {
        return -22;
    }
    if old != 0 {
        let a = p.foreign.lock().sig.actions[sig as usize];
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&a.handler.to_le_bytes());
        b[8..16].copy_from_slice(&a.flags.to_le_bytes());
        b[16..24].copy_from_slice(&a.restorer.to_le_bytes());
        b[24..32].copy_from_slice(&a.mask.to_le_bytes());
        if copy_to_user(p, old, &b).is_err() {
            return -14;
        }
    }
    if act != 0 {
        let mut b = [0u8; 32];
        if copy_from_user(p, &mut b, act).is_err() {
            return -14;
        }
        let a = SigAction {
            handler: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            flags: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            restorer: u64::from_le_bytes(b[16..24].try_into().unwrap()),
            mask: u64::from_le_bytes(b[24..32].try_into().unwrap()),
        };
        let mut g = p.foreign.lock();
        g.sig.actions[sig as usize] = a;
        if a.handler == SIG_IGN || (a.handler == SIG_DFL && default_ignored(sig)) {
            g.sig.pending &= !bit(sig); // POSIX: setting an ignored disposition discards pending instances
        }
    }
    0
}

/// rt_sigprocmask(how, set*, oldset*, sigsetsize)
pub fn rt_sigprocmask(p: &Arc<Process>, how: u64, set: u64, old: u64, size: u64) -> i64 {
    if size != 8 {
        return -22;
    }
    let cur = p.foreign.lock().sig.mask;
    if old != 0 && copy_to_user(p, old, &cur.to_le_bytes()).is_err() {
        return -14;
    }
    if set != 0 {
        let mut b = [0u8; 8];
        if copy_from_user(p, &mut b, set).is_err() {
            return -14;
        }
        let s = u64::from_le_bytes(b);
        let new = match how {
            0 => cur | s,
            1 => cur & !s,
            2 => s,
            _ => return -22,
        };
        p.foreign.lock().sig.mask = new & !(bit(SIGKILL) | bit(SIGSTOP));
    }
    0
}

pub fn rt_sigpending(p: &Arc<Process>, set: u64, size: u64) -> i64 {
    if size != 8 {
        return -22;
    }
    let g = p.foreign.lock();
    let v = g.sig.pending & g.sig.mask;
    drop(g);
    match copy_to_user(p, set, &v.to_le_bytes()) {
        Ok(()) => 0,
        Err(_) => -14,
    }
}

/// rt_sigsuspend(mask*, size): replace the mask and sleep until a signal arrives; always returns -EINTR.
pub fn rt_sigsuspend(p: &Arc<Process>, mask: u64, size: u64) -> i64 {
    if size != 8 {
        return -22;
    }
    let mut b = [0u8; 8];
    if copy_from_user(p, &mut b, mask).is_err() {
        return -14;
    }
    let new = u64::from_le_bytes(b) & !(bit(SIGKILL) | bit(SIGSTOP));
    {
        let mut g = p.foreign.lock();
        let old = g.sig.mask;
        g.sig.saved_mask = Some(old);
        g.sig.mask = new;
    }
    while !interrupted(p) {
        task::sleep_ms(1);
    }
    -EINTR
}

/// pause(): sleep until a signal arrives.
pub fn pause(p: &Arc<Process>) -> i64 {
    while !interrupted(p) {
        task::sleep_ms(1);
    }
    -EINTR
}

/// rt_sigtimedwait(set*, info*, timeout*, size): consume a pending signal from `set` (it is not delivered to a handler).
pub fn rt_sigtimedwait(p: &Arc<Process>, set: u64, info: u64, timeout: u64, size: u64) -> i64 {
    if size != 8 {
        return -22;
    }
    let mut b = [0u8; 8];
    if copy_from_user(p, &mut b, set).is_err() {
        return -14;
    }
    let want = u64::from_le_bytes(b);
    let limit_ms: Option<u64> = if timeout == 0 {
        None
    } else {
        let mut t = [0u8; 16];
        if copy_from_user(p, &mut t, timeout).is_err() {
            return -14;
        }
        Some(u64::from_le_bytes(t[..8].try_into().unwrap()).saturating_mul(1000) + u64::from_le_bytes(t[8..].try_into().unwrap()) / 1_000_000)
    };
    let t0 = crate::time::uptime_ms();
    loop {
        {
            let mut g = p.foreign.lock();
            let hit = g.sig.pending & want;
            if hit != 0 {
                let sig = hit.trailing_zeros() as u64 + 1;
                g.sig.pending &= !bit(sig);
                drop(g);
                if info != 0 {
                    let mut si = [0u8; 128];
                    si[0..4].copy_from_slice(&(sig as i32).to_le_bytes());
                    let _ = copy_to_user(p, info, &si);
                }
                return sig as i64;
            }
        }
        if let Some(l) = limit_ms {
            if crate::time::uptime_ms().saturating_sub(t0) >= l {
                return -11; // EAGAIN
            }
        }
        if interrupted(p) {
            return -EINTR;
        }
        task::sleep_ms(1);
    }
}

// ---- delivery ----

#[repr(C, align(16))]
struct Fx([u8; 512]);

const UC_OFF: u64 = 8; // pretcode(8) | ucontext(320) | siginfo(128) | fxstate(512)
const UC_LEN: u64 = 320;
const INFO_OFF: u64 = UC_OFF + UC_LEN;
const FX_OFF: u64 = INFO_OFF + 128;
const FRAME_LEN: u64 = FX_OFF + 512;

// ucontext field offsets (kernel layout: flags, link, stack(24), sigcontext, sigmask)
const G_R8: usize = 40; // r8 r9 r10 r11 r12 r13 r14 r15 rdi rsi rbp rbx rdx rax rcx rsp rip eflags ...
const G_FPPTR: usize = 224;
const G_SIGMASK: usize = 296;

fn is_user_addr(a: u64) -> bool {
    a < 0x0000_8000_0000_0000
}

/// Run at every Linux syscall return. Delivers at most one signal; returns the value for `rax`.
pub fn on_syscall_exit(f: &mut SyscallFrame, nr: u64, mut ret: i64) -> i64 {
    if nr == 15 {
        return ret; // rt_sigreturn already restored everything, including rax
    }
    let p = task::current_process();
    let Some((sig, act, old_mask)) = take_deliverable(&p) else {
        if ret == -ERESTART {
            // the signal that interrupted us was consumed elsewhere: just retry the syscall
            f.rip -= 2;
            return nr as i64;
        }
        return ret;
    };
    // default action
    if act.handler == SIG_DFL {
        if default_ignored(sig) {
            return if ret == -ERESTART { { f.rip -= 2; nr as i64 } } else { ret };
        }
        p.foreign.lock().killed_sig = sig as u8;
        task::sched::exit_process(128 + sig as i64);
    }
    if act.handler == SIG_IGN {
        return if ret == -ERESTART { { f.rip -= 2; nr as i64 } } else { ret };
    }
    // a restartable syscall is restarted after the handler only with SA_RESTART
    let restart = ret == -ERESTART && act.flags & SA_RESTART != 0;
    if ret == -ERESTART && !restart {
        ret = -EINTR;
    }
    let resume_rip = if restart { f.rip - 2 } else { f.rip };
    let resume_rax = if restart { nr } else { ret as u64 };
    if setup_frame(&p, f, sig, &act, old_mask, resume_rip, resume_rax).is_err() {
        // no usable stack: Linux forces SIGSEGV; we terminate
        p.foreign.lock().killed_sig = 11;
        task::sched::exit_process(128 + 11);
    }
    {
        let mut g = p.foreign.lock();
        let mut m = g.sig.mask | act.mask;
        if act.flags & SA_NODEFER == 0 {
            m |= bit(sig);
        }
        g.sig.mask = m & !(bit(SIGKILL) | bit(SIGSTOP));
        if act.flags & SA_RESETHAND != 0 {
            g.sig.actions[sig as usize] = DEFAULT_ACTION;
        }
    }
    0
}

fn setup_frame(p: &Arc<Process>, f: &mut SyscallFrame, sig: u64, act: &SigAction, old_mask: u64, resume_rip: u64, resume_rax: u64) -> Result<(), ()> {
    let sp = f.rsp.checked_sub(128).ok_or(())?; // skip the red zone
    let x = sp.checked_sub(FRAME_LEN).ok_or(())?;
    let base = (x & !0xF) - 8; // base + 8 is 16-byte aligned: the ABI state at a function's first instruction
    if !is_user_addr(base) || !is_user_addr(act.handler) {
        return Err(());
    }
    let mut uc = [0u8; UC_LEN as usize];
    let w = |uc: &mut [u8], off: usize, v: u64| uc[off..off + 8].copy_from_slice(&v.to_le_bytes());
    let regs = [f.r8, f.r9, f.r10, f.rflags, f.r12, f.r13, f.r14, f.r15, f.rdi, f.rsi, f.rbp, f.rbx, f.rdx, resume_rax, f.rip, f.rsp, resume_rip, f.rflags];
    for (i, v) in regs.iter().enumerate() {
        w(&mut uc, G_R8 + i * 8, *v);
    }
    w(&mut uc, G_FPPTR, base + FX_OFF);
    w(&mut uc, G_SIGMASK, old_mask);
    let mut info = [0u8; 128];
    info[0..4].copy_from_slice(&(sig as i32).to_le_bytes());
    let mut fx = Fx([0; 512]);
    // SAFETY: `fx` is 16-byte aligned and 512 bytes, as FXSAVE requires; CR4.OSFXSR is enabled for user mode.
    unsafe { core::arch::asm!("fxsave64 [{}]", in(reg) fx.0.as_mut_ptr(), options(nostack)) };
    let restorer = act.restorer;
    copy_to_user(p, base, &restorer.to_le_bytes()).map_err(|_| ())?;
    copy_to_user(p, base + UC_OFF, &uc).map_err(|_| ())?;
    copy_to_user(p, base + INFO_OFF, &info).map_err(|_| ())?;
    copy_to_user(p, base + FX_OFF, &fx.0).map_err(|_| ())?;
    f.rsp = base;
    f.rip = act.handler;
    f.rdi = sig;
    f.rsi = base + INFO_OFF;
    f.rdx = base + UC_OFF;
    f.rflags = (f.rflags & !0x400) | 0x200; // DF clear, IF set
    Ok(())
}

/// rt_sigreturn(): the handler returned through `sa_restorer`; `rsp` now points at the ucontext.
pub fn rt_sigreturn(p: &Arc<Process>, f: &mut SyscallFrame) -> i64 {
    let uc_addr = f.rsp;
    let mut uc = [0u8; UC_LEN as usize];
    if copy_from_user(p, &mut uc, uc_addr).is_err() {
        p.foreign.lock().killed_sig = 11;
        task::sched::exit_process(128 + 11);
    }
    let r = |i: usize| u64::from_le_bytes(uc[G_R8 + i * 8..G_R8 + i * 8 + 8].try_into().unwrap());
    let (rip, rsp) = (r(16), r(15));
    if !is_user_addr(rip) || !is_user_addr(rsp) {
        p.foreign.lock().killed_sig = 11;
        task::sched::exit_process(128 + 11);
    }
    f.r8 = r(0);
    f.r9 = r(1);
    f.r10 = r(2);
    f.r12 = r(4);
    f.r13 = r(5);
    f.r14 = r(6);
    f.r15 = r(7);
    f.rdi = r(8);
    f.rsi = r(9);
    f.rbp = r(10);
    f.rbx = r(11);
    f.rdx = r(12);
    f.rip = rip;
    f.rsp = rsp;
    f.rflags = (r(17) & 0x8D5) | 0x202; // only CF PF AF ZF SF DF OF are user-modifiable; IF stays on
    let fp = u64::from_le_bytes(uc[G_FPPTR..G_FPPTR + 8].try_into().unwrap());
    if fp != 0 && is_user_addr(fp) && fp % 16 == 0 {
        let mut fx = Fx([0; 512]);
        if copy_from_user(p, &mut fx.0, fp).is_ok() {
            // SAFETY: aligned 512-byte image written by our own FXSAVE; MXCSR reserved bits could fault, so mask them.
            let mxcsr = u32::from_le_bytes(fx.0[24..28].try_into().unwrap()) & 0xFFBF;
            fx.0[24..28].copy_from_slice(&mxcsr.to_le_bytes());
            unsafe { core::arch::asm!("fxrstor64 [{}]", in(reg) fx.0.as_ptr(), options(nostack)) };
        }
    }
    let mask = u64::from_le_bytes(uc[G_SIGMASK..G_SIGMASK + 8].try_into().unwrap());
    p.foreign.lock().sig.mask = mask & !(bit(SIGKILL) | bit(SIGSTOP));
    r(13) as i64 // the interrupted syscall's result (or the restart number)
}

// ---- timers ----

fn now() -> u64 {
    crate::time::uptime_ms()
}

/// alarm(secs) -> seconds that were left on the previous alarm
pub fn alarm(p: &Arc<Process>, secs: u64) -> i64 {
    let mut g = p.foreign.lock();
    let n = now();
    let left = if g.sig.itimer.0 > n { (g.sig.itimer.0 - n + 999) / 1000 } else { 0 };
    g.sig.itimer = if secs == 0 { (0, 0) } else { (n + secs * 1000, 0) };
    left as i64
}

fn tv_ms(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap()).saturating_mul(1000) + u64::from_le_bytes(b[8..16].try_into().unwrap()) / 1000
}
fn put_tv(b: &mut [u8], ms: u64) {
    b[..8].copy_from_slice(&(ms / 1000).to_le_bytes());
    b[8..16].copy_from_slice(&((ms % 1000) * 1000).to_le_bytes());
}

/// setitimer(which, new*, old*) / getitimer: ITIMER_REAL only (virtual/profiling timers are not supported).
pub fn setitimer(p: &Arc<Process>, which: u64, new: u64, old: u64) -> i64 {
    if which != 0 {
        return -22;
    }
    let (dl, iv) = p.foreign.lock().sig.itimer;
    if old != 0 {
        let mut b = [0u8; 32];
        put_tv(&mut b[0..16], iv);
        put_tv(&mut b[16..32], dl.saturating_sub(now()));
        if copy_to_user(p, old, &b).is_err() {
            return -14;
        }
    }
    if new != 0 {
        let mut b = [0u8; 32];
        if copy_from_user(p, &mut b, new).is_err() {
            return -14;
        }
        let (interval, value) = (tv_ms(&b[0..16]), tv_ms(&b[16..32]));
        p.foreign.lock().sig.itimer = if value == 0 { (0, 0) } else { (now() + value, interval) };
    }
    0
}
pub fn getitimer(p: &Arc<Process>, which: u64, cur: u64) -> i64 {
    if which != 0 {
        return -22;
    }
    setitimer(p, 0, 0, cur)
}

fn ts_ms(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap()).saturating_mul(1000) + u64::from_le_bytes(b[8..16].try_into().unwrap()) / 1_000_000
}
fn put_ts(b: &mut [u8], ms: u64) {
    b[..8].copy_from_slice(&(ms / 1000).to_le_bytes());
    b[8..16].copy_from_slice(&((ms % 1000) * 1_000_000).to_le_bytes());
}

/// timer_create(clockid, sevp*, timerid*): SIGEV_SIGNAL / SIGEV_THREAD_ID deliver a signal; SIGEV_NONE only counts down.
pub fn timer_create(p: &Arc<Process>, _clock: u64, sevp: u64, out: u64) -> i64 {
    let (mut signo, mut notify) = (SIGALRM as u8, true);
    if sevp != 0 {
        let mut b = [0u8; 64];
        if copy_from_user(p, &mut b, sevp).is_err() {
            return -14;
        }
        let s = i32::from_le_bytes(b[8..12].try_into().unwrap());
        let n = i32::from_le_bytes(b[12..16].try_into().unwrap());
        if n == 1 {
            notify = false; // SIGEV_NONE
        } else if n == 2 {
            return -22; // SIGEV_THREAD is done by libc with a helper thread + SIGEV_THREAD_ID; plain SIGEV_THREAD is not supported
        }
        if s < 1 || s > 64 {
            return -22;
        }
        signo = s as u8;
    }
    let id = {
        let mut g = p.foreign.lock();
        if g.sig.timers.len() >= 32 {
            return -11;
        }
        let id = g.sig.next_timer;
        g.sig.next_timer += 1;
        g.sig.timers.push(PosixTimer { id, signo, value: 0, interval: 0, deadline: 0, notify });
        id
    };
    match copy_to_user(p, out, &id.to_le_bytes()) {
        Ok(()) => 0,
        Err(_) => -14,
    }
}

/// timer_settime(id, flags, new*, old*): flags bit 0 = absolute time.
pub fn timer_settime(p: &Arc<Process>, id: u64, flags: u64, new: u64, old: u64) -> i64 {
    let mut b = [0u8; 32];
    if copy_from_user(p, &mut b, new).is_err() {
        return -14;
    }
    let (interval, value) = (ts_ms(&b[0..16]), ts_ms(&b[16..32]));
    let mut o = [0u8; 32];
    {
        let mut g = p.foreign.lock();
        let Some(t) = g.sig.timers.iter_mut().find(|t| t.id as u64 == id) else { return -22 };
        put_ts(&mut o[0..16], t.interval);
        put_ts(&mut o[16..32], t.deadline.saturating_sub(now()));
        let rel = if flags & 1 != 0 {
            // absolute: against CLOCK_REALTIME; if that is already past, fire now
            let rt = crate::time::unix_ms();
            value.saturating_sub(rt)
        } else {
            value
        };
        t.value = value;
        t.interval = interval;
        t.deadline = if value == 0 { 0 } else { now() + rel.max(1) };
    }
    if old != 0 && copy_to_user(p, old, &o).is_err() {
        return -14;
    }
    0
}

pub fn timer_gettime(p: &Arc<Process>, id: u64, cur: u64) -> i64 {
    let mut o = [0u8; 32];
    {
        let g = p.foreign.lock();
        let Some(t) = g.sig.timers.iter().find(|t| t.id as u64 == id) else { return -22 };
        put_ts(&mut o[0..16], t.interval);
        put_ts(&mut o[16..32], t.deadline.saturating_sub(now()));
    }
    match copy_to_user(p, cur, &o) {
        Ok(()) => 0,
        Err(_) => -14,
    }
}

pub fn timer_delete(p: &Arc<Process>, id: u64) -> i64 {
    let mut g = p.foreign.lock();
    let before = g.sig.timers.len();
    g.sig.timers.retain(|t| t.id as u64 != id);
    if g.sig.timers.len() == before { -22 } else { 0 }
}

/// Kernel thread: every few milliseconds, fire the timers whose deadline passed.
pub fn timer_thread() {
    loop {
        task::sleep_ms(3);
        let procs: Vec<Arc<Process>> = task::PROCS.lock().iter().filter_map(|w| w.upgrade()).collect();
        let n = now();
        for p in procs {
            if p.has_exited() {
                continue;
            }
            let mut fire: Vec<u64> = Vec::new();
            {
                let mut g = p.foreign.lock();
                let (dl, iv) = g.sig.itimer;
                if dl != 0 && dl <= n {
                    fire.push(SIGALRM);
                    g.sig.itimer = if iv == 0 { (0, 0) } else { (n + iv, iv) };
                }
                for t in g.sig.timers.iter_mut() {
                    if t.deadline != 0 && t.deadline <= n {
                        if t.notify {
                            fire.push(t.signo as u64);
                        }
                        t.deadline = if t.interval == 0 { 0 } else { n + t.interval };
                    }
                }
            }
            for s in fire {
                send(&p, s);
            }
        }
    }
}
