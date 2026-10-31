//! Preemptive round-robin scheduler (single CPU).
//!
//! * Timer tick (1 kHz) -> `on_tick` -> wake sleepers, burn quantum, `schedule`.
//! * All kernel code runs with interrupts off except idle and user mode, so a
//!   thread is only ever preempted in user mode or in the idle loop; kernel
//!   threads yield/sleep/exit voluntarily or are preempted at the timer
//!   interrupt they are running (IF=1 in thread bodies).

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use x86_64::instructions::interrupts;
use x86_64::registers::control::{Cr3, Cr3Flags};

use super::{Thread, BLOCKED, DEAD, READY, RUNNING, SLEEPING};
use crate::arch::x86_64::context::{fx_restore, fx_save, switch_context};
use crate::arch::x86_64::{gdt, syscall};
use crate::sync::IrqMutex;
use crate::time;

pub const QUANTUM_TICKS: u32 = 10; // 10 ms at 1 kHz

struct Sched {
    ready: VecDeque<Arc<Thread>>,
    sleeping: Vec<Arc<Thread>>,
    dead: Vec<Arc<Thread>>,
    futex: Vec<(u64, Arc<Thread>)>,
    current: Option<Arc<Thread>>,
    idle: Option<Arc<Thread>>,
    quantum: u32,
    switches: u64,
}

static SCHED: IrqMutex<Sched> = IrqMutex::new(Sched {
    ready: VecDeque::new(),
    sleeping: Vec::new(),
    dead: Vec::new(),
    futex: Vec::new(),
    current: None,
    idle: None,
    quantum: QUANTUM_TICKS,
    switches: 0,
});

pub(super) fn install_idle(idle: Arc<Thread>) {
    let mut s = SCHED.lock();
    s.current = Some(idle.clone());
    s.idle = Some(idle);
}

pub(super) fn enqueue(t: Arc<Thread>) {
    t.set_state(READY);
    SCHED.lock().ready.push_back(t);
}

pub fn try_current() -> Option<Arc<Thread>> {
    SCHED.lock().current.clone()
}

pub fn current() -> Arc<Thread> {
    SCHED.lock().current.clone().expect("scheduler not initialised")
}

pub fn context_switches() -> u64 {
    SCHED.lock().switches
}

/// First code run by every new thread (entered via `switch_context`'s `ret`).
pub(super) extern "C" fn thread_start() -> ! {
    interrupts::enable(); // schedule() switched with IF=0
    let entry = current().take_entry();
    if let Some(f) = entry {
        f();
    }
    exit_current()
}

/// Pick the next thread and switch to it. Returns when this thread is resumed.
pub fn schedule() {
    let were_enabled = interrupts::are_enabled();
    interrupts::disable();

    // Decide under the lock; drop every Arc before switching so a thread that
    // never resumes (dead) cannot leak references on its stack.
    let plan = {
        let mut s = SCHED.lock();
        let prev = s.current.clone().expect("no current thread");
        if prev.state() == RUNNING {
            prev.set_state(READY);
            if !prev.is_idle {
                s.ready.push_back(prev.clone());
            }
        }
        let next = match s.ready.pop_front() {
            Some(t) => t,
            None => s.idle.clone().unwrap(),
        };
        s.quantum = QUANTUM_TICKS;
        if Arc::ptr_eq(&prev, &next) {
            prev.set_state(RUNNING);
            None
        } else {
            next.set_state(RUNNING);
            s.current = Some(next.clone());
            s.switches += 1;
            // SAFETY (reads): `next` is not running, so nobody else touches its saved RSP.
            let next_rsp = unsafe { *next.saved_rsp.get() };
            Some((
                prev.saved_rsp.get(),
                next_rsp,
                unsafe { &mut **prev.fpu.get() as *mut _ },
                unsafe { &**next.fpu.get() as *const _ },
                next.kstack_top,
                next.process.cr3,
                next.fs_base.load(Ordering::Relaxed),
                next.gs_base.load(Ordering::Relaxed),
            ))
        }
    };

    if let Some((prev_rsp, next_rsp, prev_fpu, next_fpu, ktop, cr3, fs, gs)) = plan {
        set_user_segment_bases(fs, gs);
        gdt::set_kernel_stack(ktop);
        syscall::set_kernel_rsp(ktop);
        if Cr3::read().0 != cr3 {
            // SAFETY: every address space shares the kernel half, so code, this
            // stack and the heap stay mapped across the switch.
            unsafe { Cr3::write(cr3, Cr3Flags::empty()) };
        }
        // SAFETY: interrupts are off; both Thread objects stay alive (they sit in
        // scheduler lists) and `next_rsp` is a valid saved/prepared context.
        unsafe {
            fx_save(prev_fpu);
            fx_restore(next_fpu);
            switch_context(prev_rsp, next_rsp);
        }
    }

    if were_enabled {
        interrupts::enable();
    }
}

pub fn yield_now() {
    schedule();
}

/// Timer-interrupt hook (IF=0).
pub fn on_tick() {
    let now = time::ticks();
    let need_switch = {
        let mut s = SCHED.lock();
        let mut i = 0;
        while i < s.sleeping.len() {
            if s.sleeping[i].wake_at.load(Ordering::SeqCst) <= now {
                let t = s.sleeping.remove(i);
                t.set_state(READY);
                s.ready.push_back(t);
            } else {
                i += 1;
            }
        }
        s.quantum = s.quantum.saturating_sub(1);
        let idle_running = s.current.as_ref().map_or(false, |c| c.is_idle);
        if s.ready.is_empty() {
            if s.quantum == 0 {
                s.quantum = QUANTUM_TICKS;
            }
            false
        } else {
            s.quantum == 0 || idle_running
        }
    };
    if need_switch {
        schedule();
    }
}

pub fn sleep_ms(ms: u64) {
    let were = interrupts::are_enabled();
    interrupts::disable();
    {
        let mut s = SCHED.lock();
        let cur = s.current.clone().unwrap();
        cur.wake_at.store(time::ticks() + time::ms_to_ticks(ms).max(1), Ordering::SeqCst);
        cur.set_state(SLEEPING);
        s.sleeping.push(cur);
    }
    schedule();
    if were {
        interrupts::enable();
    }
}

/// Mark `t` dead and account for it in its process. Caller holds the scheduler lock.
fn retire(s: &mut Sched, t: Arc<Thread>) {
    t.set_state(DEAD);
    let p = &t.process;
    if p.live_threads.fetch_sub(1, Ordering::SeqCst) == 1 {
        p.exited.store(true, Ordering::SeqCst);
        // SIGCHLD to the parent right away (not only when the thread is reaped), so a handler that runs after the parent's
        // wait4 returns has already been queued. try_lock: we hold the scheduler lock; the reap path is the fallback.
        let parent = p.foreign.try_lock().and_then(|mut g| {
            if g.chld_sent { None } else { g.chld_sent = true; g.parent.as_ref().and_then(|w| w.upgrade()) }
        });
        if let Some(par) = parent {
            crate::abi::signals::raise_try(&par, crate::abi::signals::SIGCHLD);
        }
    }
    s.dead.push(t);
}

/// Terminate the calling thread. Never returns.
pub fn exit_current() -> ! {
    interrupts::disable();
    {
        let mut s = SCHED.lock();
        let cur = s.current.clone().unwrap();
        retire(&mut s, cur);
    }
    schedule();
    unreachable!("dead thread was rescheduled");
}

/// Kill every thread of the current process (including the caller). Never returns.
pub fn kill_current_process(code: i64) -> ! {
    interrupts::disable();
    {
        let (pid, tid) = {
            let s = SCHED.lock();
            let c = s.current.as_ref().unwrap();
            (c.process.pid, c.tid)
        };
        let _ = tid;
        crate::audit_log!(crate::audit::EV_PROC_EXIT, 0, 0, pid, code, code);
    }
    {
        let mut s = SCHED.lock();
        let cur = s.current.clone().unwrap();
        let pid = cur.process.pid;
        cur.process.set_exit_code(code);

        let mut victims: Vec<Arc<Thread>> = Vec::new();
        let mut i = 0;
        while i < s.ready.len() {
            if s.ready[i].process.pid == pid {
                victims.push(s.ready.remove(i).unwrap());
            } else {
                i += 1;
            }
        }
        let mut i = 0;
        while i < s.sleeping.len() {
            if s.sleeping[i].process.pid == pid {
                victims.push(s.sleeping.remove(i));
            } else {
                i += 1;
            }
        }
        let mut i = 0;
        while i < s.futex.len() {
            if s.futex[i].1.process.pid == pid {
                victims.push(s.futex.remove(i).1);
            } else {
                i += 1;
            }
        }
        for v in victims {
            retire(&mut s, v);
        }
        retire(&mut s, cur);
    }
    schedule();
    unreachable!("killed thread was rescheduled");
}

/// Terminate another process (all its threads). Returns false if it already exited.
pub fn kill_process(target: &Arc<crate::task::Process>, code: i64) -> bool {
    if target.has_exited() {
        return false;
    }
    let were = interrupts::are_enabled();
    interrupts::disable();
    let cur_pid = SCHED.lock().current.as_ref().map(|c| c.process.pid);
    if cur_pid == Some(target.pid) {
        kill_current_process(code);
    }
    {
        let mut s = SCHED.lock();
        target.set_exit_code(code);
        let pid = target.pid;
        let mut victims: Vec<Arc<Thread>> = Vec::new();
        let mut i = 0;
        while i < s.ready.len() {
            if s.ready[i].process.pid == pid {
                victims.push(s.ready.remove(i).unwrap());
            } else {
                i += 1;
            }
        }
        let mut i = 0;
        while i < s.sleeping.len() {
            if s.sleeping[i].process.pid == pid {
                victims.push(s.sleeping.remove(i));
            } else {
                i += 1;
            }
        }
        let mut i = 0;
        while i < s.futex.len() {
            if s.futex[i].1.process.pid == pid {
                victims.push(s.futex.remove(i).1);
            } else {
                i += 1;
            }
        }
        for v in victims {
            retire(&mut s, v);
        }
    }
    crate::audit_log!(crate::audit::EV_PROC_EXIT, 0, 0, target.pid, code, code);
    if were {
        interrupts::enable();
    }
    true
}

/// Exit only the calling thread; if it was the last one the process ends.
pub fn exit_thread() -> ! {
    exit_current()
}

/// Free the resources of dead threads (kernel stacks, and via Drop, processes).
/// Must run on a thread other than the dead ones - the idle loop calls it.
pub fn reap() {
    let dead: Vec<Arc<Thread>> = {
        let mut s = SCHED.lock();
        core::mem::take(&mut s.dead)
    };
    for t in &dead {
        if t.process.has_exited() {
            t.process.release_resources();
            // tell the parent (once): SIGCHLD
            let parent = {
                let mut g = t.process.foreign.lock();
                if g.chld_sent { None } else { g.chld_sent = true; g.parent.as_ref().and_then(|w| w.upgrade()) }
            };
            if let Some(par) = parent {
                crate::abi::signals::raise(&par, crate::abi::signals::SIGCHLD);
            }
        }
    }
    drop(dead);
}

/// `exit(code)` syscall: end the whole process.
pub fn exit_process(code: i64) -> ! {
    kill_current_process(code)
}

/// Block the calling thread on futex `key` (physical address of the futex word).
/// The caller must have verified the wait condition with interrupts disabled.
pub fn futex_block(key: u64) {
    let were = interrupts::are_enabled();
    interrupts::disable();
    {
        let mut s = SCHED.lock();
        let cur = s.current.clone().unwrap();
        cur.set_state(BLOCKED);
        s.futex.push((key, cur));
    }
    schedule();
    if were {
        interrupts::enable();
    }
}

/// Wake up to `n` threads blocked on `key`; returns how many were woken.
pub fn futex_wake(key: u64, n: usize) -> usize {
    let mut s = SCHED.lock();
    let mut woken = 0;
    let mut i = 0;
    while i < s.futex.len() && woken < n {
        if s.futex[i].0 == key {
            let (_, t) = s.futex.remove(i);
            t.set_state(READY);
            s.ready.push_back(t);
            woken += 1;
        } else {
            i += 1;
        }
    }
    woken
}

/// Wake one thread (by tid) if it is blocked on a futex (thread-directed signal).
pub fn futex_interrupt_tid(tid: u64) -> bool {
    let mut s = SCHED.lock();
    if let Some(i) = s.futex.iter().position(|(_, t)| t.tid == tid) {
        let (_, t) = s.futex.remove(i);
        t.set_state(READY);
        s.ready.push_back(t);
        return true;
    }
    false
}

/// A signal became deliverable for process `pid`: make its futex waiters runnable so they notice it (the woken syscall
/// sees `signals::interrupted` and returns EINTR/ERESTART; a woken waiter that finds no signal just returns 0, which
/// FUTEX_WAIT allows as a spurious wake-up). Returns how many threads were woken.
pub fn futex_interrupt(pid: u64) -> usize {
    let mut s = SCHED.lock();
    let mut woken = 0;
    let mut i = 0;
    while i < s.futex.len() {
        if s.futex[i].1.process.pid == pid {
            let (_, t) = s.futex.remove(i);
            t.set_state(READY);
            s.ready.push_back(t);
            woken += 1;
        } else {
            i += 1;
        }
    }
    woken
}

static CUR_FS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static CUR_GS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Load the incoming thread's FS/GS base MSRs (only when they change). The kernel itself
/// never uses FS/GS, so these MSRs belong to user space entirely.
fn set_user_segment_bases(fs: u64, gs: u64) {
    use x86_64::registers::model_specific::{FsBase, GsBase};
    use x86_64::VirtAddr;
    if CUR_FS.swap(fs, Ordering::Relaxed) != fs {
        FsBase::write(VirtAddr::new_truncate(fs));
    }
    if CUR_GS.swap(gs, Ordering::Relaxed) != gs {
        GsBase::write(VirtAddr::new_truncate(gs));
    }
}

/// Set the calling thread's FS base (Linux `arch_prctl(ARCH_SET_FS)`).
pub fn set_current_fs_base(v: u64) {
    let cur = current();
    cur.fs_base.store(v, Ordering::Relaxed);
    set_user_segment_bases(v, cur.gs_base.load(Ordering::Relaxed));
}

/// FS/GS base of the running thread (what a forked child inherits).
pub fn current_tls_bases() -> (u64, u64) {
    let s = SCHED.lock();
    match s.current.as_ref() {
        Some(t) => (t.fs_base.load(core::sync::atomic::Ordering::SeqCst), t.gs_base.load(core::sync::atomic::Ordering::SeqCst)),
        None => (0, 0),
    }
}

/// Set the running thread's FS/GS base (execve resets TLS) and program the MSRs now.
pub fn set_current_tls_bases(fs: u64, gs: u64) {
    {
        let s = SCHED.lock();
        if let Some(t) = s.current.as_ref() {
            t.fs_base.store(fs, core::sync::atomic::Ordering::SeqCst);
            t.gs_base.store(gs, core::sync::atomic::Ordering::SeqCst);
        }
    }
    set_user_segment_bases(fs, gs); // goes through the CUR_FS/CUR_GS cache so the next switch restores correctly
}
