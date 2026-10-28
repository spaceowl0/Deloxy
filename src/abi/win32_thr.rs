//! Windows threads and synchronization for PE programs: CreateThread / _beginthreadex, events, mutexes,
//! semaphores, WaitForSingle/MultipleObjects, real critical sections and Interlocked* calls.
//!
//! Kernel objects live in `ForeignState.kobjs`; their handles are `0x2000 + 4 * index`. Syscalls run with
//! interrupts disabled on a single CPU, so every operation here is atomic with respect to other threads.
//! Blocking waits poll with 1 ms sleeps (simple and correct; not optimal for many waiters).

use alloc::sync::Arc;

use super::nt::{set_err, DATA_PAGE3, NT_DATA_BASE};
use super::KObj;
use crate::mm::layout::PAGE_SIZE;
use crate::sys::uaccess::{copy_from_user, copy_to_user};
use crate::task::{self, Process};

type A = [u64; 4];
const WAIT_OBJECT_0: u64 = 0;
const WAIT_TIMEOUT: u64 = 0x102;
const WAIT_FAILED: u64 = 0xFFFF_FFFF;
const INFINITE: u32 = 0xFFFF_FFFF;
const THREAD_STACK_PAGES: usize = 256; // 1 MiB

fn stack_arg(p: &Arc<Process>, k: usize) -> u64 {
    let rsp = p.foreign.lock().nt_rsp;
    let mut b = [0u8; 8];
    let _ = copy_from_user(p, &mut b, rsp + super::msvcrt::STACK_ARG0 + 8 * (k as u64 - 4));
    u64::from_le_bytes(b)
}
fn me() -> u64 {
    task::current_ids().1
}
fn obj_slot(h: u64) -> Option<usize> {
    if h >= 0x2000 && h < 0x100000 && h % 4 == 0 { Some(((h - 0x2000) / 4) as usize) } else { None }
}
fn new_obj(p: &Arc<Process>, o: KObj) -> u64 {
    let mut f = p.foreign.lock();
    let i = match f.kobjs.iter().position(|s| s.is_none()) {
        Some(i) => {
            f.kobjs[i] = Some(o);
            i
        }
        None => {
            f.kobjs.push(Some(o));
            f.kobjs.len() - 1
        }
    };
    0x2000 + i as u64 * 4
}

/// Try to satisfy a wait on `h` now (acquiring it when that has side effects). `None` = invalid handle.
fn try_acquire(p: &Arc<Process>, h: u64) -> Option<bool> {
    let i = obj_slot(h)?;
    let mut f = p.foreign.lock();
    Some(match f.kobjs.get_mut(i)?.as_mut()? {
        KObj::Thread { done, .. } => *done,
        KObj::Event { manual, set } => {
            if *set {
                if !*manual {
                    *set = false;
                }
                true
            } else {
                false
            }
        }
        KObj::Mutex { owner, count } => {
            if *owner == 0 || *owner == me() {
                *owner = me();
                *count += 1;
                true
            } else {
                false
            }
        }
        KObj::Sem { count, .. } => {
            if *count > 0 {
                *count -= 1;
                true
            } else {
                false
            }
        }
    })
}

fn signaled(p: &Arc<Process>, h: u64) -> Option<bool> {
    let i = obj_slot(h)?;
    let f = p.foreign.lock();
    Some(match f.kobjs.get(i)?.as_ref()? {
        KObj::Thread { done, .. } => *done,
        KObj::Event { set, .. } => *set,
        KObj::Mutex { owner, .. } => *owner == 0 || *owner == me(),
        KObj::Sem { count, .. } => *count > 0,
    })
}

pub fn wait_single(p: &Arc<Process>, a: A) -> u64 {
    let ms = a[1] as u32;
    let t0 = crate::time::uptime_ms();
    loop {
        match try_acquire(p, a[0]) {
            None => {
                // pseudo handles / std handles: nothing to wait for; never signalled
                if ms == INFINITE {
                    task::sleep_ms(1);
                    continue;
                }
                set_err(p, 6);
                return WAIT_FAILED;
            }
            Some(true) => return WAIT_OBJECT_0,
            Some(false) => {}
        }
        if ms != INFINITE && crate::time::uptime_ms().saturating_sub(t0) >= ms as u64 {
            return WAIT_TIMEOUT;
        }
        task::sleep_ms(1);
    }
}

pub fn wait_multiple(p: &Arc<Process>, a: A) -> u64 {
    let n = (a[0] as usize).min(64);
    let wait_all = a[2] != 0;
    let ms = a[3] as u32; // 4th argument (r9)
    let mut hs = alloc::vec::Vec::new();
    for i in 0..n {
        let mut b = [0u8; 8];
        if copy_from_user(p, &mut b, a[1] + i as u64 * 8).is_err() {
            return WAIT_FAILED;
        }
        hs.push(u64::from_le_bytes(b));
    }
    let t0 = crate::time::uptime_ms();
    loop {
        if wait_all {
            if hs.iter().all(|h| signaled(p, *h) == Some(true)) {
                for h in &hs {
                    try_acquire(p, *h);
                }
                return WAIT_OBJECT_0;
            }
        } else {
            for (i, h) in hs.iter().enumerate() {
                if try_acquire(p, *h) == Some(true) {
                    return WAIT_OBJECT_0 + i as u64;
                }
            }
        }
        if ms != INFINITE && crate::time::uptime_ms().saturating_sub(t0) >= ms as u64 {
            return WAIT_TIMEOUT;
        }
        task::sleep_ms(1);
    }
}

pub fn create_event(p: &Arc<Process>, a: A) -> u64 {
    new_obj(p, KObj::Event { manual: a[1] != 0, set: a[2] != 0 })
}
pub fn set_event(p: &Arc<Process>, a: A) -> u64 {
    set_ev(p, a[0], true)
}
pub fn reset_event(p: &Arc<Process>, a: A) -> u64 {
    set_ev(p, a[0], false)
}
fn set_ev(p: &Arc<Process>, h: u64, v: bool) -> u64 {
    let Some(i) = obj_slot(h) else { return 0 };
    let mut f = p.foreign.lock();
    if let Some(Some(KObj::Event { set, .. })) = f.kobjs.get_mut(i) {
        *set = v;
        1
    } else {
        0
    }
}
pub fn create_mutex(p: &Arc<Process>, a: A) -> u64 {
    let init = a[1] != 0;
    new_obj(p, KObj::Mutex { owner: if init { me() } else { 0 }, count: init as u32 })
}
pub fn release_mutex(p: &Arc<Process>, a: A) -> u64 {
    let Some(i) = obj_slot(a[0]) else { return 0 };
    let mut f = p.foreign.lock();
    if let Some(Some(KObj::Mutex { owner, count })) = f.kobjs.get_mut(i) {
        if *owner == me() && *count > 0 {
            *count -= 1;
            if *count == 0 {
                *owner = 0;
            }
            return 1;
        }
    }
    drop(f);
    set_err(p, 288); // ERROR_NOT_OWNER
    0
}
pub fn create_semaphore(p: &Arc<Process>, a: A) -> u64 {
    new_obj(p, KObj::Sem { count: a[1] as i32, max: (a[2] as i32).max(1) })
}
pub fn release_semaphore(p: &Arc<Process>, a: A) -> u64 {
    let Some(i) = obj_slot(a[0]) else { return 0 };
    let mut f = p.foreign.lock();
    if let Some(Some(KObj::Sem { count, max })) = f.kobjs.get_mut(i) {
        let prev = *count;
        if prev as i64 + a[1] as i32 as i64 > *max as i64 {
            return 0;
        }
        *count += a[1] as i32;
        drop(f);
        if a[2] != 0 {
            let _ = copy_to_user(p, a[2], &prev.to_le_bytes());
        }
        return 1;
    }
    0
}

pub fn close_obj(p: &Arc<Process>, h: u64) -> Option<u64> {
    let i = obj_slot(h)?;
    let mut f = p.foreign.lock();
    match f.kobjs.get_mut(i) {
        Some(s) if s.is_some() => {
            *s = None;
            Some(1)
        }
        _ => Some(0),
    }
}

pub fn get_exit_code_thread(p: &Arc<Process>, a: A) -> u64 {
    let Some(i) = obj_slot(a[0]) else { return 0 };
    let f = p.foreign.lock();
    if let Some(Some(KObj::Thread { done, code, .. })) = f.kobjs.get(i) {
        let c: u32 = if *done { *code } else { 259 }; // STILL_ACTIVE
        drop(f);
        let _ = copy_to_user(p, a[1], &c.to_le_bytes());
        return 1;
    }
    0
}

/// CreateThread / _beginthreadex: (attr, stack size, start, parameter, flags, *thread id)
pub fn create_thread(p: &Arc<Process>, a: A) -> u64 {
    let (start, param) = (a[2], a[3]);
    let tidptr = stack_arg(p, 5);
    if p.foreign.lock().nthreads >= 32 {
        set_err(p, 8);
        return 0;
    }
    let oom = |_| ();
    // stack (1 MiB) + one page for the TEB/TLS array, taken from the mmap area
    let total = THREAD_STACK_PAGES + 2;
    let base = p.mmap_next.fetch_add((total as u64 + 1) * PAGE_SIZE, core::sync::atomic::Ordering::SeqCst);
    if p.map_region(base, total, crate::mm::vmm::VmFlags::WRITE | crate::mm::vmm::VmFlags::USER).map_err(oom).is_err() {
        set_err(p, 8);
        return 0;
    }
    let teb = base;
    let stack_limit = base + 2 * PAGE_SIZE;
    let stack_top = base + total as u64 * PAGE_SIZE;
    let sp = stack_top - 64; // 16-aligned; [sp] = start, [sp+8] = param
    let w64 = |off: u64, v: u64| super::super::exec::write_user(p, off, &v.to_le_bytes());
    let peb = NT_DATA_BASE + PAGE_SIZE;
    let tmpl = p.foreign.lock().tls_tmpl;
    let _ = w64(teb + 0x08, stack_top);
    let _ = w64(teb + 0x10, stack_limit);
    let _ = w64(teb + 0x30, teb);
    let _ = w64(teb + 0x40, p.pid);
    let _ = w64(teb + 0x60, peb);
    if let Some((start_va, end_va, zero, _)) = tmpl {
        let len = (end_va - start_va) as usize;
        let pages = (((len + zero as usize) as u64 + PAGE_SIZE - 1) / PAGE_SIZE).max(1) as usize;
        let va = p.mmap_next.fetch_add((pages as u64 + 1) * PAGE_SIZE, core::sync::atomic::Ordering::SeqCst);
        if p.map_region(va, pages, crate::mm::vmm::VmFlags::WRITE | crate::mm::vmm::VmFlags::USER).is_ok() {
            let mut t = alloc::vec![0u8; len];
            if copy_from_user(p, &mut t, start_va).is_ok() {
                let _ = super::super::exec::write_user(p, va, &t);
            }
            let _ = w64(teb + 0x800, va); // this thread's TLS array: [block]
            let _ = w64(teb + 0x58, teb + 0x800);
        }
    }
    let _ = w64(sp, start);
    let _ = w64(sp + 8, param);
    let stub = super::msvcrt::code_stub_addr("<thread_start>").unwrap_or(0);
    let Some(tid) = task::spawn_user_thread_ex(p, "nthread", stub, sp, 0, teb) else {
        set_err(p, 8);
        return 0;
    };
    p.foreign.lock().nthreads += 1;
    let h = new_obj(p, KObj::Thread { tid, done: false, code: 0 });
    if tidptr != 0 {
        let _ = copy_to_user(p, tidptr, &(tid as u32).to_le_bytes());
    }
    h
}

/// _beginthread(start, stack, arg): the start routine returns void and the handle is closed by the runtime.
pub fn beginthread(p: &Arc<Process>, a: A) -> u64 {
    // build the same call as CreateThread(NULL, stack, start, arg, 0, NULL); stack args 5/6 read as 0
    let rsp = p.foreign.lock().nt_rsp;
    let _ = rsp;
    create_thread(p, [0, a[1], a[0], a[2]])
}

pub fn exit_thread(p: &Arc<Process>, a: A) -> u64 {
    let tid = me();
    let last = {
        let mut f = p.foreign.lock();
        for o in f.kobjs.iter_mut().flatten() {
            if let KObj::Thread { tid: t, done, code } = o {
                if *t == tid {
                    *done = true;
                    *code = a[0] as u32;
                }
            }
        }
        f.nthreads = f.nthreads.saturating_sub(1);
        f.nthreads == 0
    };
    if last {
        super::vfs::flush_all(p);
        task::sched::exit_process(a[0] as u32 as i64);
    }
    task::sched::exit_thread()
}

pub fn switch_to_thread(_: &Arc<Process>, _: A) -> u64 {
    task::yield_now();
    1
}
pub fn get_current_thread(_: &Arc<Process>, _: A) -> u64 {
    u64::MAX - 1 // pseudo handle (-2)
}

// ---- critical sections: CRITICAL_SECTION { debug, LockCount i32 @8, RecursionCount i32 @12, OwningThread @16 } ----
fn rd32(p: &Arc<Process>, va: u64) -> i32 {
    let mut b = [0u8; 4];
    let _ = copy_from_user(p, &mut b, va);
    i32::from_le_bytes(b)
}
fn rd64(p: &Arc<Process>, va: u64) -> u64 {
    let mut b = [0u8; 8];
    let _ = copy_from_user(p, &mut b, va);
    u64::from_le_bytes(b)
}
pub fn cs_init(p: &Arc<Process>, a: A) -> u64 {
    let _ = copy_to_user(p, a[0], &[0u8; 40]);
    1
}
pub fn cs_try_enter(p: &Arc<Process>, a: A) -> u64 {
    let owner = rd64(p, a[0] + 16);
    if owner == 0 || owner == me() {
        let rec = rd32(p, a[0] + 12);
        let _ = copy_to_user(p, a[0] + 16, &me().to_le_bytes());
        let _ = copy_to_user(p, a[0] + 12, &(rec + 1).to_le_bytes());
        1
    } else {
        0
    }
}
pub fn cs_enter(p: &Arc<Process>, a: A) -> u64 {
    while cs_try_enter(p, a) == 0 {
        task::sleep_ms(1);
    }
    0
}
pub fn cs_leave(p: &Arc<Process>, a: A) -> u64 {
    let rec = rd32(p, a[0] + 12) - 1;
    if rec <= 0 {
        let _ = copy_to_user(p, a[0] + 12, &0i32.to_le_bytes());
        let _ = copy_to_user(p, a[0] + 16, &0u64.to_le_bytes());
    } else {
        let _ = copy_to_user(p, a[0] + 12, &rec.to_le_bytes());
    }
    0
}

// ---- Interlocked*: 32-bit (Long) and 64-bit variants ----
pub fn il_inc(p: &Arc<Process>, a: A) -> u64 {
    let v = rd32(p, a[0]).wrapping_add(1);
    let _ = copy_to_user(p, a[0], &v.to_le_bytes());
    v as u32 as u64
}
pub fn il_dec(p: &Arc<Process>, a: A) -> u64 {
    let v = rd32(p, a[0]).wrapping_sub(1);
    let _ = copy_to_user(p, a[0], &v.to_le_bytes());
    v as u32 as u64
}
pub fn il_xchg(p: &Arc<Process>, a: A) -> u64 {
    let old = rd32(p, a[0]);
    let _ = copy_to_user(p, a[0], &(a[1] as u32).to_le_bytes());
    old as u32 as u64
}
pub fn il_xadd(p: &Arc<Process>, a: A) -> u64 {
    let old = rd32(p, a[0]);
    let _ = copy_to_user(p, a[0], &old.wrapping_add(a[1] as u32 as i32).to_le_bytes());
    old as u32 as u64
}
pub fn il_cmpxchg(p: &Arc<Process>, a: A) -> u64 {
    // (dest, exchange, comparand)
    let old = rd32(p, a[0]);
    if old == a[2] as u32 as i32 {
        let _ = copy_to_user(p, a[0], &(a[1] as u32).to_le_bytes());
    }
    old as u32 as u64
}
pub fn il_inc64(p: &Arc<Process>, a: A) -> u64 {
    let v = rd64(p, a[0]).wrapping_add(1);
    let _ = copy_to_user(p, a[0], &v.to_le_bytes());
    v
}
pub fn il_cmpxchg64(p: &Arc<Process>, a: A) -> u64 {
    let old = rd64(p, a[0]);
    if old == a[2] {
        let _ = copy_to_user(p, a[0], &a[1].to_le_bytes());
    }
    old
}

// Compile-time reminders of the layout assumptions made above.
const _: () = assert!(DATA_PAGE3 > NT_DATA_BASE);

// ---- SRW locks (one pointer-sized word: 0 free, MAX exclusive, n shared readers) and condition variables ----
pub fn srw_init(p: &Arc<Process>, a: A) -> u64 {
    let _ = copy_to_user(p, a[0], &0u64.to_le_bytes());
    0
}
pub fn srw_try_excl(p: &Arc<Process>, a: A) -> u64 {
    if rd64(p, a[0]) == 0 {
        let _ = copy_to_user(p, a[0], &u64::MAX.to_le_bytes());
        1
    } else {
        0
    }
}
pub fn srw_acq_excl(p: &Arc<Process>, a: A) -> u64 {
    while srw_try_excl(p, a) == 0 {
        task::sleep_ms(1);
    }
    0
}
pub fn srw_rel_excl(p: &Arc<Process>, a: A) -> u64 {
    let _ = copy_to_user(p, a[0], &0u64.to_le_bytes());
    0
}
pub fn srw_try_shared(p: &Arc<Process>, a: A) -> u64 {
    let v = rd64(p, a[0]);
    if v != u64::MAX {
        let _ = copy_to_user(p, a[0], &(v + 1).to_le_bytes());
        1
    } else {
        0
    }
}
pub fn srw_acq_shared(p: &Arc<Process>, a: A) -> u64 {
    while srw_try_shared(p, a) == 0 {
        task::sleep_ms(1);
    }
    0
}
pub fn srw_rel_shared(p: &Arc<Process>, a: A) -> u64 {
    let v = rd64(p, a[0]);
    let _ = copy_to_user(p, a[0], &v.saturating_sub(1).to_le_bytes());
    0
}

/// SleepConditionVariable{CS,SRW}: release the lock, wait for the variable's generation to change (or the
/// timeout), re-acquire. Wakeups may be spurious, as the API allows.
fn cv_wait(p: &Arc<Process>, cv: u64, ms: u32, release: impl Fn(), acquire: impl Fn()) -> u64 {
    let gen = rd64(p, cv);
    release();
    let t0 = crate::time::uptime_ms();
    let mut ok = true;
    loop {
        if rd64(p, cv) != gen {
            break;
        }
        if ms != INFINITE && crate::time::uptime_ms().saturating_sub(t0) >= ms as u64 {
            ok = false;
            break;
        }
        task::sleep_ms(1);
    }
    acquire();
    if !ok {
        set_err(p, 1460); // ERROR_TIMEOUT
    }
    ok as u64
}
pub fn cv_sleep_cs(p: &Arc<Process>, a: A) -> u64 {
    let (cv, cs) = (a[0], a[1]);
    cv_wait(p, cv, a[2] as u32, || { cs_leave(p, [cs, 0, 0, 0]); }, || { cs_enter(p, [cs, 0, 0, 0]); })
}
pub fn cv_sleep_srw(p: &Arc<Process>, a: A) -> u64 {
    let (cv, l, shared) = (a[0], a[1], a[3] & 1 != 0);
    cv_wait(
        p,
        cv,
        a[2] as u32,
        || { if shared { srw_rel_shared(p, [l, 0, 0, 0]); } else { srw_rel_excl(p, [l, 0, 0, 0]); } },
        || { if shared { srw_acq_shared(p, [l, 0, 0, 0]); } else { srw_acq_excl(p, [l, 0, 0, 0]); } },
    )
}
pub fn cv_wake(p: &Arc<Process>, a: A) -> u64 {
    let v = rd64(p, a[0]).wrapping_add(1);
    let _ = copy_to_user(p, a[0], &v.to_le_bytes());
    0
}
