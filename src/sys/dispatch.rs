//! Syscall dispatch. ABI: number in RAX; args RDI, RSI, RDX, R10, R8, R9;
//! result in RAX (negative = -errno). Syscalls run with interrupts disabled.
//!
//! Every syscall is audited (`EV_SYSCALL`); results of EPERM/EBADF are recorded
//! as `EV_CAP_DENIED`, so denials are visible even when the caller ignores them.

use alloc::sync::Arc;

use x86_64::VirtAddr;

use super::errno::*;
use super::uaccess;
use crate::arch::x86_64::syscall::SyscallFrame;
use crate::audit::{self, AuditEvent, EV_CAP_DENIED, EV_SYSCALL};
use crate::cap::{CapObject, Rights};
use crate::mm::layout::{is_user_range, PAGE_SIZE};
use crate::mm::vmm::VmFlags;
use crate::task::{self, Process};
use crate::time;

pub const SYS_EXIT: u64 = 0;
pub const SYS_YIELD: u64 = 1;
pub const SYS_SLEEP_MS: u64 = 2;
pub const SYS_WRITE_DEBUG: u64 = 3;
pub const SYS_MMAP_ANON: u64 = 4;
pub const SYS_MUNMAP: u64 = 5;
pub const SYS_THREAD_SPAWN: u64 = 6;
pub const SYS_THREAD_EXIT: u64 = 7;
pub const SYS_TIME_NOW: u64 = 8;
pub const SYS_GETPID: u64 = 9;
pub const SYS_GETTID: u64 = 10;
pub const SYS_CAP_DROP: u64 = 11;
pub const SYS_CAP_DERIVE: u64 = 12;
pub const SYS_CAP_INFO: u64 = 13;
pub const SYS_SHM_MAP: u64 = 14;
pub const SYS_FUTEX_WAIT: u64 = 15;
pub const SYS_FUTEX_WAKE: u64 = 16;
pub const SYS_PORT_IN: u64 = 17;
pub const SYS_PORT_OUT: u64 = 18;
pub const SYS_AUDIT_READ: u64 = 19;
pub const SYS_STAT: u64 = 20;

const MAX_WRITE: usize = 512;
const MAX_MMAP: u64 = 256 * 1024 * 1024;
const MAX_AUDIT_BATCH: usize = 32;

pub extern "C" fn syscall_dispatch(f: &mut SyscallFrame) {
    use crate::abi::AbiKind;
    let abi = task::current_process().abi();
    if abi != AbiKind::Native {
        let nr = f.rax;
        let (a0, a1) = (if abi == AbiKind::Nt { f.r10 } else { f.rdi }, f.rsi);
        let ret = match abi {
            AbiKind::Linux => crate::abi::linux::syscall(f),
            _ => crate::abi::nt::syscall(f),
        };
        let tag = ((abi as u32) << 16) | (nr as u32 & 0xFFFF);
        let kind = if ret == -EPERM || ret == -EBADF { EV_CAP_DENIED } else { EV_SYSCALL };
        crate::audit_log!(kind, tag, 0, a0, a1, ret);
        f.rax = ret as u64;
        return;
    }
    let nr = f.rax;
    let (a0, a1, a2) = (f.rdi, f.rsi, f.rdx);
    // Foreign-ABI processes (Linux ELF / Windows PE) use their own numbering and conventions.
    let abi = task::current_process().abi();
    if abi != crate::abi::AbiKind::Native {
        let tag = (abi as u32) << 16;
        let ret = match abi {
            crate::abi::AbiKind::Linux => crate::abi::linux::syscall(f),
            _ => crate::abi::nt::syscall(f),
        };
        let kind = if ret == -EPERM || ret == -EBADF { EV_CAP_DENIED } else { EV_SYSCALL };
        crate::audit_log!(kind, nr as u32 | tag, 0, a0, a1, ret);
        f.rax = ret as u64;
        return;
    }
    if nr == SYS_EXIT {
        crate::audit_log!(EV_SYSCALL, nr, 0, a0, 0, 0);
    }
    let ret: i64 = match nr {
        SYS_EXIT => task::sched::exit_process(a0 as i64),
        SYS_YIELD => {
            task::yield_now();
            0
        }
        SYS_SLEEP_MS => {
            task::sleep_ms(a0.min(60_000));
            0
        }
        SYS_WRITE_DEBUG => sys_write_debug(a0, a1 as usize),
        SYS_MMAP_ANON => sys_mmap_anon(a0),
        SYS_MUNMAP => sys_munmap(a0, a1),
        SYS_THREAD_SPAWN => sys_thread_spawn(a0, a1),
        SYS_THREAD_EXIT => task::sched::exit_thread(),
        SYS_TIME_NOW => time::uptime_ms() as i64,
        SYS_GETPID => task::current_ids().0 as i64,
        SYS_GETTID => task::current_ids().1 as i64,
        SYS_CAP_DROP => sys_cap_drop(a0),
        SYS_CAP_DERIVE => sys_cap_derive(a0, a1),
        SYS_CAP_INFO => sys_cap_info(a0),
        SYS_SHM_MAP => sys_shm_map(a0),
        SYS_FUTEX_WAIT => sys_futex_wait(a0, a1 as u32),
        SYS_FUTEX_WAKE => sys_futex_wake(a0, a1 as usize),
        SYS_PORT_IN => sys_port_in(a0, a1),
        SYS_PORT_OUT => sys_port_out(a0, a1, a2 as u32),
        SYS_AUDIT_READ => sys_audit_read(a0, a1, a2 as usize),
        SYS_STAT => sys_stat(a0),
        21..=38 => super::sysx::handle(nr, f),
        _ => -ENOSYS,
    };
    if nr != SYS_EXIT {
        let kind = if ret == -EPERM || ret == -EBADF { EV_CAP_DENIED } else { EV_SYSCALL };
        crate::audit_log!(kind, nr, a0, a0, a1, ret);
    }
    f.rax = ret as u64;
}

fn sys_write_debug(ptr: u64, len: usize) -> i64 {
    if len > MAX_WRITE {
        return -EINVAL;
    }
    let p: Arc<Process> = task::current_process();
    let mut buf = [0u8; MAX_WRITE];
    if let Err(e) = uaccess::copy_from_user(&p, &mut buf[..len], ptr) {
        return -e;
    }
    match core::str::from_utf8(&buf[..len]) {
        Ok(s) => crate::serial_print!("[user pid {}] {}", p.pid, s),
        Err(_) => crate::serial_print!("[user pid {}] <{} non-utf8 bytes>\n", p.pid, len),
    }
    len as i64
}

fn sys_mmap_anon(len: u64) -> i64 {
    if len == 0 || len > MAX_MMAP {
        return -EINVAL;
    }
    let pages = ((len + PAGE_SIZE - 1) / PAGE_SIZE) as usize;
    let p = task::current_process();
    let va = p.mmap_next.fetch_add((pages as u64 + 1) * PAGE_SIZE, core::sync::atomic::Ordering::SeqCst);
    if !is_user_range(va, pages as u64 * PAGE_SIZE) {
        return -ENOMEM;
    }
    match p.map_region(va, pages, VmFlags::WRITE | VmFlags::USER) {
        Ok(()) => va as i64,
        Err(_) => -ENOMEM,
    }
}

/// Only whole regions returned by `mmap_anon` / `shm_map` can be unmapped (alpha restriction).
fn sys_munmap(addr: u64, len: u64) -> i64 {
    let pages = ((len + PAGE_SIZE - 1) / PAGE_SIZE) as usize;
    let p = task::current_process();
    let owned = {
        let mut m = p.mappings.lock();
        match m.iter().position(|r| r.va == addr && r.pages == pages && r.va >= task::USER_MMAP_BASE) {
            Some(i) => m.remove(i).owned,
            None => return -EINVAL,
        }
    };
    let mut g = p.space.lock();
    if let Some(sp) = g.as_mut() {
        for i in 0..pages {
            let va = VirtAddr::new(addr + i as u64 * PAGE_SIZE);
            if owned {
                let _ = sp.unmap_free(va);
            } else {
                let _ = sp.unmap(va);
            }
        }
    }
    0
}

fn sys_thread_spawn(entry: u64, stack_top: u64) -> i64 {
    if !is_user_range(entry, 1) || !is_user_range(stack_top.wrapping_sub(16), 16) || stack_top % 16 != 0 {
        return -EFAULT;
    }
    let p = task::current_process();
    match task::spawn_user_thread(&p, "user-thread", entry, stack_top, 0) {
        Some(tid) => tid as i64,
        None => -ENOMEM,
    }
}

// ------------------------------------------------------ capabilities -------

fn sys_cap_drop(h: u64) -> i64 {
    let p = task::current_process();
    let r = p.caps.lock().remove(h);
    match r {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

fn sys_cap_derive(h: u64, rights: u64) -> i64 {
    let p = task::current_process();
    let r = p.caps.lock().derive(h, Rights(rights as u32));
    match r {
        Ok(nh) => nh as i64,
        Err(e) => -e,
    }
}

/// `kind | side << 8 | rights << 16`
fn sys_cap_info(h: u64) -> i64 {
    let p = task::current_process();
    let r = p.caps.lock().lookup(h, Rights::NONE);
    match r {
        Ok((obj, rights)) => {
            let side = if let CapObject::Channel { side, .. } = &obj { *side as u64 } else { 0 };
            (obj.kind() | side << 8 | (rights.0 as u64) << 16) as i64
        }
        Err(e) => -e,
    }
}

fn sys_shm_map(h: u64) -> i64 {
    let p = task::current_process();
    let r = p.caps.lock().lookup(h, Rights::MAP);
    let (obj, rights) = match r {
        Ok(v) => v,
        Err(e) => return -e,
    };
    let mem = match obj {
        CapObject::Memory(m) => m,
        CapObject::Channel { mem, .. } => mem,
        _ => return -EINVAL,
    };
    match p.map_shared(&mem, rights.contains(Rights::WRITE)) {
        Ok(va) => va as i64,
        Err(e) => -e,
    }
}

fn sys_port_in(h: u64, port: u64) -> i64 {
    let p = task::current_process();
    let r = p.caps.lock().lookup(h, Rights::IO);
    match r {
        Ok((CapObject::IoPort { base, len }, _)) => {
            if port < base as u64 || port >= base as u64 + len as u64 {
                return -EPERM;
            }
            // SAFETY: the capability authorises this exact port range.
            unsafe { x86_64::instructions::port::Port::<u8>::new(port as u16).read() as i64 }
        }
        Ok(_) => -EINVAL,
        Err(e) => -e,
    }
}

fn sys_port_out(h: u64, port: u64, val: u32) -> i64 {
    let p = task::current_process();
    let r = p.caps.lock().lookup(h, Rights::IO | Rights::WRITE);
    match r {
        Ok((CapObject::IoPort { base, len }, _)) => {
            if port < base as u64 || port >= base as u64 + len as u64 {
                return -EPERM;
            }
            // SAFETY: the capability authorises this exact port range.
            unsafe { x86_64::instructions::port::Port::<u8>::new(port as u16).write(val as u8) };
            0
        }
        Ok(_) => -EINVAL,
        Err(e) => -e,
    }
}

fn sys_audit_read(h: u64, buf: u64, max: usize) -> i64 {
    let p = task::current_process();
    let r = p.caps.lock().lookup(h, Rights::AUDIT_READ);
    match r {
        Ok((CapObject::AuditStream, _)) => {}
        Ok(_) => return -EINVAL,
        Err(e) => return -e,
    }
    let max = max.min(MAX_AUDIT_BATCH);
    let mut out = [AuditEvent::default(); MAX_AUDIT_BATCH];
    let mut n = 0;
    while n < max {
        match audit::pop() {
            Some(ev) => {
                out[n] = ev;
                n += 1;
            }
            None => break,
        }
    }
    if n == 0 {
        return 0;
    }
    // SAFETY: AuditEvent is a plain repr(C) struct of integers (no padding, size 64).
    let bytes = unsafe { core::slice::from_raw_parts(out.as_ptr() as *const u8, n * 64) };
    match uaccess::copy_to_user(&p, buf, bytes) {
        Ok(()) => n as i64,
        Err(e) => -e,
    }
}

// ------------------------------------------------------------- futex -------

/// Futex word key = physical address, so it works across processes sharing memory.
fn futex_key(p: &Process, uaddr: u64) -> Result<u64, i64> {
    if uaddr % 4 != 0 || !is_user_range(uaddr, 4) {
        return Err(EFAULT);
    }
    let mut g = p.space.lock();
    let sp = g.as_mut().ok_or(EFAULT)?;
    sp.translate_user(VirtAddr::new(uaddr), false).map(|pa| pa.as_u64()).ok_or(EFAULT)
}

fn sys_futex_wait(uaddr: u64, expected: u32) -> i64 {
    let key = {
        let p = task::current_process();
        let key = match futex_key(&p, uaddr) {
            Ok(k) => k,
            Err(e) => return -e,
        };
        let mut word = [0u8; 4];
        if let Err(e) = uaccess::copy_from_user(&p, &mut word, uaddr) {
            return -e;
        }
        if u32::from_ne_bytes(word) != expected {
            return -EAGAIN;
        }
        key
    }; // no Arc held while blocked
    task::sched::futex_block(key);
    0
}

fn sys_futex_wake(uaddr: u64, n: usize) -> i64 {
    let key = {
        let p = task::current_process();
        match futex_key(&p, uaddr) {
            Ok(k) => k,
            Err(e) => return -e,
        }
    };
    task::sched::futex_wake(key, n.max(1)) as i64
}

fn sys_stat(buf: u64) -> i64 {
    let (frames_total, frames_free) = crate::mm::frame::stats();
    let hs = crate::mm::heap::stats();
    let (sw, sh) = crate::drivers::fb::info().map_or((0, 0), |f| (f.width as u64, f.height as u64));
    let st = super::abi::SysStats {
        uptime_ms: time::uptime_ms(),
        ticks: time::ticks(),
        frames_total: frames_total as u64,
        frames_free: frames_free as u64,
        heap_used: hs.used as u64,
        heap_mapped: hs.mapped as u64,
        ctx_switches: task::sched::context_switches(),
        audit_dropped: audit::dropped(),
        audit_pending: audit::pending() as u64,
        screen_w: sw,
        screen_h: sh,
        reserved: {
            let n = crate::net::stats();
            (n.tx_frames.min(u32::MAX as u64) << 32) | n.rx_frames.min(u32::MAX as u64)
        },
    };
    let p = task::current_process();
    // SAFETY: SysStats is repr(C) plain integers with no padding.
    let bytes = unsafe { core::slice::from_raw_parts(&st as *const _ as *const u8, core::mem::size_of::<super::abi::SysStats>()) };
    match uaccess::copy_to_user(&p, buf, bytes) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}
