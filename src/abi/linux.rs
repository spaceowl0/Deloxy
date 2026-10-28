//! Linux x86-64 syscall translation (subset sufficient for static, single-threaded programs).
//! Calls map onto Deloxy mechanisms: stdout/stderr -> Console capability, memory ->
//! per-process mappings, time -> kernel tick clock. Unsupported calls log once and
//! return -ENOSYS.

use alloc::sync::Arc;
use alloc::vec::Vec;

use x86_64::VirtAddr;

use super::{console_write, unmap_region};
use crate::arch::x86_64::syscall::SyscallFrame;
use crate::mm::layout::{is_user_range, PAGE_SIZE};
use crate::mm::vmm::VmFlags;
use crate::sys::errno::*;
use crate::sys::uaccess::{copy_from_user, copy_to_user};
use crate::task::{self, Process};
use crate::time;

const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const BRK_LIMIT: u64 = 64 * 1024 * 1024;

fn prot_flags(prot: u64) -> VmFlags {
    let mut f = VmFlags::USER;
    if prot & PROT_WRITE != 0 {
        f = f | VmFlags::WRITE;
    }
    if prot & PROT_EXEC != 0 {
        f = f | VmFlags::EXEC;
    }
    f
}

/// Linux syscall entry: runs the call, then delivers a pending signal (and handles syscall restart) before returning.
pub fn syscall(f: &mut SyscallFrame) -> i64 {
    let nr = f.rax;
    let ret = syscall_inner(f);
    super::signals::on_syscall_exit(f, nr, ret)
}

fn syscall_inner(f: &mut SyscallFrame) -> i64 {
    let (a0, a1, a2, a3) = (f.rdi, f.rsi, f.rdx, f.r10);
    let p = task::current_process();
    match f.rax {
        0 => sys_read(&p, a0, a1, a2),
        41 => super::linux_net::socket(&p, a0, a1, a2),
        42 => super::linux_net::connect(&p, a0, a1, a2),
        43 => super::linux_net::accept(&p, a0, a1, a2, 0),
        288 => super::linux_net::accept(&p, a0, a1, a2, a3),
        44 => super::linux_net::sendto(&p, a0, a1, a2, a3, f.r8, f.r9),
        45 => super::linux_net::recvfrom(&p, a0, a1, a2, a3, f.r8, f.r9),
        46 => super::linux_net::sendmsg(&p, a0, a1, a2),
        47 => super::linux_net::recvmsg(&p, a0, a1, a2),
        307 => super::linux_net::sendmmsg(&p, a0, a1, a2, a3),
        48 => super::linux_net::shutdown(&p, a0, a1),
        49 => super::linux_net::bind(&p, a0, a1, a2),
        50 => super::linux_net::listen(&p, a0, a1),
        51 => super::linux_net::getsockname(&p, a0, a1, a2),
        52 => super::linux_net::getpeername(&p, a0, a1, a2),
        54 => super::linux_net::setsockopt(&p, a0, a1, a2, a3, f.r8),
        55 => super::linux_net::getsockopt(&p, a0, a1, a2, a3, f.r8),
        23 => super::linux_net::select(&p, a0, a1, a2, a3, f.r8),
        270 => super::linux_net::pselect6(&p, a0, a1, a2, a3, f.r8),
        213 => super::linux_net::epoll_create(&p, 0),
        291 => super::linux_net::epoll_create(&p, a0),
        290 => sys_eventfd(&p, a0, a1),
        284 => sys_eventfd(&p, a0, 0),
        19 => sys_readv(&p, a0, a1, a2),
        18 => sys_pwrite(&p, a0, a1, a2, a3),
        137 => sys_statfs(&p, a1),
        138 => sys_statfs(&p, a1),
        40 => sys_sendfile(&p, a0, a1, a2, a3),
        233 => super::linux_net::epoll_ctl(&p, a0, a1, a2, a3),
        232 | 281 => super::linux_net::epoll_wait(&p, a0, a1, a2, a3 as i32 as i64),
        56 => sys_clone(&p, f, a0, a1, a2, a3, f.r8),
        435 => -ENOSYS,                           // clone3: glibc falls back to clone
        60 => sys_thread_exit(&p),
        22 => sys_pipe2(&p, a0, 0),
        293 => sys_pipe2(&p, a0, a1),
        32 => sys_dup(&p, a0),
        33 | 292 => sys_dup2(&p, a0, a1),
        7 => sys_poll(&p, a0, a1, a2 as i32),
        271 => sys_ppoll(&p, a0, a1, a2),
        200 => super::linux_proc::kill(&p, a0, a1),          // tkill(tid, sig): tid == pid for the main thread
        234 => super::linux_proc::kill(&p, a0, a2),          // tgkill(tgid, tid, sig)
        13 => super::signals::rt_sigaction(&p, a0, a1, a2, a3),
        14 => super::signals::rt_sigprocmask(&p, a0, a1, a2, a3),
        15 => super::signals::rt_sigreturn(&p, f),
        34 => super::signals::pause(&p),
        36 => super::signals::getitimer(&p, a0, a1),
        37 => super::signals::alarm(&p, a0),
        38 => super::signals::setitimer(&p, a0, a1, a2),
        127 => super::signals::rt_sigpending(&p, a0, a1),
        128 => super::signals::rt_sigtimedwait(&p, a0, a1, a2, a3),
        130 => super::signals::rt_sigsuspend(&p, a0, a1),
        222 => super::signals::timer_create(&p, a0, a1, a2),
        223 => super::signals::timer_settime(&p, a0, a1, a2, a3),
        224 => super::signals::timer_gettime(&p, a0, a1),
        225 => 0, // timer_getoverrun
        226 => super::signals::timer_delete(&p, a0),
        202 => sys_futex(&p, a0, a1, a2, a3),
        218 => sys_set_tid_address(&p, a0),
        217 => sys_getdents64(&p, a0, a1, a2),
        87 => sys_unlink(&p, a0),
        263 => sys_unlinkat(&p, a0, a1, a2),
        74 | 75 => 0,
        77 => sys_ftruncate(&p, a0, a1),
        80 => sys_chdir(&p, a0),
        81 => sys_fchdir(&p, a0),
        83 => sys_mkdirat(&p, AT_FDCWD as u64, a0),
        258 => sys_mkdirat(&p, a0, a1),
        84 => sys_rmdirat(&p, AT_FDCWD as u64, a0),
        82 => sys_renameat(&p, AT_FDCWD as u64, a0, AT_FDCWD as u64, a1),
        264 | 316 => sys_renameat(&p, a0, a1, a2, a3),
        17 => sys_pread(&p, a0, a1, a2, a3),
        2 => sys_open(&p, a0, a1, a2),
        257 => sys_openat(&p, a0, a1, a2, a3),
        4 => sys_stat_path(&p, a0, a1),
        6 => sys_lstat_path(&p, a0, a1),
        262 => sys_newfstatat(&p, a0, a1, a2, a3),
        21 => sys_access(&p, a0),
        79 => sys_getcwd(&p, a0, a1),
        72 => sys_fcntl(&p, a0, a1, a2),
        110 => 1,
        57 => super::linux_proc::fork(&p, f, 0, false),
        58 => super::linux_proc::fork(&p, f, 0, true),
        59 => super::linux_proc::execve(&p, f, a0, a1, a2),
        61 => super::linux_proc::wait4(&p, a0, a1, a2),
        62 => super::linux_proc::kill(&p, a0, a1),
        204 => sys_sched_getaffinity(&p, a1, a2),
        230 => sys_clock_nanosleep(&p, a1, a2, a3),
        97 => sys_getrlimit(&p, a1),
        95 => 0o22,
        25 => -ENOMEM,
        1 => sys_write(&p, a0, a1, a2),
        3 => sys_close(&p, a0),
        5 => sys_fstat(&p, a0, a1),              // fstat
        8 => sys_lseek(&p, a0, a1, a2),
        9 => sys_mmap(&p, a0, a1, a2, a3, f.r8, f.r9),
        10 => sys_mprotect(&p, a0, a1, a2),
        11 => sys_munmap(&p, a0, a1),
        12 => sys_brk(&p, a0),
        16 => sys_ioctl(&p, a0, a1, a2),
        20 => sys_writev(&p, a0, a1, a2),
        89 => sys_readlinkat(&p, AT_FDCWD as u64, a0, a1, a2),
        267 => sys_readlinkat(&p, a0, a1, a2, a3),
        269 | 439 => sys_access_at(&p, a0, a1),
        24 => {
            task::yield_now();
            0
        }
        28 => 0,                                 // madvise
        35 => sys_nanosleep(&p, a0, a1),
        39 => p.pid as i64,                      // getpid
        63 => sys_uname(&p, a0),
        231 => {
            super::vfs::flush_all(&p);
            task::sched::exit_process((a0 & 0xFF) as i64)
        }
        96 => sys_gettimeofday(&p, a0),
        229 => {
            // clock_getres: 1 ms resolution
            if a1 != 0 && copy_to_user(&p, a1, &timespec(0, 1_000_000)).is_err() { -EFAULT } else { 0 }
        }
        157 => 0, // prctl: PR_SET_NAME / PR_SET_DUMPABLE / ... are accepted and ignored
        140 => 20, // getpriority: raw value is 20 - nice
        141 | 142 | 143 | 144 | 145 | 146 | 147 | 148 => 0, // get/setpriority, sched_*: everything runs at normal priority
        201 => {
            let t = (time::unix_ms() / 1000) as i64;
            if a0 != 0 && copy_to_user(&p, a0, &t.to_le_bytes()).is_err() {
                -EFAULT
            } else {
                t
            }
        }
        99 => sys_sysinfo(&p, a0),
        102 | 104 | 107 | 108 => 1000,           // get[e]uid/gid
        158 => sys_arch_prctl(&p, a0, a1),
        186 => task::current_ids().1 as i64,     // gettid
        228 => sys_clock_gettime(&p, a1),
        273 => 0,                                // set_robust_list
        334 => -ENOSYS,                          // rseq (glibc copes)
        302 => sys_prlimit(&p, a3),
        318 => sys_getrandom(&p, a0, a1),
        n => {
            if p.foreign.lock().first_warning(n as u16) {
                log::warn!("linux: unimplemented syscall {} in pid {} - returning ENOSYS", n, p.pid);
            }
            -ENOSYS
        }
    }
}

/// stdin/stdout/stderr may have been redirected with dup2/dup3: map fd 0..2 to the descriptor they alias.
fn rd(p: &Arc<Process>, fd: u64) -> u64 {
    if fd < 3 {
        if let Some(slot) = p.foreign.lock().redirect[fd as usize] {
            return slot as u64 + 3;
        }
    }
    fd
}

fn write_fd(p: &Arc<Process>, fd: u64, buf: u64, len: usize) -> i64 {
    let fd = rd(p, fd);
    if fd >= 3 {
        return write_file_fd(p, fd, buf, len);
    }
    if fd != 1 && fd != 2 {
        return -EBADF;
    }
    let mut done = 0usize;
    let mut chunk = [0u8; 512];
    while done < len {
        let n = core::cmp::min(len - done, chunk.len());
        if let Err(e) = copy_from_user(p, &mut chunk[..n], buf + done as u64) {
            return if done > 0 { done as i64 } else { -e };
        }
        if let Err(e) = console_write(p, "linux", &chunk[..n]) {
            return -e;
        }
        done += n;
    }
    done as i64
}

fn sys_write(p: &Arc<Process>, fd: u64, buf: u64, len: u64) -> i64 {
    if len > 1 << 20 {
        return -EINVAL;
    }
    let r = write_fd(p, fd, buf, len as usize);
    if r == -32 {
        super::signals::raise(p, super::signals::SIGPIPE);
    }
    r
}

fn sys_writev(p: &Arc<Process>, fd: u64, iov: u64, cnt: u64) -> i64 {
    if cnt > 64 {
        return -EINVAL;
    }
    let mut total = 0i64;
    for i in 0..cnt {
        let mut ent = [0u8; 16];
        if let Err(e) = copy_from_user(p, &mut ent, iov + i * 16) {
            return -e;
        }
        let base = u64::from_le_bytes(ent[..8].try_into().unwrap());
        let len = u64::from_le_bytes(ent[8..].try_into().unwrap());
        if len > 1 << 20 {
            return -EINVAL;
        }
        let r = write_fd(p, fd, base, len as usize);
        if r < 0 {
            return if total > 0 { total } else { r };
        }
        total += r;
    }
    total
}

fn sys_brk(p: &Arc<Process>, new: u64) -> i64 {
    let mut f = p.foreign.lock();
    if new == 0 || new < f.brk_base {
        return f.brk as i64;
    }
    if new > f.brk_base + BRK_LIMIT {
        return f.brk as i64;
    }
    let need_end = (new + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    if need_end > f.brk_mapped {
        let start = f.brk_mapped;
        let pages = ((need_end - start) / PAGE_SIZE) as usize;
        drop(f);
        if p.map_region(start, pages, VmFlags::WRITE | VmFlags::USER).is_err() {
            return p.foreign.lock().brk as i64;
        }
        f = p.foreign.lock();
        f.brk_mapped = need_end;
    }
    f.brk = new;
    new as i64
}

fn sys_mmap(p: &Arc<Process>, addr: u64, len: u64, prot: u64, flags: u64, fd: u64, _off: u64) -> i64 {
    let file_bytes: Option<Vec<u8>> = if flags & MAP_ANONYMOUS == 0 {
        // private file mapping: the file's bytes are copied into fresh pages (writes never reach the file)
        let Some(i) = fd_slot(fd) else { return -ENODEV_LIKE };
        let g = p.foreign.lock();
        let Some(Some(f)) = g.fds.get(i) else { return -EBADF };
        if f.is_dir() {
            return -ENODEV_LIKE;
        }
        let b = f.bytes();
        let off = (_off as usize).min(b.len());
        Some(b[off..b.len().min(off + len as usize)].to_vec())
    } else {
        None
    };
    if len == 0 || len > 256 * 1024 * 1024 {
        return -EINVAL;
    }
    let pages = ((len + PAGE_SIZE - 1) / PAGE_SIZE) as usize;
    let va = if flags & MAP_FIXED != 0 {
        if addr % PAGE_SIZE != 0 || !is_user_range(addr, pages as u64 * PAGE_SIZE) {
            return -EINVAL;
        }
        p.unmap_range(addr, pages); // MAP_FIXED replaces whatever is there (ld.so reserves a range, then overlays segments)
        addr
    } else {
        p.mmap_next.fetch_add((pages as u64 + 1) * PAGE_SIZE, core::sync::atomic::Ordering::SeqCst)
    };
    if !is_user_range(va, pages as u64 * PAGE_SIZE) {
        return -ENOMEM;
    }
    if p.map_region(va, pages, VmFlags::WRITE | VmFlags::USER).is_err() {
        return -ENOMEM;
    }
    if let Some(bytes) = &file_bytes {
        if copy_to_user(p, va, bytes).is_err() {
            return -ENOMEM;
        }
    }
    if prot & PROT_WRITE == 0 || prot & PROT_EXEC != 0 {
        let mut g = p.space.lock();
        if let Some(sp) = g.as_mut() {
            for i in 0..pages {
                let _ = sp.protect(VirtAddr::new(va + i as u64 * PAGE_SIZE), prot_flags(prot));
            }
        }
    }
    va as i64
}

/// Linux uses EACCES/ENODEV for unsupported file mappings; we report ENODEV (19).
const ENODEV_LIKE: i64 = 19;

fn sys_mprotect(p: &Arc<Process>, addr: u64, len: u64, prot: u64) -> i64 {
    if addr % PAGE_SIZE != 0 || !is_user_range(addr, len.max(1)) {
        return -EINVAL;
    }
    let pages = ((len + PAGE_SIZE - 1) / PAGE_SIZE) as usize;
    let mut g = p.space.lock();
    let Some(sp) = g.as_mut() else { return -ENOMEM };
    for i in 0..pages {
        if sp.protect(VirtAddr::new(addr + i as u64 * PAGE_SIZE), prot_flags(prot)).is_err() {
            return -ENOMEM;
        }
    }
    0
}

fn sys_munmap(p: &Arc<Process>, addr: u64, len: u64) -> i64 {
    if addr % PAGE_SIZE != 0 || len == 0 || !is_user_range(addr, len) {
        return -EINVAL;
    }
    p.unmap_range(addr, ((len + PAGE_SIZE - 1) / PAGE_SIZE) as usize);
    0
}

fn sys_uname(p: &Arc<Process>, buf: u64) -> i64 {
    let mut u = [0u8; 65 * 6];
    let fields: [&[u8]; 6] = [b"Linux", b"deloxy", b"6.1.0-deloxy-wltd", b"#1 deloxy-wltd", b"x86_64", b"(none)"];
    for (i, f) in fields.iter().enumerate() {
        u[i * 65..i * 65 + f.len()].copy_from_slice(f);
    }
    match copy_to_user(p, buf, &u) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

fn sys_arch_prctl(_p: &Arc<Process>, code: u64, addr: u64) -> i64 {
    const ARCH_SET_FS: u64 = 0x1002;
    match code {
        ARCH_SET_FS => {
            if addr != 0 && !is_user_range(addr, 1) {
                return -EINVAL;
            }
            task::sched::set_current_fs_base(addr);
            0
        }
        _ => -EINVAL,
    }
}

fn timespec(sec: u64, nsec: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&sec.to_le_bytes());
    b[8..].copy_from_slice(&nsec.to_le_bytes());
    b
}

fn sys_clock_gettime(p: &Arc<Process>, ts: u64) -> i64 {
    let ms = time::uptime_ms();
    match copy_to_user(p, ts, &timespec(time::unix_ms() / 1000, (time::unix_ms() % 1000) * 1_000_000)) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

fn sys_gettimeofday(p: &Arc<Process>, tv: u64) -> i64 {
    if tv == 0 {
        return 0;
    }
    let ms = time::uptime_ms();
    match copy_to_user(p, tv, &timespec(time::unix_ms() / 1000, (time::unix_ms() % 1000) * 1000)) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

fn sys_nanosleep(p: &Arc<Process>, req: u64, rem: u64) -> i64 {
    sleep_for(p, req, rem, false)
}

/// Sleep for the interval at `req` (or until the absolute deadline). On a signal returns EINTR and stores the time left.
fn sleep_for(p: &Arc<Process>, req: u64, rem: u64, absolute: bool) -> i64 {
    let mut b = [0u8; 16];
    if let Err(e) = copy_from_user(p, &mut b, req) {
        return -e;
    }
    let sec = u64::from_le_bytes(b[..8].try_into().unwrap());
    let nsec = u64::from_le_bytes(b[8..].try_into().unwrap());
    let want_ms = sec.min(1 << 40).saturating_mul(1000) + nsec / 1_000_000;
    let total = if absolute { want_ms.saturating_sub(time::unix_ms()) } else { want_ms.min(3_600_000) };
    let t0 = time::uptime_ms();
    loop {
        let el = time::uptime_ms().saturating_sub(t0);
        if el >= total {
            return 0;
        }
        if super::signals::interrupted(p) {
            if rem != 0 && !absolute {
                let left = total - el;
                let mut o = [0u8; 16];
                o[..8].copy_from_slice(&(left / 1000).to_le_bytes());
                o[8..].copy_from_slice(&((left % 1000) * 1_000_000).to_le_bytes());
                let _ = copy_to_user(p, rem, &o);
            }
            return -super::signals::EINTR;
        }
        task::sleep_ms(1);
    }
}

/// Not cryptographic: xorshift seeded from the tick clock (documented limitation).
fn sys_getrandom(p: &Arc<Process>, buf: u64, len: u64) -> i64 {
    let len = len.min(1 << 20) as usize;
    let mut out = alloc::vec![0u8; len];
    crate::rand::fill(&mut out);
    match copy_to_user(p, buf, &out) {
        Ok(()) => len as i64,
        Err(e) => -e,
    }
}

// ------------------------------------------------------------------- files ---

use super::vfs;

const AT_FDCWD: i64 = -100;

/// Path argument of an *at() syscall: absolute paths and AT_FDCWD use the working directory, otherwise the path is
/// relative to the directory open on `dirfd`.
fn user_path_at(p: &Arc<Process>, dirfd: u64, ptr: u64) -> Result<alloc::string::String, i64> {
    let s = user_cstr(p, ptr)?;
    if s.starts_with('/') || dirfd as u32 as i32 as i64 == AT_FDCWD || s.is_empty() {
        return Ok(s);
    }
    let Some(i) = fd_slot(dirfd) else { return Err(EBADF) };
    let g = p.foreign.lock();
    match g.fds.get(i).and_then(|f| f.as_ref()) {
        Some(f) if f.is_dir() => Ok(alloc::format!("{}/{}", f.name, s)),
        Some(_) => Err(ENOTDIR_),
        None => Err(EBADF),
    }
}

fn user_cstr(p: &Arc<Process>, ptr: u64) -> Result<alloc::string::String, i64> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    for i in 0..4096u64 {
        copy_from_user(p, &mut b, ptr + i).map_err(|e| e)?;
        if b[0] == 0 {
            return alloc::string::String::from_utf8(out).map_err(|_| EINVAL);
        }
        out.push(b[0]);
    }
    Err(36) // ENAMETOOLONG
}

fn fd_slot(fd: u64) -> Option<usize> {
    if fd >= 3 { Some(fd as usize - 3) } else { None }
}

fn sys_open(p: &Arc<Process>, path: u64, flags: u64, mode: u64) -> i64 {
    sys_openat(p, AT_FDCWD as u64, path, flags, mode)
}

fn sys_openat(p: &Arc<Process>, dirfd: u64, path: u64, flags: u64, _mode: u64) -> i64 {
    let path = match user_path_at(p, dirfd, path) {
        Ok(s) => s,
        Err(e) => return -e,
    };
    let acc = flags & 3;
    let write = acc == 1 || acc == 2;
    let (creat, trunc, append) = (flags & 0o100 != 0, flags & 0o1000 != 0, flags & 0o2000 != 0);
    let abs = vfs::resolve_abs(p, &path);
    if vfs::is_dir_path(&abs) {
        if write {
            return -EISDIR_;
        }
        return match vfs::alloc(p, vfs::open_dir(p)) {
            Ok(i) => i as i64 + 3,
            Err(e) => -e,
        };
    }
    match vfs::open(p, &path, write, creat, trunc, append) {
        Ok(f) if flags & 0o200000 != 0 && !f.is_dir() => {
            drop(f);
            -ENOTDIR_ // O_DIRECTORY on a file
        }
        Ok(f) if write && f.is_dir() => -EISDIR_,
        Ok(f) => match vfs::alloc(p, f) {
            Ok(i) => i as i64 + 3,
            Err(e) => -e,
        },
        Err(e) => -e,
    }
}

fn sys_close(p: &Arc<Process>, fd: u64) -> i64 {
    if fd < 3 {
        // closing a redirected stdio fd drops the alias (and its descriptor)
        let old = p.foreign.lock().redirect[fd as usize].take();
        if let Some(slot) = old {
            let _ = vfs::close(p, slot);
        }
        return 0;
    }
    match fd_slot(fd) {
        None => 0,
        Some(i) => match vfs::close(p, i) {
            Ok(()) => 0,
            Err(e) => -e,
        },
    }
}

fn sys_read(p: &Arc<Process>, fd: u64, buf: u64, len: u64) -> i64 {
    let fd = rd(p, fd);
    let Some(i) = fd_slot(fd) else {
        if fd != 0 {
            return -EBADF;
        }
        return match super::stdin_read(p, (len as usize).min(64 * 1024)) {
            Ok(v) => match copy_to_user(p, buf, &v) {
                Ok(()) => v.len() as i64,
                Err(e) => -e,
            },
            Err(_) => 0,
        };
    };
    if super::sock::is_sock(p, i) {
        return match super::sock::recv(p, i, len as usize, false) {
            Ok(v) => match copy_to_user(p, buf, &v) {
                Ok(()) => v.len() as i64,
                Err(e) => -e,
            },
            Err(e) => -e,
        };
    }
    // an empty pipe with live writers blocks (or EAGAINs); an eventfd blocks while its counter is zero
    loop {
        enum W { No, Wait(bool), Ev(Option<u64>, bool) }
        let w = {
            let g = p.foreign.lock();
            match g.fds.get(i).and_then(|s| s.as_ref()).map(|f| &f.data) {
                Some(vfs::Data::Pipe(pe)) if !pe.write && !pe.readable() => W::Wait(pe.nonblock),
                Some(vfs::Data::Event(ev)) => {
                    use core::sync::atomic::Ordering::SeqCst;
                    let c = ev.counter.load(SeqCst);
                    if len < 8 {
                        return -EINVAL;
                    }
                    if c == 0 {
                        W::Ev(None, ev.nonblock)
                    } else {
                        let take = if ev.semaphore { 1 } else { c };
                        ev.counter.fetch_sub(take, SeqCst);
                        W::Ev(Some(take), ev.nonblock)
                    }
                }
                _ => W::No,
            }
        };
        match w {
            W::No => break,
            W::Wait(true) | W::Ev(None, true) => return -11,
            W::Wait(false) | W::Ev(None, false) => {
                if super::signals::interrupted(p) {
                    return -super::signals::ERESTART;
                }
                task::sleep_ms(1)
            }
            W::Ev(Some(v), _) => {
                return match copy_to_user(p, buf, &v.to_le_bytes()) {
                    Ok(()) => 8,
                    Err(e) => -e,
                };
            }
        }
    }
    let n = (len as usize).min(64 * 1024);
    let mut tmp = alloc::vec![0u8; n];
    let got = {
        let mut g = p.foreign.lock();
        match g.fds.get_mut(i).and_then(|s| s.as_mut()) {
            Some(f) if f.is_dir() => return -EISDIR_,
            Some(f) => vfs::read(f, &mut tmp),
            None => return -EBADF,
        }
    };
    match copy_to_user(p, buf, &tmp[..got]) {
        Ok(()) => got as i64,
        Err(e) => -e,
    }
}

fn sys_pread(p: &Arc<Process>, fd: u64, buf: u64, len: u64, off: u64) -> i64 {
    let fd = rd(p, fd);
    let Some(i) = fd_slot(fd) else { return -ESPIPE_ };
    let n = (len as usize).min(64 * 1024);
    let mut tmp = alloc::vec![0u8; n];
    let got = {
        let mut g = p.foreign.lock();
        match g.fds.get_mut(i).and_then(|s| s.as_mut()) {
            Some(f) => {
                let save = f.pos;
                f.pos = off as usize;
                let r = vfs::read(f, &mut tmp);
                f.pos = save;
                r
            }
            None => return -EBADF,
        }
    };
    match copy_to_user(p, buf, &tmp[..got]) {
        Ok(()) => got as i64,
        Err(e) => -e,
    }
}

const ESPIPE_: i64 = 29;

fn write_file_fd(p: &Arc<Process>, fd: u64, buf: u64, len: usize) -> i64 {
    let Some(i) = fd_slot(fd) else { return -EBADF };
    if super::sock::is_sock(p, i) {
        let mut tmp = alloc::vec![0u8; len.min(1 << 20)];
        if let Err(e) = copy_from_user(p, &mut tmp, buf) {
            return -e;
        }
        return match super::sock::send(p, i, &tmp, false) {
            Ok(n) => n as i64,
            Err(e) => -e,
        };
    }
    let n = len.min(64 * 1024);
    let mut tmp = alloc::vec![0u8; n];
    if let Err(e) = copy_from_user(p, &mut tmp, buf) {
        return -e;
    }
    let mut g = p.foreign.lock();
    if let Some(Some(vfs::OpenFile { data: vfs::Data::Event(ev), .. })) = g.fds.get(i) {
        if tmp.len() < 8 {
            return -EINVAL;
        }
        let v = u64::from_le_bytes(tmp[..8].try_into().unwrap());
        if v == u64::MAX {
            return -EINVAL;
        }
        ev.counter.fetch_add(v, core::sync::atomic::Ordering::SeqCst);
        return 8;
    }
    match g.fds.get_mut(i).and_then(|s| s.as_mut()) {
        Some(f) => match vfs::write(f, &tmp) {
            Ok(n) => n as i64,
            Err(e) => -e,
        },
        None => -EBADF,
    }
}

fn sys_lseek(p: &Arc<Process>, fd: u64, off: u64, whence: u64) -> i64 {
    let fd = rd(p, fd);
    let Some(i) = fd_slot(fd) else { return -ESPIPE_ };
    let mut g = p.foreign.lock();
    match g.fds.get_mut(i).and_then(|s| s.as_mut()) {
        Some(f) => match vfs::seek(f, off as i64, whence) {
            Ok(v) => v as i64,
            Err(e) => -e,
        },
        None => -EBADF,
    }
}

fn stat_buf(mode: u32, size: u64) -> [u8; 144] {
    let mut st = [0u8; 144];
    st[16..24].copy_from_slice(&1u64.to_le_bytes()); // st_nlink
    st[24..28].copy_from_slice(&mode.to_le_bytes());
    st[48..56].copy_from_slice(&size.to_le_bytes());
    st[56..64].copy_from_slice(&4096u64.to_le_bytes()); // st_blksize
    st[64..72].copy_from_slice(&((size + 511) / 512).to_le_bytes());
    st
}

/// st_dev / st_ino: unique and stable per file name. ld.so compares them to decide whether a library is already loaded,
/// so every file needs its own non-zero identity.
fn with_ino(mut st: [u8; 144], name: &str) -> [u8; 144] {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes() {
        h = (h ^ b as u64).wrapping_mul(0x0100_0000_01b3);
    }
    st[0..8].copy_from_slice(&0x801u64.to_le_bytes());
    st[8..16].copy_from_slice(&(h | 1).to_le_bytes());
    st
}

fn sys_fstat(p: &Arc<Process>, fd: u64, buf: u64) -> i64 {
    let fd = rd(p, fd);
    let st = match fd_slot(fd) {
        None => stat_buf(0o020620, 0), // S_IFCHR | 0620
        Some(i) => {
            let g = p.foreign.lock();
            match g.fds.get(i).and_then(|s| s.as_ref()) {
                Some(f) if f.is_dir() => stat_buf(0o040755, 0),
                Some(f) => with_ino(stat_buf(if f.name.ends_with(".elf") || f.name.contains(".so") || vfs::looks_executable(f.bytes()) { 0o100755 } else { 0o100644 }, f.len() as u64), &f.name),
                None => return -EBADF,
            }
        }
    };
    match copy_to_user(p, buf, &st) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

fn stat_for(f: &vfs::OpenFile) -> [u8; 144] {
    if f.is_dir() {
        return with_ino(stat_buf(0o040755, 0), &f.name);
    }
    with_ino(stat_buf(if f.name.ends_with(".elf") || f.name.contains(".so") || vfs::looks_executable(f.bytes()) { 0o100755 } else { 0o100644 }, f.len() as u64), &f.name)
}

fn sys_stat_path(p: &Arc<Process>, path: u64, buf: u64) -> i64 {
    sys_stat_at(p, AT_FDCWD as u64, path, buf)
}

/// Target of the symlink named by `abs` (the final component is NOT followed), if it is one.
fn symlink_target(abs: &str) -> Option<alloc::string::String> {
    match abs.rsplit_once('/') {
        Some((parent, name)) => crate::fs::rootfs::lookup(parent).and_then(|(cp, _)| crate::fs::rootfs::readlink(&alloc::format!("{}/{}", cp, name))),
        None => crate::fs::rootfs::readlink(abs),
    }
}

fn sys_lstat_path(p: &Arc<Process>, path: u64, buf: u64) -> i64 {
    sys_stat_at_nf(p, AT_FDCWD as u64, path, buf, true)
}

fn sys_stat_at(p: &Arc<Process>, dirfd: u64, path: u64, buf: u64) -> i64 {
    sys_stat_at_nf(p, dirfd, path, buf, false)
}

fn sys_stat_at_nf(p: &Arc<Process>, dirfd: u64, path: u64, buf: u64, nofollow: bool) -> i64 {
    let path = match user_path_at(p, dirfd, path) {
        Ok(s) => s,
        Err(e) => return -e,
    };
    let abs = vfs::resolve_abs(p, &path);
    if nofollow {
        if let Some(t) = symlink_target(&abs) {
            return match copy_to_user(p, buf, &with_ino(stat_buf(0o120777, t.len() as u64), &alloc::format!("/{}", abs))) {
                Ok(()) => 0,
                Err(e) => -e,
            };
        }
    }
    if vfs::is_dir_path(&abs) {
        return match copy_to_user(p, buf, &with_ino(stat_buf(0o040755, 0), &alloc::format!("/{}", abs))) {
            Ok(()) => 0,
            Err(e) => -e,
        };
    }
    match vfs::open(p, &path, false, false, false, false) {
        Ok(f) => match copy_to_user(p, buf, &stat_for(&f)) {
            Ok(()) => 0,
            Err(e) => -e,
        },
        Err(e) => -e,
    }
}

fn sys_newfstatat(p: &Arc<Process>, dirfd: u64, path: u64, buf: u64, flags: u64) -> i64 {
    match user_cstr(p, path) {
        Ok(s) if s.is_empty() => sys_fstat(p, dirfd, buf),
        Ok(_) => sys_stat_at_nf(p, dirfd, path, buf, flags & 0x100 != 0),
        Err(e) => -e,
    }
}

fn sys_access_at(p: &Arc<Process>, dirfd: u64, path: u64) -> i64 {
    let path = match user_path_at(p, dirfd, path) {
        Ok(s) => s,
        Err(e) => return -e,
    };
    let abs = vfs::resolve_abs(p, &path);
    if vfs::is_dir_path(&abs) {
        return 0;
    }
    match vfs::open(p, &path, false, false, false, false) {
        Ok(_) => 0,
        Err(e) => -e,
    }
}

fn sys_access(p: &Arc<Process>, path: u64) -> i64 {
    sys_access_at(p, AT_FDCWD as u64, path)
}

fn sys_chdir(p: &Arc<Process>, path: u64) -> i64 {
    let s = match user_cstr(p, path) {
        Ok(s) => s,
        Err(e) => return -e,
    };
    let abs = vfs::resolve_abs(p, &s);
    if vfs::is_dir_abs(p, &abs) {
        p.foreign.lock().cwd = abs;
        return 0;
    }
    // a file, or nothing at all
    match vfs::open(p, &s, false, false, false, false) {
        Ok(_) => -ENOTDIR_,
        Err(e) => -e,
    }
}

fn sys_fchdir(p: &Arc<Process>, fd: u64) -> i64 {
    let Some(i) = fd_slot(fd) else { return -EBADF };
    let mut g = p.foreign.lock();
    let name = match g.fds.get(i).and_then(|f| f.as_ref()) {
        Some(f) if f.is_dir() => f.name.clone(),
        Some(_) => return -ENOTDIR_,
        None => return -EBADF,
    };
    g.cwd = crate::fs::rootfs::canon(&name);
    0
}

fn sys_mkdirat(p: &Arc<Process>, dirfd: u64, path: u64) -> i64 {
    match user_path_at(p, dirfd, path) {
        Ok(s) => match vfs::mkdir(p, &s) {
            Ok(()) => 0,
            Err(e) => -e,
        },
        Err(e) => -e,
    }
}

fn sys_rmdirat(p: &Arc<Process>, dirfd: u64, path: u64) -> i64 {
    match user_path_at(p, dirfd, path) {
        Ok(s) => match vfs::rmdir(p, &s) {
            Ok(()) => 0,
            Err(e) => -e,
        },
        Err(e) => -e,
    }
}

fn sys_renameat(p: &Arc<Process>, odir: u64, old: u64, ndir: u64, new: u64) -> i64 {
    let (a, b) = match (user_path_at(p, odir, old), user_path_at(p, ndir, new)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => return -e,
    };
    match vfs::rename(p, &a, &b) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

fn sys_readlinkat(p: &Arc<Process>, dirfd: u64, path: u64, buf: u64, size: u64) -> i64 {
    let s = match user_path_at(p, dirfd, path) {
        Ok(s) => s,
        Err(e) => return -e,
    };
    let abs = vfs::resolve_abs(p, &s);
    let target: Option<alloc::string::String> = if abs == "proc/self/exe" {
        Some(alloc::format!("/bin/{}", p.foreign.lock().prog_name))
    } else if let Some((parent, name)) = abs.rsplit_once('/') {
        crate::fs::rootfs::lookup(parent).and_then(|(cp, _)| crate::fs::rootfs::readlink(&alloc::format!("{}/{}", cp, name)))
    } else {
        crate::fs::rootfs::readlink(&abs)
    };
    match target {
        Some(t) => {
            let n = t.len().min(size as usize);
            match copy_to_user(p, buf, &t.as_bytes()[..n]) {
                Ok(()) => n as i64,
                Err(e) => -e,
            }
        }
        None => {
            if vfs::open(p, &s, false, false, false, false).is_ok() || vfs::is_dir_abs(p, &abs) { -EINVAL } else { -ENOENT }
        }
    }
}

fn sys_getcwd(p: &Arc<Process>, buf: u64, size: u64) -> i64 {
    if size < 2 {
        return -ERANGE;
    }
    let cwd = alloc::format!("/{}\0", p.foreign.lock().cwd);
    if (size as usize) < cwd.len() {
        return -ERANGE;
    }
    match copy_to_user(p, buf, cwd.as_bytes()) {
        Ok(()) => cwd.len() as i64,
        Err(e) => -e,
    }
}

fn sys_fcntl(p: &Arc<Process>, fd: u64, cmd: u64, arg: u64) -> i64 {
    match cmd {
        1 | 2 => 0, // F_GETFD / F_SETFD
        3 => match fd_slot(fd) {
            Some(i) if super::sock::is_sock(p, i) && super::sock::is_nonblock(p, i) => 0x800, // F_GETFL
            Some(i) => {
                let g = p.foreign.lock();
                match g.fds.get(i).and_then(|s| s.as_ref()).map(|f| &f.data) {
                    Some(vfs::Data::Pipe(pe)) if pe.nonblock => 0x800,
                    Some(vfs::Data::Event(e)) if e.nonblock => 0x800,
                    _ => 0,
                }
            }
            _ => 0,
        },
        4 => {
            if let Some(i) = fd_slot(fd) {
                let nb = arg & 0x800 != 0;
                let _ = super::sock::set_nonblock(p, i, nb); // F_SETFL(O_NONBLOCK)
                let mut g = p.foreign.lock();
                match g.fds.get_mut(i).and_then(|s| s.as_mut()).map(|f| &mut f.data) {
                    Some(vfs::Data::Pipe(pe)) => pe.nonblock = nb,
                    Some(vfs::Data::Event(e)) => e.nonblock = nb,
                    _ => {}
                }
            }
            0
        }
        0 | 1030 => dup_from(p, fd, arg),  // F_DUPFD / F_DUPFD_CLOEXEC
        _ => -EINVAL,
    }
}

fn sys_ioctl(p: &Arc<Process>, fd: u64, req: u64, arg: u64) -> i64 {
    let fd = rd(p, fd);
    if fd > 2 {
        if req == 0x541B {
            if let Some(r) = super::linux_net::fionread(p, fd, arg) {
                return r;
            }
        }
        if req == 0x5421 {
            // FIONBIO on a socket
            let mut b = [0u8; 4];
            if let (Some(i), Ok(())) = (fd_slot(fd), copy_from_user(p, &mut b, arg)) {
                return match super::sock::set_nonblock(p, i, u32::from_ne_bytes(b) != 0) {
                    Ok(()) => 0,
                    Err(e) => -e,
                };
            }
        }
        return -ENOTTY;
    }
    match req {
        0x5401 => match copy_to_user(p, arg, &[0u8; 36]) {
            // TCGETS: pretend to be a terminal (glibc then line-buffers stdout)
            Ok(()) => 0,
            Err(e) => -e,
        },
        0x5413 => {
            // TIOCGWINSZ: 24 rows x 80 cols
            let mut w = [0u8; 8];
            w[0..2].copy_from_slice(&24u16.to_le_bytes());
            w[2..4].copy_from_slice(&80u16.to_le_bytes());
            match copy_to_user(p, arg, &w) {
                Ok(()) => 0,
                Err(e) => -e,
            }
        }
        _ => -ENOTTY,
    }
}

fn sys_prlimit(p: &Arc<Process>, old: u64) -> i64 {
    if old != 0 {
        let mut r = [0u8; 16];
        r[..8].copy_from_slice(&(8u64 << 20).to_le_bytes());
        r[8..].copy_from_slice(&u64::MAX.to_le_bytes());
        if let Err(e) = copy_to_user(p, old, &r) {
            return -e;
        }
    }
    0
}

fn sys_getrlimit(p: &Arc<Process>, buf: u64) -> i64 {
    sys_prlimit(p, buf)
}

fn sys_sched_getaffinity(p: &Arc<Process>, len: u64, buf: u64) -> i64 {
    if len < 8 {
        return -EINVAL;
    }
    match copy_to_user(p, buf, &1u64.to_le_bytes()) {
        Ok(()) => 8,
        Err(e) => -e,
    }
}

fn sys_clock_nanosleep(p: &Arc<Process>, flags: u64, req: u64, rem: u64) -> i64 {
    sleep_for(p, req, rem, flags & 1 != 0)
}

fn sys_sysinfo(p: &Arc<Process>, buf: u64) -> i64 {
    let mut si = [0u8; 112];
    si[0..8].copy_from_slice(&(time::uptime_ms() / 1000).to_le_bytes()); // uptime
    si[32..40].copy_from_slice(&(256u64 << 20).to_le_bytes()); // totalram
    si[40..48].copy_from_slice(&(128u64 << 20).to_le_bytes()); // freeram
    si[80..82].copy_from_slice(&1u16.to_le_bytes()); // procs
    si[104..108].copy_from_slice(&1u32.to_le_bytes()); // mem_unit
    match copy_to_user(p, buf, &si) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

const EACCES_: i64 = 13;
const EISDIR_: i64 = 21;
const ENOTDIR_: i64 = 20;

fn sys_unlink(p: &Arc<Process>, path: u64) -> i64 {
    sys_unlinkat(p, AT_FDCWD as u64, path, 0)
}

fn sys_unlinkat(p: &Arc<Process>, dirfd: u64, path: u64, flags: u64) -> i64 {
    if flags & 0x200 != 0 {
        return sys_rmdirat(p, dirfd, path);
    }
    let path = match user_path_at(p, dirfd, path) {
        Ok(s) => s,
        Err(e) => return -e,
    };
    match vfs::unlink(p, &path) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

fn sys_ftruncate(p: &Arc<Process>, fd: u64, len: u64) -> i64 {
    let Some(i) = fd_slot(fd) else { return -EINVAL };
    let mut g = p.foreign.lock();
    match g.fds.get_mut(i).and_then(|s| s.as_mut()) {
        Some(f) => match &mut f.data {
            vfs::Data::Buf(b) if (len as usize) <= crate::store::MAX_FILE_BYTES => {
                b.resize(len as usize, 0);
                f.dirty = true;
                0
            }
            _ => -EINVAL,
        },
        None => -EBADF,
    }
}

/// getdents64: `struct linux_dirent64 { u64 ino; i64 off; u16 reclen; u8 type; char name[]; }`, 8-byte aligned.
fn sys_getdents64(p: &Arc<Process>, fd: u64, buf: u64, size: u64) -> i64 {
    let Some(i) = fd_slot(fd) else { return -ENOTDIR_ };
    let mut out: Vec<u8> = Vec::new();
    {
        let mut g = p.foreign.lock();
        let Some(Some(f)) = g.fds.get_mut(i) else { return -EBADF };
        let vfs::Data::Dir(names) = &f.data else { return -ENOTDIR_ };
        while f.pos < names.len() {
            let raw = names[f.pos].as_str();
            let is_dir = raw.ends_with('/') || raw == "." || raw == "..";
            let nm = raw.trim_end_matches('/').as_bytes();
            let reclen = (19 + nm.len() + 1 + 7) & !7;
            if out.len() + reclen > size as usize {
                break;
            }
            let start = out.len();
            out.extend_from_slice(&((f.pos as u64) + 1).to_le_bytes()); // d_ino
            out.extend_from_slice(&((f.pos as u64) + 1).to_le_bytes()); // d_off
            out.extend_from_slice(&(reclen as u16).to_le_bytes());
            out.push(if is_dir { 4 } else { 8 }); // DT_DIR / DT_REG
            out.extend_from_slice(nm);
            out.resize(start + reclen, 0);
            f.pos += 1;
        }
        if out.is_empty() && f.pos < names.len() {
            return -EINVAL; // buffer too small for even one entry
        }
    }
    match copy_to_user(p, buf, &out) {
        Ok(()) => out.len() as i64,
        Err(e) => -e,
    }
}

// ----------------------------------------------------------------- threads ---

const ENOSYS_: i64 = 38;

fn futex_key(p: &Process, uaddr: u64) -> Result<u64, i64> {
    use x86_64::VirtAddr;
    if uaddr % 4 != 0 || !is_user_range(uaddr, 4) {
        return Err(14); // EFAULT
    }
    let mut g = p.space.lock();
    let sp = g.as_mut().ok_or(14i64)?;
    sp.translate_user(VirtAddr::new(uaddr), false).map(|pa| pa.as_u64()).ok_or(14)
}

/// clone(CLONE_VM|CLONE_THREAD...): a new thread in this process. fork-style clones are not supported.
fn sys_clone(p: &Arc<Process>, f: &SyscallFrame, flags: u64, stack: u64, ptid: u64, ctid: u64, tls: u64) -> i64 {
    const VM: u64 = 0x100;
    const THREAD: u64 = 0x10000;
    const SETTLS: u64 = 0x80000;
    const PARENT_SETTID: u64 = 0x100000;
    const CHILD_CLEARTID: u64 = 0x200000;
    const CHILD_SETTID: u64 = 0x0100_0000;
    if flags & VM == 0 || flags & THREAD == 0 {
        // fork-like (fork, vfork, posix_spawn's CLONE_VM|CLONE_VFORK): a new process
        let r = super::linux_proc::fork(p, f, stack, flags & 0x4000 != 0);
        if r > 0 && flags & PARENT_SETTID != 0 && ptid != 0 {
            let _ = copy_to_user(p, ptid, &(r as u32).to_le_bytes());
        }
        return r;
    }
    if stack == 0 || !is_user_range(stack.saturating_sub(16), 16) {
        return -EINVAL;
    }
    if p.foreign.lock().nthreads >= 32 {
        return -11; // EAGAIN
    }
    let fs = if flags & SETTLS != 0 { tls } else { task::sched::current().fs_base.load(core::sync::atomic::Ordering::Relaxed) };
    let Some(tid) = task::spawn_user_thread_full(p, "lthread", f.rip, stack, 0, 0, fs) else { return -ENOMEM };
    p.foreign.lock().nthreads += 1;
    if flags & PARENT_SETTID != 0 {
        let _ = copy_to_user(p, ptid, &(tid as u32).to_le_bytes());
    }
    if flags & CHILD_SETTID != 0 {
        let _ = copy_to_user(p, ctid, &(tid as u32).to_le_bytes());
    }
    if flags & CHILD_CLEARTID != 0 {
        p.foreign.lock().clear_tids.push((tid, ctid));
    }
    tid as i64
}

fn sys_set_tid_address(p: &Arc<Process>, addr: u64) -> i64 {
    let tid = task::current_ids().1;
    let mut g = p.foreign.lock();
    g.clear_tids.retain(|(t, _)| *t != tid);
    if addr != 0 {
        g.clear_tids.push((tid, addr));
    }
    tid as i64
}

/// exit(): ends only the calling thread (zeroing + waking its CLEARTID word); the last thread ends the process.
fn sys_thread_exit(p: &Arc<Process>) -> i64 {
    let tid = task::current_ids().1;
    let addr = {
        let mut g = p.foreign.lock();
        g.nthreads = g.nthreads.saturating_sub(1);
        g.clear_tids.iter().position(|(t, _)| *t == tid).map(|i| g.clear_tids.remove(i).1)
    };
    if let Some(a) = addr {
        let _ = copy_to_user(p, a, &0u32.to_le_bytes());
        if let Ok(key) = futex_key(p, a) {
            task::sched::futex_wake(key, usize::MAX >> 1);
        }
    }
    let last = p.foreign.lock().nthreads == 0;
    if last {
        super::vfs::flush_all(p);
    }
    task::sched::exit_thread()
}

fn timespec_ms(p: &Arc<Process>, ptr: u64) -> Option<u64> {
    let mut b = [0u8; 16];
    copy_from_user(p, &mut b, ptr).ok()?;
    let s = u64::from_le_bytes(b[..8].try_into().ok()?);
    let ns = u64::from_le_bytes(b[8..].try_into().ok()?);
    Some(s.saturating_mul(1000).saturating_add(ns / 1_000_000))
}

fn sys_futex(p: &Arc<Process>, uaddr: u64, op: u64, val: u64, timeout: u64) -> i64 {
    let cmd = op & 0x7F;
    match cmd {
        0 | 9 => {
            // WAIT / WAIT_BITSET
            let key = match futex_key(p, uaddr) {
                Ok(k) => k,
                Err(e) => return -e,
            };
            let mut w = [0u8; 4];
            if let Err(e) = copy_from_user(p, &mut w, uaddr) {
                return -e;
            }
            if u32::from_ne_bytes(w) != val as u32 {
                return -EAGAIN;
            }
            if timeout == 0 {
                task::sched::futex_block(key); // woken by FUTEX_WAKE (or CLEARTID at thread exit)
                return 0;
            }
            let Some(mut ms) = timespec_ms(p, timeout) else { return -14 };
            if cmd == 9 {
                // absolute deadline
                let now = if op & 256 != 0 { time::unix_ms() } else { time::uptime_ms() };
                ms = ms.saturating_sub(now);
            }
            let t0 = time::uptime_ms();
            loop {
                if copy_from_user(p, &mut w, uaddr).is_ok() && u32::from_ne_bytes(w) != val as u32 {
                    return 0;
                }
                if time::uptime_ms().saturating_sub(t0) >= ms {
                    return -110; // ETIMEDOUT
                }
                task::sleep_ms(1);
            }
        }
        1 | 10 => match futex_key(p, uaddr) {
            Ok(k) => task::sched::futex_wake(k, (val as u32 as usize).min(1 << 20)) as i64,
            Err(e) => -e,
        },
        _ => 0,
    }
}

// ----------------------------------------------------------- pipes / dup ---

fn sys_pipe2(p: &Arc<Process>, fds: u64, flags: u64) -> i64 {
    let (mut r, mut w) = vfs::new_pipe();
    if flags & 0x800 != 0 {
        for e in [&mut r, &mut w] {
            if let vfs::Data::Pipe(pe) = &mut e.data {
                pe.nonblock = true;
            }
        }
    }
    let (ri, wi) = match (vfs::alloc(p, r), vfs::alloc(p, w)) {
        (Ok(a), Ok(b)) => (a, b),
        (Ok(a), Err(e)) => {
            let _ = vfs::close(p, a);
            return -e;
        }
        (Err(e), _) => return -e,
    };
    let mut b = [0u8; 8];
    b[..4].copy_from_slice(&((ri + 3) as u32).to_le_bytes());
    b[4..].copy_from_slice(&((wi + 3) as u32).to_le_bytes());
    match copy_to_user(p, fds, &b) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

fn dup_into(p: &Arc<Process>, old: u64, new_slot: Option<usize>) -> i64 {
    let Some(i) = fd_slot(old) else { return -EBADF };
    let copy = {
        let g = p.foreign.lock();
        match g.fds.get(i).and_then(|s| s.as_ref()) {
            Some(f) => vfs::clone_open(f),
            None => return -EBADF,
        }
    };
    let Some(c) = copy else { return -EBADF };
    match new_slot {
        None => match vfs::alloc(p, c) {
            Ok(n) => n as i64 + 3,
            Err(e) => -e,
        },
        Some(n) => {
            if n >= vfs::MAX_FDS {
                return -EBADF;
            }
            let mut g = p.foreign.lock();
            while g.fds.len() <= n {
                g.fds.push(None);
            }
            g.fds[n] = Some(c);
            n as i64 + 3
        }
    }
}

fn sys_dup(p: &Arc<Process>, old: u64) -> i64 {
    dup_into(p, old, None)
}

fn sys_dup2(p: &Arc<Process>, old: u64, new: u64) -> i64 {
    if old == new {
        return new as i64;
    }
    if new < 3 {
        // redirect stdin/stdout/stderr: keep a private copy of the source file as the alias target
        let src = rd(p, old);
        let copy = match fd_slot(src) {
            None => None, // dup2(console, n): back to the console
            Some(i) => {
                let g = p.foreign.lock();
                match g.fds.get(i).and_then(|s| s.as_ref()) {
                    Some(f) => match vfs::clone_open(f) {
                        Some(c) => Some(c),
                        None => return -EINVAL,
                    },
                    None => return -EBADF,
                }
            }
        };
        let slot = match copy {
            Some(c) => match vfs::alloc(p, c) {
                Ok(s) => Some(s),
                Err(e) => return -e,
            },
            None => None,
        };
        let old_slot = core::mem::replace(&mut p.foreign.lock().redirect[new as usize], slot);
        if let Some(s) = old_slot {
            let _ = vfs::close(p, s);
        }
        return new as i64;
    }
    match fd_slot(new) {
        Some(n) => dup_into(p, old, Some(n)),
        None => -EBADF,
    }
}

pub(super) fn poll_ready(p: &Arc<Process>, fd: i32, events: i16) -> i16 {
    const IN: i16 = 1;
    const OUT: i16 = 4;
    const HUP: i16 = 0x10;
    const NVAL: i16 = 0x20;
    if fd < 0 {
        return 0;
    }
    let fd = rd(p, fd as u64) as i32;
    let Some(i) = fd_slot(fd as u64) else {
        return match fd {
            0 => if events & IN != 0 && (crate::tty::has_input() || !p.foreign.lock().stdin_buf.is_empty()) { IN } else { 0 },
            1 | 2 => events & OUT,
            _ => NVAL,
        };
    };
    if super::sock::is_sock(p, i) {
        let (r, w) = super::sock::readiness(p, i);
        let hup = if super::sock::hangup(p, i) { HUP | 8 } else { 0 };
        return (if r { events & IN } else { 0 }) | (if w { events & OUT } else { 0 }) | hup;
    }
    let g = p.foreign.lock();
    match g.fds.get(i).and_then(|s| s.as_ref()) {
        None => NVAL,
        Some(f) => match &f.data {
            vfs::Data::Pipe(pe) => {
                if pe.write {
                    events & OUT
                } else if pe.readable() {
                    let hup = if pe.buf.writers.load(core::sync::atomic::Ordering::SeqCst) == 0 { HUP } else { 0 };
                    (events & IN) | hup
                } else {
                    0
                }
            }
            vfs::Data::Event(ev) => (if ev.counter.load(core::sync::atomic::Ordering::SeqCst) > 0 { events & IN } else { 0 }) | (events & OUT),
            _ => events & (IN | OUT),
        },
    }
}

fn do_poll(p: &Arc<Process>, fds: u64, n: u64, timeout_ms: i64) -> i64 {
    let n = n.min(64) as usize;
    let t0 = time::uptime_ms();
    loop {
        let mut ready = 0;
        for k in 0..n {
            let mut b = [0u8; 8];
            if let Err(e) = copy_from_user(p, &mut b, fds + k as u64 * 8) {
                return -e;
            }
            let fd = i32::from_le_bytes(b[..4].try_into().unwrap());
            let ev = i16::from_le_bytes(b[4..6].try_into().unwrap());
            let rev = poll_ready(p, fd, ev);
            b[6..8].copy_from_slice(&rev.to_le_bytes());
            let _ = copy_to_user(p, fds + k as u64 * 8, &b);
            if rev != 0 {
                ready += 1;
            }
        }
        if ready > 0 || timeout_ms == 0 || (timeout_ms > 0 && time::uptime_ms().saturating_sub(t0) >= timeout_ms as u64) {
            return ready;
        }
        if super::signals::interrupted(p) {
            return -super::signals::EINTR;
        }
        task::sleep_ms(1);
    }
}

fn sys_poll(p: &Arc<Process>, fds: u64, n: u64, timeout: i32) -> i64 {
    do_poll(p, fds, n, timeout as i64)
}

fn sys_ppoll(p: &Arc<Process>, fds: u64, n: u64, ts: u64) -> i64 {
    let t = if ts == 0 { -1 } else { timespec_ms(p, ts).map_or(-1, |m| m as i64) };
    do_poll(p, fds, n, t)
}

// ----------------------------------------------------------------- sockets ---


/// F_DUPFD: duplicate `fd` into the lowest free descriptor >= `min`.
fn dup_from(p: &Arc<Process>, fd: u64, min: u64) -> i64 {
    let Some(i) = fd_slot(fd) else { return -EBADF };
    let mut g = p.foreign.lock();
    let Some(Some(f)) = g.fds.get(i) else { return -EBADF };
    let Some(copy) = vfs::clone_open(f) else { return -EINVAL };
    let start = (min as usize).saturating_sub(3);
    while g.fds.len() < start {
        g.fds.push(None);
    }
    for k in start..g.fds.len() {
        if g.fds[k].is_none() {
            g.fds[k] = Some(copy);
            return k as i64 + 3;
        }
    }
    if g.fds.len() >= 1024 {
        return -24;
    }
    g.fds.push(Some(copy));
    g.fds.len() as i64 + 2
}

fn sys_eventfd(p: &Arc<Process>, init: u64, flags: u64) -> i64 {
    let f = vfs::OpenFile {
        name: alloc::string::String::from("eventfd"),
        data: vfs::Data::Event(vfs::EventFd { counter: Arc::new(core::sync::atomic::AtomicU64::new(init as u32 as u64)), semaphore: flags & 1 != 0, nonblock: flags & 0x800 != 0 }),
        pos: 0,
        writable: true,
        dirty: false,
        eof: false,
    };
    match vfs::alloc(p, f) {
        Ok(i) => i as i64 + 3,
        Err(e) => -e,
    }
}

fn sys_readv(p: &Arc<Process>, fd: u64, iov: u64, cnt: u64) -> i64 {
    if cnt > 64 {
        return -EINVAL;
    }
    let mut total = 0i64;
    for i in 0..cnt {
        let mut ent = [0u8; 16];
        if let Err(e) = copy_from_user(p, &mut ent, iov + i * 16) {
            return -e;
        }
        let base = u64::from_le_bytes(ent[..8].try_into().unwrap());
        let len = u64::from_le_bytes(ent[8..].try_into().unwrap());
        if len == 0 {
            continue;
        }
        let r = sys_read(p, fd, base, len.min(1 << 20));
        if r < 0 {
            return if total > 0 { total } else { r };
        }
        total += r;
        if (r as u64) < len {
            break;
        }
    }
    total
}

fn sys_pwrite(p: &Arc<Process>, fd: u64, buf: u64, len: u64, off: u64) -> i64 {
    let Some(i) = fd_slot(fd) else { return -ESPIPE_ };
    let mut tmp = alloc::vec![0u8; (len as usize).min(64 * 1024)];
    if let Err(e) = copy_from_user(p, &mut tmp, buf) {
        return -e;
    }
    let mut g = p.foreign.lock();
    match g.fds.get_mut(i).and_then(|s| s.as_mut()) {
        Some(f) => {
            let save = f.pos;
            f.pos = off as usize;
            let r = vfs::write(f, &tmp);
            f.pos = save;
            match r {
                Ok(n) => n as i64,
                Err(e) => -e,
            }
        }
        None => -EBADF,
    }
}

/// statfs/fstatfs: a plausible filesystem (struct statfs, 120 bytes).
fn sys_statfs(p: &Arc<Process>, out: u64) -> i64 {
    let mut b = [0u8; 120];
    b[0..8].copy_from_slice(&0xEF53u64.to_le_bytes()); // f_type
    b[8..16].copy_from_slice(&4096u64.to_le_bytes()); // f_bsize
    b[16..24].copy_from_slice(&65536u64.to_le_bytes()); // f_blocks
    b[24..32].copy_from_slice(&32768u64.to_le_bytes()); // f_bfree
    b[32..40].copy_from_slice(&32768u64.to_le_bytes()); // f_bavail
    b[40..48].copy_from_slice(&1024u64.to_le_bytes()); // f_files
    b[48..56].copy_from_slice(&512u64.to_le_bytes()); // f_ffree
    b[72..80].copy_from_slice(&255u64.to_le_bytes()); // f_namelen
    b[80..88].copy_from_slice(&4096u64.to_le_bytes()); // f_frsize
    match copy_to_user(p, out, &b) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

/// sendfile(out, in, *offset, count): copy through a bounce buffer.
fn sys_sendfile(p: &Arc<Process>, out_fd: u64, in_fd: u64, off_p: u64, count: u64) -> i64 {
    let count = count.min(1 << 20) as usize;
    let mut tmp = alloc::vec![0u8; count];
    let got = {
        let Some(i) = fd_slot(in_fd) else { return -EBADF };
        let mut g = p.foreign.lock();
        let Some(f) = g.fds.get_mut(i).and_then(|s| s.as_mut()) else { return -EBADF };
        let save = f.pos;
        if off_p != 0 {
            let mut ob = [0u8; 8];
            if copy_from_user(p, &mut ob, off_p).is_err() {
                return -EFAULT;
            }
            f.pos = u64::from_le_bytes(ob) as usize;
        }
        let n = vfs::read(f, &mut tmp);
        if off_p != 0 {
            let newpos = f.pos as u64;
            f.pos = save;
            let _ = copy_to_user(p, off_p, &newpos.to_le_bytes());
        }
        n
    };
    // write through a scratch user buffer is not possible; write via the fd helpers directly
    let Some(o) = fd_slot(out_fd) else { return got as i64 };
    if super::sock::is_sock(p, o) {
        return match super::sock::send(p, o, &tmp[..got], false) {
            Ok(n) => n as i64,
            Err(e) => -e,
        };
    }
    let mut g = p.foreign.lock();
    match g.fds.get_mut(o).and_then(|s| s.as_mut()) {
        Some(f) => match vfs::write(f, &tmp[..got]) {
            Ok(n) => n as i64,
            Err(e) => -e,
        },
        None => -EBADF,
    }
}
