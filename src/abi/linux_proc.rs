//! Linux process syscalls: fork / vfork / clone (without CLONE_THREAD), execve, wait4, kill.
//!
//! * **fork** copies the caller's anonymous pages into a new `Process` (eagerly: no copy-on-write), clones its
//!   descriptor table (pipes and files are shared/copied, sockets are not inherited), inherits the console/file/TTY
//!   capabilities with the same handle values and starts one thread in the child with the parent's registers and
//!   `rax = 0`. A vfork-style child (CLONE_VFORK, as `posix_spawn` uses) holds the parent until it execs or exits.
//! * **execve** replaces the image of the calling process in place: the program is located in the image/store by file
//!   name, everything that can fail is checked before the old image is destroyed, and the **new program starts with
//!   no network grants and its own permission identity** (name + hash), so nothing the old program was allowed carries over.
//! * **wait4** collects exited children (`WNOHANG`, pid or any), returning `(exit code << 8)` as the wait status.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::vfs;
use crate::arch::x86_64::syscall::{SyscallFrame, UserRegs};
use crate::sys::uaccess::{copy_from_user, copy_to_user};
use crate::task::{self, Process};

const ENOENT: i64 = 2;
const ESRCH: i64 = 3;
const EPERM: i64 = 1;
const ECHILD: i64 = 10;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENOEXEC: i64 = 8;
const E2BIG: i64 = 7;

fn read_cstr(p: &Arc<Process>, va: u64, max: usize) -> Result<String, i64> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    while out.len() < max {
        copy_from_user(p, &mut b, va + out.len() as u64).map_err(|_| EFAULT)?;
        if b[0] == 0 {
            return Ok(String::from_utf8_lossy(&out).into_owned());
        }
        out.push(b[0]);
    }
    Err(E2BIG)
}

/// NULL-terminated array of C strings (argv / envp).
fn read_str_array(p: &Arc<Process>, va: u64, max_n: usize, max_total: usize) -> Result<Vec<String>, i64> {
    let mut v = Vec::new();
    if va == 0 {
        return Ok(v);
    }
    let mut total = 0usize;
    for i in 0..max_n + 1 {
        let mut w = [0u8; 8];
        copy_from_user(p, &mut w, va + 8 * i as u64).map_err(|_| EFAULT)?;
        let ptr = u64::from_le_bytes(w);
        if ptr == 0 {
            return Ok(v);
        }
        let s = read_cstr(p, ptr, 128 * 1024)?;
        total += s.len() + 1;
        if total > max_total {
            return Err(E2BIG);
        }
        v.push(s);
    }
    Err(E2BIG)
}

pub fn fork(p: &Arc<Process>, f: &SyscallFrame, child_stack: u64, vfork: bool) -> i64 {
    let Some(child) = task::create_process(&p.name) else { return -ENOMEM };
    child.set_abi(p.abi());
    if p.fork_memory_into(&child).is_err() {
        return -ENOMEM; // dropping `child` frees what was copied
    }
    *child.caps.lock() = p.caps.lock().fork_copy();
    let st = p.foreign.lock().fork_clone();
    *child.foreign.lock() = st;
    let regs = UserRegs {
        r15: f.r15, r14: f.r14, r13: f.r13, r12: f.r12, rbp: f.rbp, rbx: f.rbx, r9: f.r9, r8: f.r8, r10: f.r10, rdx: f.rdx, rsi: f.rsi, rdi: f.rdi,
        rip: f.rip,
        rflags: f.rflags,
        rsp: if child_stack != 0 { child_stack } else { f.rsp },
    };
    let (fs, gs) = task::sched::current_tls_bases();
    if task::spawn_user_thread_regs(&child, &p.name, regs, fs, gs).is_none() {
        return -ENOMEM;
    }
    {
        // the child starts in its parent's process group and session, running
        let (pg, sd) = (super::signals::pgid_of(p), super::signals::sid_of(p));
        let mut cg = child.foreign.lock();
        cg.pgid = pg;
        cg.sid = sd;
        cg.stopped = false;
        cg.continued = false;
        cg.stop_reported = false;
        cg.parent = Some(Arc::downgrade(p));
    }
    p.foreign.lock().children.push(child.clone());
    if vfork {
        // the parent resumes when the child execs or exits (the child shares nothing with us here, but callers rely on the ordering)
        while !child.has_exited() && !child.foreign.lock().execed {
            task::sleep_ms(1);
        }
    }
    child.pid as i64
}

/// Locate an executable by path: the shared-library directories, then the image's flat namespace by base name, then
/// the persistent store. Returns (display name, bytes).
fn find_exec(p: &Arc<Process>, path: &str) -> Option<(String, Vec<u8>)> {
    let base = path.rsplit('/').next().unwrap_or(path);
    if base.is_empty() {
        return None;
    }
    if let Some(f) = vfs::system_lib(path).or_else(|| vfs::system_bin(path)) {
        return Some((String::from(base), f.data.to_vec()));
    }
    // a path inside the persistent store (/store/..., /home/..., /opt/...)
    if vfs::pfs_map(&vfs::resolve_abs(p, path)).is_some() {
        if let Ok(f) = vfs::open(p, path, false, false, false, false) {
            if !f.is_dir() {
                return Some((String::from(base), f.bytes().to_vec()));
            }
        }
    }
    // a bare/relative name or any directory prefix: the flat namespace of the image
    if let Some(f) = crate::fs::root().and_then(|r| r.lookup(base)) {
        return Some((String::from(base), f.data.to_vec()));
    }
    let _ = p;
    if let Ok(Ok(d)) = crate::store::with(|s| s.read(base)) {
        return Some((String::from(base), (*d).as_ref().to_vec()));
    }
    None
}

pub fn execve(p: &Arc<Process>, f: &mut SyscallFrame, path_va: u64, argv_va: u64, envp_va: u64) -> i64 {
    let path = match read_cstr(p, path_va, 4096) {
        Ok(s) => s,
        Err(e) => return -e,
    };
    let args = match read_str_array(p, argv_va, 512, 256 * 1024) {
        Ok(v) => v,
        Err(e) => return -e,
    };
    let env = match read_str_array(p, envp_va, 512, 256 * 1024) {
        Ok(v) => v,
        Err(e) => return -e,
    };
    let Some((mut name, mut bytes)) = find_exec(p, &path) else { return -ENOENT };
    let mut args = args;
    // `#!interpreter [arg]` scripts: run the interpreter with the script path (up to 4 levels, like Linux's 5)
    let mut script_path = path.clone();
    for _ in 0..4 {
        if !bytes.starts_with(b"#!") {
            break;
        }
        let line_end = bytes.iter().take(256).position(|&c| c == b'\n').unwrap_or(bytes.len().min(256));
        let line = String::from_utf8_lossy(&bytes[2..line_end]).into_owned();
        let line = line.trim();
        let (interp, opt) = match line.split_once(|c: char| c == ' ' || c == '\t') {
            Some((i, o)) => (i.trim(), Some(o.trim())),
            None => (line, None),
        };
        if interp.is_empty() {
            return -ENOEXEC;
        }
        let Some((n2, b2)) = find_exec(p, interp) else { return -ENOENT };
        let mut na: Vec<String> = alloc::vec![String::from(interp)];
        if let Some(o) = opt.filter(|o| !o.is_empty()) {
            na.push(String::from(o));
        }
        na.push(script_path.clone());
        na.extend(args.iter().skip(1).cloned());
        args = na;
        script_path = String::from(interp);
        name = n2;
        bytes = b2;
    }
    super::vfs::sync_all(p);
    let arg_refs: Vec<&str> = if args.is_empty() { alloc::vec![name.as_str()] } else { args.iter().map(|s| s.as_str()).collect() };
    match crate::exec::exec_replace(p, &name, &bytes, &arg_refs, env) {
        Ok(r) => {
            f.rip = r.rip;
            f.rsp = r.rsp;
            f.rdi = r.arg0;
            f.rsi = 0;
            f.rdx = 0;
            f.r10 = 0;
            f.r8 = 0;
            f.r9 = 0;
            f.rbx = 0;
            f.rbp = 0;
            f.r12 = 0;
            f.r13 = 0;
            f.r14 = 0;
            f.r15 = 0;
            f.rflags = 0x202;
            task::sched::set_current_tls_bases(0, r.gs);
            log::info!("exec: {} (pid {}) now runs {}", p.name, p.pid, name);
            0
        }
        Err((e, false)) => {
            log::debug!("execve {}: {:?}", path, e);
            -ENOEXEC
        }
        Err((e, true)) => {
            // the old image is gone; Linux kills the process in this situation too
            log::warn!("execve {} failed after the old image was destroyed: {:?}", path, e);
            task::sched::exit_process(127)
        }
    }
}

pub fn wait4(p: &Arc<Process>, pid: u64, status_va: u64, options: u64) -> i64 {
    let want = pid as u32 as i32 as i64; // a 32-bit pid_t: -1 arrives as 0xffffffff
    let my_pg = super::signals::pgid_of(p);
    // pid > 0: that child; -1: any; 0: a child in our process group; < -1: a child in group -pid
    let matches = |c: &Arc<Process>| -> bool {
        if want > 0 {
            c.pid as i64 == want
        } else if want == -1 {
            true
        } else if want == 0 {
            super::signals::pgid_of(c) == my_pg
        } else {
            super::signals::pgid_of(c) as i64 == -want
        }
    };
    const WUNTRACED: u64 = 2;
    const WCONTINUED: u64 = 8;
    loop {
        let kids: alloc::vec::Vec<Arc<Process>> = p.foreign.lock().children.clone();
        let cand: alloc::vec::Vec<Arc<Process>> = kids.into_iter().filter(|c| matches(c)).collect();
        if cand.is_empty() {
            return -ECHILD;
        }
        // (child, wait status, remove from the child list?)
        let mut ev: Option<(Arc<Process>, u32, bool)> = None;
        if let Some(c) = cand.iter().find(|c| c.has_exited()) {
            let code = c.exit_code.load(core::sync::atomic::Ordering::SeqCst);
            let ks = c.foreign.lock().killed_sig as i64;
            let st: u32 = if ks != 0 {
                ks as u32 // terminated by signal: low 7 bits
            } else if code < 0 {
                ((-code) as u32) & 0x7F // crashed (e.g. -11 = SIGSEGV)
            } else {
                ((code & 0xFF) as u32) << 8
            };
            ev = Some((c.clone(), st, true));
        } else {
            for c in cand.iter() {
                let mut cg = c.foreign.lock();
                if options & WUNTRACED != 0 && cg.stopped && !cg.stop_reported {
                    cg.stop_reported = true;
                    ev = Some((c.clone(), ((cg.stop_sig as u32) << 8) | 0x7f, false));
                    break;
                }
                if options & WCONTINUED != 0 && cg.continued {
                    cg.continued = false;
                    ev = Some((c.clone(), 0xffff, false));
                    break;
                }
            }
        }
        if let Some((c, st, remove)) = ev {
            if remove {
                p.foreign.lock().children.retain(|x| !Arc::ptr_eq(x, &c));
            }
            if status_va != 0 && copy_to_user(p, status_va, &st.to_le_bytes()).is_err() {
                return -EFAULT;
            }
            return c.pid as i64;
        }
        if options & 1 != 0 {
            return 0; // WNOHANG
        }
        if super::signals::interrupted(p) {
            return -super::signals::ERESTART;
        }
        task::sleep_ms(1);
    }
}

fn find_linux(p: &Arc<Process>, pid: u64) -> Option<Arc<Process>> {
    let pid = pid as u32 as i32 as i64;
    if pid == 0 || pid == p.pid as i64 {
        return Some(p.clone());
    }
    crate::task::list_processes().into_iter().find(|t| t.pid as i64 == pid && !t.has_exited() && t.abi() == super::AbiKind::Linux)
}

/// getpgid(pid) / getsid(pid)
pub fn getpgid(p: &Arc<Process>, pid: u64, session: bool) -> i64 {
    match find_linux(p, pid) {
        Some(t) => (if session { super::signals::sid_of(&t) } else { super::signals::pgid_of(&t) }) as i64,
        None => -ESRCH,
    }
}

/// setpgid(pid, pgid): the caller or one of its children joins (or founds) a group of the same session.
pub fn setpgid(p: &Arc<Process>, pid: u64, pgid: u64) -> i64 {
    let pgid_i = pgid as u32 as i32 as i64;
    if pgid_i < 0 {
        return -EINVAL;
    }
    let Some(t) = find_linux(p, pid) else { return -ESRCH };
    let is_self = Arc::ptr_eq(&t, p);
    if !is_self && !p.foreign.lock().children.iter().any(|c| c.pid == t.pid) {
        return -ESRCH;
    }
    let target_sid = super::signals::sid_of(&t);
    if target_sid == t.pid {
        return -EPERM; // a session leader keeps its group
    }
    if target_sid != super::signals::sid_of(p) {
        return -EPERM;
    }
    let new_pg = if pgid_i == 0 { t.pid } else { pgid_i as u64 };
    if new_pg != t.pid {
        // joining an existing group of the same session
        let ok = crate::task::list_processes().iter().any(|q| !q.has_exited() && super::signals::pgid_of(q) == new_pg && super::signals::sid_of(q) == target_sid);
        if !ok {
            return -EPERM;
        }
    }
    t.foreign.lock().pgid = new_pg;
    0
}

/// setsid(): a new session (and group) led by the caller; fails for a process-group leader.
pub fn setsid(p: &Arc<Process>) -> i64 {
    if super::signals::pgid_of(p) == p.pid {
        return -EPERM;
    }
    let mut g = p.foreign.lock();
    g.sid = p.pid;
    g.pgid = p.pid;
    p.pid as i64
}

/// tkill(tid, sig) / tgkill(tgid, tid, sig): a thread of the caller's own process gets the signal in its *own* pending
/// set (only that thread can take it); other processes are treated like `kill` on the owning process.
pub fn tgkill(p: &Arc<Process>, tgid: Option<u64>, tid: u64, sig: u64) -> i64 {
    if sig > 64 {
        return -EINVAL;
    }
    let Some(t) = crate::task::find_thread(tid) else {
        // old convention: the main thread's tid is the pid
        return if tid == p.pid { kill(p, tid, sig) } else { -ESRCH };
    };
    if tgid.map_or(false, |g| g != t.process.pid) {
        return -ESRCH;
    }
    if !Arc::ptr_eq(&t.process, p) {
        return kill(p, t.process.pid, sig);
    }
    if sig == 0 {
        return 0;
    }
    super::signals::send_thread(p, &t, sig);
    0
}

/// kill(pid, sig) / tkill / tgkill: the caller itself and the processes it started (there are no process groups).
/// Terminating signals take effect immediately on others; for the caller they are delivered when the syscall returns
/// (so a handler or `SIG_IGN` is honoured, e.g. `raise(SIGABRT)`).
pub fn kill(p: &Arc<Process>, pid: u64, sig: u64) -> i64 {
    let pid = pid as u32 as i32 as i64;
    if pid <= 0 {
        // kill(0): the caller's own process group; kill(-pgid): that group; kill(-1): every Linux process we may signal
        if sig > 64 {
            return -EINVAL;
        }
        let pg = if pid == 0 { super::signals::pgid_of(p) } else { (-pid) as u64 };
        let sid = super::signals::sid_of(p);
        let parent_pid = p.foreign.lock().parent.as_ref().and_then(|w| w.upgrade()).map(|q| q.pid);
        let mut hit = 0;
        for t in crate::task::list_processes() {
            if t.has_exited() || t.abi() != super::AbiKind::Linux {
                continue;
            }
            let in_group = pid == -1 && t.pid != p.pid || pid != -1 && super::signals::pgid_of(&t) == pg;
            // allowed: ourselves, our children/parent, or anything in our session
            let allowed = Arc::ptr_eq(&t, p) || Some(t.pid) == parent_pid || super::signals::sid_of(&t) == sid || p.foreign.lock().children.iter().any(|c| c.pid == t.pid);
            if !in_group || !allowed {
                continue;
            }
            hit += 1;
            if sig != 0 {
                if Arc::ptr_eq(&t, p) {
                    super::signals::raise(&t, sig);
                } else {
                    super::signals::send(&t, sig);
                }
            }
        }
        return if hit == 0 { -ESRCH } else { 0 };
    }
    let me = pid == p.pid as i64;
    let target: Option<Arc<Process>> = if me {
        Some(p.clone())
    } else {
        let g = p.foreign.lock();
        g.children.iter().find(|c| c.pid as i64 == pid).cloned().or_else(|| g.parent.as_ref().and_then(|w| w.upgrade()).filter(|par| par.pid as i64 == pid))
    };
    let Some(t) = target else { return -ESRCH };
    if sig == 0 {
        return if t.has_exited() { -ESRCH } else { 0 };
    }
    if sig > 64 {
        return -EINVAL;
    }
    if me {
        super::signals::raise(&t, sig);
    } else {
        super::signals::send(&t, sig);
    }
    0
}
