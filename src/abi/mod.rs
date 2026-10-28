//! Foreign-ABI compatibility layers (`deloxy-wltd`): Linux x86_64 syscalls and a
//! Win32 (kernel32) shim, both translated onto native Deloxy mechanisms
//! (address-space mappings, the console capability, the scheduler).
//!
//! No ambient authority: stdout/stderr of a foreign process exist only if it was
//! launched with a `Console` capability; everything else is per-process state.

pub mod linux;
pub mod linux_net;
pub mod linux_proc;
pub mod signals;
pub mod msvcrt;
pub mod win32;
pub mod winmath;
pub mod winsock;
pub mod win_extra;
pub mod win32_thr;
pub mod nt;
pub mod sock;
pub mod vfs;

use alloc::string::String;
use alloc::sync::Arc;

use crate::cap::{CapObject, Rights};
use crate::sys::errno::{EBADF, EPERM};
use crate::task::Process;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum AbiKind {
    Native = 0,
    Linux = 1,
    Nt = 2,
}

impl AbiKind {
    pub fn from_u8(v: u8) -> AbiKind {
        match v {
            1 => AbiKind::Linux,
            2 => AbiKind::Nt,
            _ => AbiKind::Native,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            AbiKind::Native => "native",
            AbiKind::Linux => "linux",
            AbiKind::Nt => "nt",
        }
    }
}

pub const OUT_CAPTURE: usize = 160;

pub enum KObj {
    Thread { tid: u64, done: bool, code: u32 },
    Event { manual: bool, set: bool },
    Mutex { owner: u64, count: u32 },
    Sem { count: i32, max: i32 },
}

pub struct ForeignState {
    pub image_base: u64,
    pub brk_base: u64,
    pub brk: u64,
    pub brk_mapped: u64,
    pub last_error: u32,
    pub tls: [u64; 64],
    pub tls_used: u64,
    pub heap_next: u64,
    /// child processes started with fork/vfork (waited for with wait4)
    pub children: alloc::vec::Vec<alloc::sync::Arc<crate::task::Process>>,
    /// this process has called execve (a vfork parent resumes when its child does)
    pub execed: bool,
    /// working directory: canonical path without a leading slash ("" = the root)
    pub cwd: alloc::string::String,
    /// signal dispositions, mask, pending set and timers (see `signals`)
    pub sig: signals::SigState,
    /// the process that forked us (gets SIGCHLD when we exit)
    pub parent: Option<alloc::sync::Weak<crate::task::Process>>,
    pub chld_sent: bool,
    /// signal that terminated this process via kill(2) (0 = it exited normally or crashed)
    pub killed_sig: u8,
    /// dup2/dup3 onto fd 0..2: descriptor slot that stdin/stdout/stderr currently alias (None = the console)
    pub redirect: [Option<usize>; 3],
    /// per-process scratch for wide->narrow argument conversion, cached UTF-16 command line, struct tm buffer, strtok state
    pub wscratch: u64,
    pub cmdline_w: Option<u64>,
    pub tm_buf: u64,
    pub strtok_save: u64,
    /// freed heap blocks by capacity (size class), reused by `heap_alloc`
    pub heap_free: alloc::collections::BTreeMap<u64, alloc::vec::Vec<u64>>,
    pub heap_end: u64,
    pub rng: u64,
    pub cmdline_va: u64,
    /// Handle of the Console capability (0 = none).
    pub console: u64,
    /// File access granted by capabilities (see `vfs`).
    pub fs_dir: bool,
    pub fs_store_read: bool,
    pub fs_store_write: bool,
    pub fds: alloc::vec::Vec<Option<vfs::OpenFile>>,
    /// NT: user rsp at the last shim call (to read stack arguments), argc/argv of the process.
    pub nt_rsp: u64,
    /// Bytes of an already-read input line that the program has not consumed yet.
    pub stdin_buf: alloc::vec::Vec<u8>,
    pub stdin_eof: bool,
    /// Linux CLONE_CHILD_CLEARTID: (thread id, user address to zero + futex-wake at thread exit)
    pub clear_tids: alloc::vec::Vec<(u64, u64)>,
    pub nthreads: u32,
    /// file capabilities were offered but the user's decision has not been resolved yet (see `perm`)
    pub fs_pending: bool,
    /// this run's network grants, one per rule scope (so time/data limits cover the whole run)
    pub net_grants: alloc::vec::Vec<(crate::perm::Dest, alloc::sync::Arc<crate::net::NetGrant>)>,
    /// network scopes answered "once"/"no" during this run (see `perm::resolve_scope`)
    pub net_asked: alloc::vec::Vec<(([u8; 4], u16), Option<crate::perm::NetRule>)>,
    pub prog_name: alloc::string::String,
    pub prog_hash: alloc::string::String,
    /// PE static TLS template (start, end, zero fill, index VA) for new threads
    pub tls_tmpl: Option<(u64, u64, u32, u64)>,
    /// Windows kernel objects (threads, events, mutexes, semaphores), handles 0x2000 + 4*index
    pub kobjs: alloc::vec::Vec<Option<KObj>>,
    /// per-thread TlsAlloc values
    pub tls_threads: alloc::vec::Vec<(u64, [u64; 64])>,
    pub argc: u64,
    pub argv_va: u64,
    warned: [u16; 16],
    warned_n: usize,
    /// First bytes written to the console (lets tests check a program's output).
    pub out: [u8; OUT_CAPTURE],
    pub out_len: usize,
}

impl ForeignState {
    /// State of a forked child: the parent's memory layout bookkeeping, a copy of its descriptors (sockets are not
    /// inherited), its permission identity and this run's already-resolved decisions.
    pub fn fork_clone(&self) -> ForeignState {
        let mut n = ForeignState::new();
        n.image_base = self.image_base;
        n.brk_base = self.brk_base;
        n.brk = self.brk;
        n.brk_mapped = self.brk_mapped;
        n.tls = self.tls;
        n.tls_used = self.tls_used;
        n.heap_next = self.heap_next;
        n.heap_end = self.heap_end;
        n.heap_free = self.heap_free.clone();
        n.redirect = self.redirect;
        n.wscratch = self.wscratch;
        n.cmdline_va = self.cmdline_va;
        n.cmdline_w = self.cmdline_w;
        n.tm_buf = self.tm_buf;
        n.console = self.console;
        n.fs_dir = self.fs_dir;
        n.fs_store_read = self.fs_store_read;
        n.fs_store_write = self.fs_store_write;
        n.fs_pending = self.fs_pending;
        n.nt_rsp = self.nt_rsp;
        n.net_grants = self.net_grants.clone();
        n.net_asked = self.net_asked.clone();
        n.prog_name = self.prog_name.clone();
        n.prog_hash = self.prog_hash.clone();
        n.tls_tmpl = self.tls_tmpl;
        n.argc = self.argc;
        n.argv_va = self.argv_va;
        n.sig.actions = self.sig.actions; // handlers, masks and the signal mask are inherited; pending signals and timers are not
        n.sig.mask = self.sig.mask;
        n.cwd = self.cwd.clone();
        n.nthreads = 1;
        n.fds = self.fds.iter().map(|f| f.as_ref().and_then(vfs::clone_open)).collect();
        n.stdin_buf = self.stdin_buf.clone();
        n
    }

    /// execve: forget everything tied to the old program image and its identity. Descriptors and stdio redirections
    /// survive. Network decisions and grants do **not**: the new program must earn its own.
    pub fn reset_for_exec(&mut self) {
        self.image_base = 0;
        self.brk_base = 0;
        self.brk = 0;
        self.brk_mapped = 0;
        self.tls = [0; 64];
        self.tls_used = 0;
        self.heap_next = 0;
        self.heap_end = 0;
        self.heap_free.clear();
        self.wscratch = 0;
        self.cmdline_w = None;
        self.tm_buf = 0;
        self.strtok_save = 0;
        self.net_grants.clear();
        self.net_asked.clear();
        self.clear_tids.clear();
        self.nthreads = 1;
        self.tls_tmpl = None;
        self.kobjs.clear();
        self.tls_threads.clear();
        // the new program is offered file access again and resolved under its own name + hash
        self.fs_dir = true;
        self.fs_store_read = true;
        self.fs_store_write = true;
        self.fs_pending = true;
        self.execed = true;
        // caught signals revert to the default (the handler code is gone); ignored ones stay ignored; mask and pending survive
        for a in self.sig.actions.iter_mut() {
            if a.handler > signals::SIG_IGN {
                *a = signals::SigAction { handler: signals::SIG_DFL, flags: 0, restorer: 0, mask: 0 };
            }
        }
        self.sig.saved_mask = None;
    }

    pub const fn new() -> ForeignState {
        ForeignState {
            image_base: 0,
            brk_base: 0,
            brk: 0,
            brk_mapped: 0,
            last_error: 0,
            tls: [0; 64],
            tls_used: 0,
            heap_next: 0,
            children: alloc::vec::Vec::new(),
            execed: false,
            cwd: alloc::string::String::new(),
            sig: signals::SigState::new(),
            parent: None,
            chld_sent: false,
            killed_sig: 0,
            redirect: [None; 3],
            wscratch: 0,
            cmdline_w: None,
            tm_buf: 0,
            strtok_save: 0,
            heap_free: alloc::collections::BTreeMap::new(),
            heap_end: 0,
            rng: 0x9E37_79B9_7F4A_7C15,
            cmdline_va: 0,
            console: 0,
            fs_dir: false,
            fs_store_read: false,
            fs_store_write: false,
            fds: alloc::vec::Vec::new(),
            nt_rsp: 0,
            stdin_buf: alloc::vec::Vec::new(),
            stdin_eof: false,
            clear_tids: alloc::vec::Vec::new(),
            nthreads: 1,
            fs_pending: false,
            net_grants: alloc::vec::Vec::new(),
            net_asked: alloc::vec::Vec::new(),
            prog_name: alloc::string::String::new(),
            prog_hash: alloc::string::String::new(),
            tls_tmpl: None,
            kobjs: alloc::vec::Vec::new(),
            tls_threads: alloc::vec::Vec::new(),
            argc: 0,
            argv_va: 0,
            warned: [0; 16],
            warned_n: 0,
            out: [0; OUT_CAPTURE],
            out_len: 0,
        }
    }

    /// True the first time `nr` is reported for this process (log-once helper).
    pub fn first_warning(&mut self, nr: u16) -> bool {
        if self.warned[..self.warned_n].contains(&nr) {
            return false;
        }
        if self.warned_n < self.warned.len() {
            self.warned[self.warned_n] = nr;
            self.warned_n += 1;
        }
        true
    }

    /// Cryptographically strong random word (kernel CSPRNG, see `rand`).
    pub fn next_random(&mut self) -> u64 {
        crate::rand::next_u64()
    }
}

/// Write to the console on behalf of a foreign process. Requires a live Console
/// capability with WRITE; otherwise `-EBADF`/`-EPERM` (and the syscall audit shows a denial).
/// Cooked terminal input for foreign programs: echoes, edits (backspace) and returns one line at a time
/// (up to `max` bytes; the rest stays buffered). Ctrl-D on an empty line is end-of-file (empty result).
/// Requires the process's console capability (the same terminal it writes to).
pub fn stdin_read(p: &Arc<Process>, max: usize) -> Result<alloc::vec::Vec<u8>, i64> {
    if p.foreign.lock().console == 0 {
        return Err(EBADF);
    }
    {
        let mut f = p.foreign.lock();
        if !f.stdin_buf.is_empty() {
            let n = max.min(f.stdin_buf.len());
            return Ok(f.stdin_buf.drain(..n).collect());
        }
    }
    let mut line: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut b = [0u8; 1];
    loop {
        if crate::tty::read_input(&mut b) == 0 {
            crate::task::sleep_ms(2);
            continue;
        }
        match b[0] {
            b'\r' | b'\n' => {
                line.push(b'\n');
                let _ = console_write(p, "stdin", b"\r\n");
                break;
            }
            0x04 => {
                if line.is_empty() {
                    return Ok(alloc::vec::Vec::new());
                }
                break;
            }
            0x08 | 0x7F => {
                if line.pop().is_some() {
                    let _ = console_write(p, "stdin", b"\x08 \x08");
                }
            }
            c if (0x20..0x7F).contains(&c) => {
                line.push(c);
                let _ = console_write(p, "stdin", &[c]);
            }
            _ => {}
        }
        if line.len() >= 4000 {
            break;
        }
    }
    let n = max.min(line.len());
    let rest = line.split_off(n);
    p.foreign.lock().stdin_buf = rest;
    Ok(line)
}

pub fn console_write(p: &Arc<Process>, tag: &str, bytes: &[u8]) -> Result<(), i64> {
    let h = p.foreign.lock().console;
    if h == 0 {
        return Err(EBADF);
    }
    match p.caps.lock().lookup(h, Rights::WRITE) {
        Ok((CapObject::Console, _)) => {}
        Ok(_) => return Err(EPERM),
        Err(e) => return Err(e),
    }
    {
        let mut f = p.foreign.lock();
        let n = bytes.len().min(OUT_CAPTURE - f.out_len);
        let at = f.out_len;
        f.out[at..at + n].copy_from_slice(&bytes[..n]);
        f.out_len += n;
    }
    // Foreign stdout/stderr go to the kernel TTY (serial + screen + the shell's terminal), raw.
    let _ = tag;
    crate::tty::write(bytes);
    Ok(())
}

/// Unmap a whole region recorded in the process's mapping list. Returns true on success.
pub fn unmap_region(p: &Arc<Process>, addr: u64, pages: usize) -> bool {
    use crate::mm::layout::PAGE_SIZE;
    use x86_64::VirtAddr;
    let owned = {
        let mut m = p.mappings.lock();
        match m.iter().position(|r| r.va == addr && r.pages == pages) {
            Some(i) => m.remove(i).owned,
            None => return false,
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
    true
}
