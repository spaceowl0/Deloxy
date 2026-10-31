//! Files for foreign (Linux/Windows) programs.
//!
//! No ambient authority: a foreign process can only open files if it was started with a `Dir` capability
//! (read-only initramfs) and/or a `Store` capability (persistent store: READ to read, WRITE to create/replace).
//! Paths are flat: `README.txt`, `./notes.txt`, `/notes.txt` and `/store/notes.txt` all name one file; anything with
//! a further `/` or `..` does not exist. Reads look in the initramfs first (system files win), `store/` forces the
//! store. Writes always go to the store, are buffered in memory (max 4 MiB) and committed atomically on close /
//! process exit. `upd.*` is the kernel updater's namespace and can never be written by a foreign program.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::task::Process;

pub const ENOENT: i64 = 2;
pub const EIO: i64 = 5;
pub const EBADF: i64 = 9;
pub const EACCES: i64 = 13;
pub const EISDIR: i64 = 21;
pub const EINVAL: i64 = 22;
pub const EMFILE: i64 = 24;
pub const EFBIG: i64 = 27;
pub const ESPIPE: i64 = 29;
pub const ENOSPC: i64 = 28;
pub const MAX_FDS: usize = 64;

/// An in-memory pipe shared by its two ends.
pub struct PipeBuf {
    pub q: crate::sync::IrqMutex<alloc::collections::VecDeque<u8>>,
    pub writers: core::sync::atomic::AtomicUsize,
    /// open read ends: when it reaches 0 a write fails with EPIPE (and raises SIGPIPE)
    pub readers: core::sync::atomic::AtomicUsize,
}

pub struct PipeEnd {
    pub buf: Arc<PipeBuf>,
    pub write: bool,
    pub nonblock: bool,
}

/// eventfd(2): a 64-bit counter shared by dup()s; readable when non-zero, always writable.
pub struct EventFd {
    pub counter: Arc<core::sync::atomic::AtomicU64>,
    pub semaphore: bool,
    pub nonblock: bool,
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        if self.write {
            self.buf.writers.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
        } else {
            self.buf.readers.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
        }
    }
}

impl PipeEnd {
    pub fn dup(&self) -> PipeEnd {
        if self.write {
            self.buf.writers.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        } else {
            self.buf.readers.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        }
        PipeEnd { buf: self.buf.clone(), write: self.write, nonblock: self.nonblock }
    }
    pub fn readable(&self) -> bool {
        !self.buf.q.lock().is_empty() || self.buf.writers.load(core::sync::atomic::Ordering::SeqCst) == 0
    }
}

pub enum Data {
    Pipe(PipeEnd),
    Sock(super::sock::SockState),
    Epoll(super::linux_net::EpollState),
    Event(EventFd),
    /// /dev/urandom, /dev/random: the kernel CSPRNG
    Random,
    /// /dev/null (reads EOF, writes vanish) and /dev/zero (reads zeros, writes vanish)
    Null,
    Zero,
    Static(&'static [u8]),
    Shared(Arc<Vec<u8>>),
    Buf(Vec<u8>),
    /// directory listing snapshot (names), see `open_dir`
    Dir(Vec<String>),
}

pub struct OpenFile {
    pub name: String,
    pub data: Data,
    pub pos: usize,
    pub writable: bool,
    pub dirty: bool,
    pub eof: bool,
}

impl OpenFile {
    pub fn bytes(&self) -> &[u8] {
        match &self.data {
            Data::Static(s) => s,
            Data::Shared(v) => v,
            Data::Buf(v) => v,
            Data::Dir(_) | Data::Pipe(_) | Data::Sock(_) | Data::Epoll(_) | Data::Event(_) | Data::Random | Data::Null | Data::Zero => &[],
        }
    }
    pub fn is_dir(&self) -> bool {
        matches!(self.data, Data::Dir(_))
    }
    pub fn len(&self) -> usize {
        self.bytes().len()
    }
}

/// `(name, store_only)` for a flat path, or `ENOENT`.
pub fn normalize(path: &str) -> Result<(String, bool), i64> {
    let mut s = path;
    while let Some(r) = s.strip_prefix("./") {
        s = r;
    }
    let s = s.trim_start_matches('/');
    let (s, store_only) = match s.strip_prefix("store/") {
        Some(r) => (r, true),
        None => (s, false),
    };
    if !crate::store::valid_name(s) {
        return Err(ENOENT);
    }
    Ok((String::from(s), store_only))
}

fn can(p: &Arc<Process>) -> (bool, bool, bool) {
    crate::perm::resolve(p);
    let f = p.foreign.lock();
    (f.fs_dir, f.fs_store_read, f.fs_store_write)
}

/// Live processes as (pid, name, ppid, threads, rss pages) for /proc.
fn proc_snapshot() -> Vec<(u64, String, u64, u64, u64)> {
    let list: Vec<Arc<Process>> = crate::task::PROCS.lock().iter().filter_map(|w| w.upgrade()).collect();
    list.iter()
        .filter(|q| !q.has_exited() && q.pid != 0)
        .map(|q| {
            let ppid = q.foreign.lock().parent.as_ref().and_then(|w| w.upgrade()).map_or(1, |x| x.pid);
            (q.pid, q.name.clone(), ppid, q.live_threads.load(core::sync::atomic::Ordering::SeqCst) as u64, q.mem_pages())
        })
        .collect()
}

/// `/proc/<pid>/{stat,status,cmdline,comm,statm}` (and `self`): enough for ps/top-style tools.
fn proc_pid_file(p: &Arc<Process>, pid: u64, file: &str) -> Option<Vec<u8>> {
    use alloc::format;
    use alloc::format as _f;
    let (_, name, ppid, thr, rss) = proc_snapshot().into_iter().find(|e| e.0 == pid)?;
    let comm: String = name.chars().take(15).collect();
    let _ = p;
    let s: String = match file {
        "stat" => format!(
            "{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 {thr} 0 0 {vs} {rss} 18446744073709551615 4194304 4194304 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
            vs = rss * 4096
        ),
        "status" => format!("Name:\t{comm}\nState:\tS (sleeping)\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{ppid}\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nThreads:\t{thr}\nVmSize:\t{} kB\nVmRSS:\t{} kB\n", rss * 4, rss * 4),
        "cmdline" => format!("{name}\0"),
        "comm" => format!("{comm}\n"),
        "statm" => format!("{rss} {rss} 0 0 0 0 0\n"),
        "environ" | "maps" | "cgroup" | "wchan" => String::new(),
        _ => return None,
    };
    Some(s.into_bytes())
}

/// Directory listing of `/proc` or `/proc/<pid>` (`None` if it is not one).
fn proc_dir(abs: &str) -> Option<Vec<(String, bool)>> {
    let mut v: Vec<(String, bool)> = Vec::new();
    if abs == "proc" {
        for f in ["meminfo", "cpuinfo", "uptime", "loadavg", "version", "stat", "mounts"] {
            v.push((String::from(f), false));
        }
        v.push((String::from("sys"), true));
        v.push((String::from("self"), true));
        for (pid, ..) in proc_snapshot() {
            v.push((alloc::format!("{}", pid), true));
        }
        return Some(v);
    }
    let rest = abs.strip_prefix("proc/")?;
    if rest.contains('/') {
        return None;
    }
    let pid: u64 = rest.parse().ok().or_else(|| if rest == "self" { Some(0) } else { None })?;
    if pid != 0 && !proc_snapshot().iter().any(|e| e.0 == pid) {
        return None;
    }
    for f in ["stat", "status", "cmdline", "comm", "statm", "environ", "maps"] {
        v.push((String::from(f), false));
    }
    Some(v)
}

/// A small synthetic /proc (generated at open): what libc, runtimes and tools commonly read at start-up.
fn proc_file(p: &Arc<Process>, path: &str) -> Option<Vec<u8>> {
    use alloc::format;
    let (total, free) = crate::mm::frame::stats();
    let (tk, fk) = (total * 4, free * 4);
    let up_ms = crate::time::uptime_ms();
    if let Some(rest) = path.strip_prefix("proc/") {
        if let Some((who, file)) = rest.split_once('/') {
            let pid = if who == "self" { Some(p.pid) } else { who.parse::<u64>().ok() };
            if let Some(pid) = pid {
                if let Some(v) = proc_pid_file(p, pid, file) {
                    return Some(v);
                }
            }
        }
    }
    let s: String = match path {
        "proc/meminfo" => format!("MemTotal:       {:8} kB\nMemFree:        {:8} kB\nMemAvailable:   {:8} kB\nBuffers:               0 kB\nCached:                0 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\n", tk, fk, fk),
        "proc/cpuinfo" => String::from("processor\t: 0\nvendor_id\t: Deloxy\nmodel name\t: x86-64 virtual CPU\ncpu MHz\t\t: 2000.000\ncache size\t: 4096 KB\ncpu cores\t: 1\nflags\t\t: fpu sse sse2\n\n"),
        "proc/uptime" => format!("{}.{:02} {}.{:02}\n", up_ms / 1000, (up_ms % 1000) / 10, up_ms / 1000, (up_ms % 1000) / 10),
        "proc/loadavg" => String::from("0.00 0.00 0.00 1/1 1\n"),
        "proc/version" => String::from("Linux version 6.1.0-deloxy (deloxy@build) #1 SMP\n"),
        "proc/stat" => format!("cpu  0 0 0 {} 0 0 0 0 0 0\nbtime {}\n", up_ms / 10, crate::time::unix_ms() / 1000 - up_ms / 1000),
        "proc/sys/kernel/osrelease" => String::from("6.1.0-deloxy\n"),
        "proc/sys/kernel/random/uuid" => {
            let mut b = [0u8; 16];
            crate::rand::fill(&mut b);
            b[6] = (b[6] & 0x0f) | 0x40;
            b[8] = (b[8] & 0x3f) | 0x80;
            format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}\n", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
        }
        "proc/self/maps" | "proc/self/smaps" | "proc/self/mountinfo" | "proc/mounts" | "proc/self/environ" => String::new(),
        "proc/self/cmdline" => {
            let g = p.foreign.lock();
            format!("{}\0", g.prog_name)
        }
        "proc/self/status" => {
            let g = p.foreign.lock();
            format!("Name:\t{}\nState:\tR (running)\nPid:\t{}\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nThreads:\t1\nVmRSS:\t   {} kB\n", g.prog_name, p.pid, p.mem_pages() * 4)
        }
        _ => return None,
    };
    Some(s.into_bytes())
}

/// Absolute canonical path (no leading slash, "" = root) of `path` as seen from the process's working directory.
pub fn resolve_abs(p: &Arc<Process>, path: &str) -> String {
    if path.starts_with('/') {
        crate::fs::rootfs::canon(path)
    } else {
        let cwd = p.foreign.lock().cwd.clone();
        crate::fs::rootfs::canon(&alloc::format!("{}/{}", cwd, path))
    }
}

const EROFS: i64 = 30;
const EBUSY_: i64 = 16;
const ENOTDIR: i64 = 20;
const ENOTEMPTY: i64 = 39;
const EEXIST: i64 = 17;

fn tmp_err(e: crate::fs::tmpfs::TmpErr) -> i64 {
    use crate::fs::tmpfs::TmpErr::*;
    match e {
        NotFound => ENOENT,
        Exists => EEXIST,
        NoSpace => ENOSPC,
        NotDir => ENOTDIR,
        IsDir => EISDIR,
        NotEmpty => ENOTEMPTY,
        BadName => 36, // ENAMETOOLONG
    }
}

fn is_tmp(abs: &str) -> bool {
    abs == "tmp" || abs.starts_with("tmp/")
}

/// Directory object: entries with a trailing '/' are directories (getdents reports DT_DIR).
fn dir_file(abs: &str, entries: Vec<(String, bool)>) -> OpenFile {
    let mut names: Vec<String> = alloc::vec![String::from("./"), String::from("../")];
    for (n, d) in entries {
        names.push(if d { alloc::format!("{}/", n) } else { n });
    }
    OpenFile { name: alloc::format!("/{}", abs), data: Data::Dir(names), pos: 0, writable: false, dirty: false, eof: false }
}

/// Hierarchical namespace: `/tmp` (volatile, writable) and the read-only root tree (second boot module).
fn open_hier(p: &Arc<Process>, abs: &str, write: bool, create: bool, trunc: bool, append: bool) -> Result<OpenFile, i64> {
    let (dir_ok, store_r, store_w) = can(p);
    if is_tmp(abs) {
        if !(dir_ok || store_r || store_w) {
            return Err(EACCES);
        }
        if abs == "tmp" || crate::fs::tmpfs::is_dir(abs) {
            if write {
                return Err(EISDIR);
            }
            return Ok(dir_file(abs, crate::fs::tmpfs::list(abs)));
        }
        let existing = crate::fs::tmpfs::read(abs);
        if write || create || trunc {
            if !store_w {
                return Err(EACCES);
            }
            let fresh = existing.is_none();
            if fresh {
                if !create {
                    return Err(ENOENT);
                }
                crate::fs::tmpfs::create(abs).map_err(tmp_err)?;
            }
            let buf = if trunc { Vec::new() } else { existing.unwrap_or_default() };
            let pos = if append { buf.len() } else { 0 };
            return Ok(OpenFile { name: String::from(abs), data: Data::Buf(buf), pos, writable: true, dirty: trunc || fresh, eof: false });
        }
        return match existing {
            Some(v) => Ok(OpenFile { name: String::from(abs), data: Data::Shared(Arc::new(v)), pos: 0, writable: false, dirty: false, eof: false }),
            None => Err(ENOENT),
        };
    }
    if abs == "proc" || abs.starts_with("proc/") {
        if write || create || trunc {
            return Err(EROFS);
        }
        return match proc_dir(abs) {
            Some(list) => Ok(dir_file(abs, list)),
            None => Err(ENOENT),
        };
    }
    if write || create || trunc {
        return Err(EROFS);
    }
    if abs.is_empty() {
        return Ok(open_dir(p));
    }
    if !dir_ok {
        return Err(EACCES);
    }
    match crate::fs::rootfs::lookup(abs) {
        Some((_, crate::fs::rootfs::Node::File { data })) => Ok(OpenFile { name: String::from(abs), data: Data::Static(data), pos: 0, writable: false, dirty: false, eof: false }),
        Some((canon, crate::fs::rootfs::Node::Dir)) => Ok(dir_file(&canon, crate::fs::rootfs::list(&canon))),
        _ => Err(ENOENT),
    }
}

/// open(2) on the unified namespace: special files, the flat initramfs/store names (`/x`, `/store/x`), `/tmp/...` and the
/// hierarchical read-only tree, resolved against the working directory.

// ------------------------------------------------------------------ persistent hierarchical store ---

/// Top-level names that live in the persistent store (unless the read-only root tree already has them).
const PFS_ALIASES: [&str; 7] = ["home", "var", "opt", "srv", "root", "mnt", "data"];

/// Path inside the persistent store for a canonical absolute path (no leading '/'), if it lies in the persistent
/// tree: `/store/...` and the `/home`, `/var`, `/opt`, `/srv`, `/root`, `/mnt`, `/data` subtrees.
pub fn pfs_map(abs: &str) -> Option<String> {
    if abs == "store" {
        return Some(String::new());
    }
    if let Some(r) = abs.strip_prefix("store/") {
        return Some(String::from(r));
    }
    for a in PFS_ALIASES {
        if (abs == a || abs.strip_prefix(a).map_or(false, |r| r.starts_with('/'))) && crate::fs::rootfs::lookup(a).is_none() {
            return Some(String::from(abs));
        }
    }
    None
}

/// The store path of an open file created by `open_pfs`.
pub fn pfs_rel(name: &str) -> Option<&str> {
    name.strip_prefix("store/")
}

fn first_comp(rel: &str) -> &str {
    rel.split('/').find(|c| !c.is_empty() && *c != ".").unwrap_or("")
}

/// Kernel-owned root names: `upd.*`/`perms.*` may never be changed by programs; `de.conf` may be rewritten but not
/// removed or replaced by rename.
fn pfs_guarded(rel: &str, destructive: bool) -> bool {
    let c = first_comp(rel);
    crate::store::is_reserved(c) || (destructive && c == "de.conf")
}

fn store_ready() -> bool {
    crate::store::state() == crate::store::State::Ready
}

/// Run a store operation: `ENOENT` when no store is mounted, the POSIX errno of any store error.
fn pfs_do<R>(f: impl FnOnce(&mut crate::store::Store<crate::drivers::blk::Disk>) -> Result<R, crate::store::StoreErr>) -> Result<R, i64> {
    if !store_ready() {
        return Err(ENOENT);
    }
    match crate::store::with(f) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(e.errno()),
        Err(_) => Err(ENOENT),
    }
}

fn open_pfs(p: &Arc<Process>, abs: &str, rel: &str, write: bool, create: bool, trunc: bool, append: bool) -> Result<OpenFile, i64> {
    let (_, store_r, store_w) = can(p);
    if write && !store_w || !write && !store_r {
        return Err(EACCES);
    }
    if !store_ready() {
        if rel.is_empty() && !write {
            return Ok(dir_file(abs, Vec::new()));
        }
        return Err(ENOENT);
    }
    match pfs_do(|s| s.stat(rel, true)) {
        Ok(st) if st.kind == crate::store::Kind::Dir => {
            if write {
                return Err(EISDIR);
            }
            let ents = pfs_do(|s| s.readdir(rel))?;
            Ok(dir_file(abs, ents.into_iter().map(|e| (e.name, e.kind == crate::store::Kind::Dir)).collect()))
        }
        Ok(_) => {
            let real = pfs_do(|s| s.realpath(rel, true))?;
            if write && pfs_guarded(&real, false) {
                return Err(EACCES);
            }
            if write {
                let buf: Vec<u8> = if trunc { Vec::new() } else { pfs_do(|s| s.read(rel))? };
                let pos = if append { buf.len() } else { 0 };
                return Ok(OpenFile { name: alloc::format!("store/{}", real), data: Data::Buf(buf), pos, writable: true, dirty: trunc, eof: false });
            }
            let v = pfs_do(|s| s.read(rel))?;
            Ok(OpenFile { name: alloc::format!("store/{}", real), data: Data::Shared(Arc::new(v)), pos: 0, writable: false, dirty: false, eof: false })
        }
        Err(e) if e == ENOENT && write && (create || trunc) => {
            let real = pfs_do(|s| s.realpath_new(rel))?;
            if pfs_guarded(&real, false) {
                return Err(EACCES);
            }
            Ok(OpenFile { name: alloc::format!("store/{}", real), data: Data::Buf(Vec::new()), pos: 0, writable: true, dirty: true, eof: false })
        }
        Err(e) => Err(e),
    }
}

/// `stat`/`lstat` on a persistent path: `None` if the path is not in the persistent tree.
pub fn pfs_stat(p: &Arc<Process>, abs: &str, follow: bool) -> Option<Result<crate::store::Stat, i64>> {
    let rel = pfs_map(abs)?;
    let (_, store_r, store_w) = can(p);
    if !(store_r || store_w) {
        return Some(Err(EACCES));
    }
    if !store_ready() && rel.is_empty() {
        return Some(Ok(crate::store::Stat { ino: 1, kind: crate::store::Kind::Dir, mode: 0o755, size: 0, mtime: 0, crc: 0 }));
    }
    Some(pfs_do(|s| s.stat(&rel, follow)))
}

/// Stat of an already open persistent file (by `OpenFile::name`).
pub fn pfs_stat_open(name: &str) -> Option<crate::store::Stat> {
    let rel = pfs_rel(name)?;
    crate::store::with(|s| s.stat(rel, true)).ok().and_then(|r| r.ok())
}

pub fn symlink(p: &Arc<Process>, target: &str, linkpath: &str) -> Result<(), i64> {
    let abs = resolve_abs(p, linkpath);
    let rel = pfs_map(&abs).ok_or(EROFS)?;
    let (_, _, store_w) = can(p);
    if !store_w {
        return Err(EACCES);
    }
    let real = pfs_do(|s| s.realpath_new(&rel))?;
    if pfs_guarded(&real, true) {
        return Err(EACCES);
    }
    pfs_do(|s| s.symlink(target, &rel))
}

pub fn readlink_pfs(p: &Arc<Process>, abs: &str) -> Option<Result<String, i64>> {
    let rel = pfs_map(abs)?;
    let (_, store_r, _) = can(p);
    if !store_r {
        return Some(Err(EACCES));
    }
    Some(pfs_do(|s| s.readlink(&rel)).map_err(|e| if e == 22 { 22 } else { e }))
}

pub fn chmod(p: &Arc<Process>, path: &str, mode: u32) -> Result<(), i64> {
    let abs = resolve_abs(p, path);
    let Some(rel) = pfs_map(&abs) else { return Ok(()) };
    let (_, _, store_w) = can(p);
    if !store_w {
        return Err(EACCES);
    }
    let real = pfs_do(|s| s.realpath(&rel, true))?;
    if pfs_guarded(&real, false) {
        return Err(EACCES);
    }
    pfs_do(|s| s.chmod(&rel, (mode & 0o7777) as u16))
}

pub fn chmod_open(name: &str, mode: u32) -> Result<(), i64> {
    match pfs_rel(name) {
        Some(rel) => pfs_do(|s| s.chmod(rel, (mode & 0o7777) as u16)),
        None => Ok(()),
    }
}

pub fn open(p: &Arc<Process>, path: &str, write: bool, create: bool, trunc: bool, append: bool) -> Result<OpenFile, i64> {
    let abs = resolve_abs(p, path);
    if let Some(rel) = pfs_map(&abs) {
        return open_pfs(p, &abs, &rel, write, create, trunc, append);
    }
    match open_old(p, &abs, write, create, trunc, append) {
        Err(ENOENT) => open_hier(p, &abs, write, create, trunc, append),
        r => r,
    }
}

/// Is the (absolute, canonical) path a directory? Used by chdir/stat.
pub fn is_dir_abs(p: &Arc<Process>, abs: &str) -> bool {
    if is_dir_path(abs) {
        return true;
    }
    if let Some(r) = pfs_stat(p, abs, true) {
        return matches!(r, Ok(st) if st.kind == crate::store::Kind::Dir);
    }
    if is_tmp(abs) {
        return abs == "tmp" || crate::fs::tmpfs::is_dir(abs);
    }
    let _ = p;
    matches!(crate::fs::rootfs::lookup(abs), Some((_, crate::fs::rootfs::Node::Dir)))
}

/// mkdir(2): only under /tmp.
pub fn mkdir(p: &Arc<Process>, path: &str) -> Result<(), i64> {
    let abs = resolve_abs(p, path);
    let (_, _, store_w) = can(p);
    if let Some(rel) = pfs_map(&abs) {
        if rel.is_empty() {
            return Err(EEXIST);
        }
        if !store_w {
            return Err(EACCES);
        }
        let real = pfs_do(|s| s.realpath_new(&rel))?;
        if pfs_guarded(&real, true) {
            return Err(EACCES);
        }
        return pfs_do(|s| s.mkdir(&rel));
    }
    if !is_tmp(&abs) {
        return Err(if crate::fs::rootfs::lookup(&abs).is_some() || abs.is_empty() { EEXIST } else { EROFS });
    }
    if !store_w {
        return Err(EACCES);
    }
    crate::fs::tmpfs::mkdir(&abs).map_err(tmp_err)
}

pub fn rmdir(p: &Arc<Process>, path: &str) -> Result<(), i64> {
    let abs = resolve_abs(p, path);
    let (_, _, store_w) = can(p);
    if let Some(rel) = pfs_map(&abs) {
        if rel.is_empty() {
            return Err(EBUSY_);
        }
        if !store_w {
            return Err(EACCES);
        }
        if pfs_guarded(&rel, true) {
            return Err(EACCES);
        }
        return pfs_do(|s| s.rmdir(&rel));
    }
    if !is_tmp(&abs) || abs == "tmp" {
        return Err(EROFS);
    }
    if !store_w {
        return Err(EACCES);
    }
    crate::fs::tmpfs::rmdir(&abs).map_err(tmp_err)
}

pub fn rename(p: &Arc<Process>, from: &str, to: &str) -> Result<(), i64> {
    let (a, b) = (resolve_abs(p, from), resolve_abs(p, to));
    let (_, _, store_w) = can(p);
    if let (Some(ra), Some(rb)) = (pfs_map(&a), pfs_map(&b)) {
        if ra.is_empty() || rb.is_empty() {
            return Err(EBUSY_);
        }
        if !store_w {
            return Err(EACCES);
        }
        if pfs_guarded(&ra, true) || pfs_guarded(&rb, true) {
            return Err(EACCES);
        }
        return pfs_do(|s| s.rename(&ra, &rb));
    }
    if !is_tmp(&a) || !is_tmp(&b) {
        return Err(18); // EXDEV: renames only work inside /tmp or inside the persistent store
    }
    if !store_w {
        return Err(EACCES);
    }
    crate::fs::tmpfs::rename(&a, &b).map_err(tmp_err)
}

/// Read-only system files that C libraries expect (name resolution). They carry no secrets and need no permission:
/// the nameserver is the kernel's virtual resolver (`sock::VDNS`), which is itself gated by the `dns` permission.
fn synthetic(path: &str) -> Option<(&'static str, &'static [u8])> {
    let s = path.trim_start_matches("./").trim_start_matches('/');
    match s {
        "etc/resolv.conf" => Some(("resolv.conf", b"# Deloxy: the kernel resolver (needs the 'dns' permission)\nnameserver 10.255.255.53\noptions timeout:3 attempts:2\n")),
        "etc/hosts" => Some(("hosts", b"127.0.0.1 localhost\n")),
        "etc/nsswitch.conf" => Some(("nsswitch.conf", b"hosts: files dns\n")),
        "etc/passwd" => Some(("passwd", b"root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000:Deloxy user:/home/user:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n")),
        "etc/group" => Some(("group", b"root:x:0:\nuser:x:1000:\nnogroup:x:65534:\n")),
        "etc/hostname" => Some(("hostname", b"deloxy\n")),
        "etc/os-release" => Some(("os-release", b"NAME=\"Deloxy\"\nID=deloxy\nPRETTY_NAME=\"Deloxy\"\nVERSION_ID=\"0.1\"\n")),
        "etc/shells" => Some(("shells", b"/bin/sh\n")),
        "etc/host.conf" => Some(("host.conf", b"order hosts,bind\n")),
        _ => None,
    }
}

/// Shared libraries shipped in the image (`ld-linux-x86-64.so.2`, `libc.so.6`...): resolved by base name from the usual
/// system library directories. Read-only, no permission needed (they are part of the OS image, like /etc/resolv.conf).
pub fn system_lib(path: &str) -> Option<Arc<crate::fs::RamFile>> {
    let s = path.trim_start_matches("./").trim_start_matches('/');
    let (dir, base) = s.rsplit_once('/')?;
    let ok_dir = matches!(dir, "lib" | "lib64" | "usr/lib" | "usr/lib64" | "usr/local/lib" | "lib/x86_64-linux-gnu" | "usr/lib/x86_64-linux-gnu" | "opt/deloxy/lib");
    if !ok_dir || !(base.starts_with("lib") || base.starts_with("ld-")) || !base.contains(".so") || base.contains('/') {
        return None;
    }
    crate::fs::root()?.lookup(base)
}

/// Executables of the image seen through the standard binary directories (`/bin/uname`, `/usr/bin/env`...): lets PATH
/// searches (`stat`/`access`/`execve`) find programs that live in the image's flat namespace.
pub fn system_bin(path: &str) -> Option<Arc<crate::fs::RamFile>> {
    let s = path.trim_start_matches("./").trim_start_matches('/');
    let (dir, base) = s.rsplit_once('/')?;
    if !matches!(dir, "bin" | "sbin" | "usr/bin" | "usr/sbin" | "usr/local/bin" | "usr/local/sbin") || base.is_empty() || base.starts_with('.') {
        return None;
    }
    let f = crate::fs::root()?.lookup(base)?;
    // only real executables: ELF or PE images
    (f.data.starts_with(b"\x7fELF") || f.data.starts_with(b"MZ")).then_some(f)
}

/// Does this file look executable (ELF / PE magic, or a shared object)?
pub fn looks_executable(data: &[u8]) -> bool {
    data.starts_with(b"\x7fELF") || data.starts_with(b"MZ")
}

pub fn is_synthetic(path: &str) -> bool {
    synthetic(path).is_some()
}

/// Open for reading, or (with `write`) for writing with the usual create/truncate/append semantics.
fn open_old(p: &Arc<Process>, path: &str, write: bool, create: bool, trunc: bool, append: bool) -> Result<OpenFile, i64> {
    if let Some(content) = proc_file(p, path.trim_start_matches("./").trim_start_matches('/')) {
        if write {
            return Err(EACCES);
        }
        return Ok(OpenFile { name: String::from("proc"), data: Data::Buf(content), pos: 0, writable: false, dirty: false, eof: false });
    }
    match path.trim_start_matches("./").trim_start_matches('/') {
        "dev/null" => return Ok(OpenFile { name: String::from("null"), data: Data::Null, pos: 0, writable: true, dirty: false, eof: false }),
        "dev/zero" => return Ok(OpenFile { name: String::from("zero"), data: Data::Zero, pos: 0, writable: true, dirty: false, eof: false }),
        _ => {}
    }
    if matches!(path.trim_start_matches("./").trim_start_matches('/'), "dev/urandom" | "dev/random" | "dev/arandom") {
        return Ok(OpenFile { name: String::from("urandom"), data: Data::Random, pos: 0, writable: write, dirty: false, eof: false });
    }
    if let Some(f) = system_lib(path).or_else(|| system_bin(path)) {
        if write {
            return Err(EACCES);
        }
        return Ok(OpenFile { name: String::from(f.name.as_str()), data: Data::Static(f.data), pos: 0, writable: false, dirty: false, eof: false });
    }
    if let Some((name, data)) = synthetic(path) {
        if write {
            return Err(EACCES);
        }
        return Ok(OpenFile { name: String::from(name), data: Data::Static(data), pos: 0, writable: false, dirty: false, eof: false });
    }
    let (dir_ok, store_r, store_w) = can(p);
    let (name, store_only) = normalize(path)?;
    if write {
        if !store_w {
            return Err(EACCES);
        }
        if crate::store::is_reserved(&name) {
            return Err(EACCES);
        }
        let existing: Option<Vec<u8>> = if trunc { None } else { crate::store::with(|s| s.read(&name)).ok().and_then(|r| r.ok()) };
        if existing.is_none() && !create && !trunc {
            // O_WRONLY without O_CREAT on a missing file
            let exists = crate::store::with(|s| s.list().iter().any(|e| e.name == name)).unwrap_or(false);
            if !exists {
                return Err(ENOENT);
            }
        }
        if crate::store::state() != crate::store::State::Ready {
            return Err(ENOENT);
        }
        let buf = existing.unwrap_or_default();
        let pos = if append { buf.len() } else { 0 };
        return Ok(OpenFile { name, data: Data::Buf(buf), pos, writable: true, dirty: trunc || create, eof: false });
    }
    if dir_ok && !store_only {
        if let Some(f) = crate::fs::root().and_then(|d| d.lookup(&name)) {
            return Ok(OpenFile { name, data: Data::Static(f.data), pos: 0, writable: false, dirty: false, eof: false });
        }
    }
    if store_r {
        return match crate::store::with(|s| s.read(&name)) {
            Ok(Ok(v)) => Ok(OpenFile { name, data: Data::Shared(Arc::new(v)), pos: 0, writable: false, dirty: false, eof: false }),
            Ok(Err(crate::store::StoreErr::NotFound)) | Err(_) => Err(ENOENT),
            Ok(Err(_)) => Err(EIO),
        };
    }
    Err(ENOENT)
}

pub fn is_dir_path(path: &str) -> bool {
    matches!(path, "" | "/" | "." | "./")
}

/// Directory snapshot: ".", "..", initramfs files (with a Dir capability) and store files (with Store READ).
pub fn open_dir(p: &Arc<Process>) -> OpenFile {
    let (dir_ok, store_r, _) = can(p);
    let mut names: Vec<String> = alloc::vec![String::from("."), String::from("..")];
    if dir_ok {
        if let Some(root) = crate::fs::root() {
            for f in root.files.iter() {
                names.push(f.name.clone());
            }
        }
    }
    if store_r {
        let _ = crate::store::with(|s| {
            for e in s.list() {
                if !names.iter().any(|n| *n == e.name) {
                    names.push(e.name.clone());
                }
            }
        });
    }
    // hierarchical namespace: the root tree's top-level entries and /tmp (a trailing '/' marks a directory)
    if dir_ok {
        for (n, d) in crate::fs::rootfs::list("") {
            let e = if d { alloc::format!("{}/", n) } else { n };
            if !names.iter().any(|x| *x == e) {
                names.push(e);
            }
        }
    }
    names.push(String::from("tmp/"));
    names.push(String::from("proc/"));
    names.push(String::from("store/"));
    if store_r {
        let _ = crate::store::with(|s| {
            if let Ok(ents) = s.readdir("") {
                for e in ents {
                    let d = alloc::format!("{}/", e.name);
                    if e.kind == crate::store::Kind::Dir && PFS_ALIASES.contains(&e.name.as_str()) && crate::fs::rootfs::lookup(&e.name).is_none() && !names.contains(&d) {
                        names.push(d);
                    }
                }
            }
        });
    }
    OpenFile { name: String::from("/"), data: Data::Dir(names), pos: 0, writable: false, dirty: false, eof: false }
}

pub fn unlink(p: &Arc<Process>, path: &str) -> Result<(), i64> {
    let abs = resolve_abs(p, path);
    let (_, _, store_w) = can(p);
    if is_tmp(&abs) {
        if !store_w {
            return Err(EACCES);
        }
        return crate::fs::tmpfs::remove(&abs).map_err(tmp_err);
    }
    if let Some(rel) = pfs_map(&abs) {
        if !store_w {
            return Err(EACCES);
        }
        if pfs_guarded(&rel, true) {
            return Err(EACCES);
        }
        return pfs_do(|s| s.unlink(&rel));
    }
    let (name, _) = normalize(&abs)?;
    if !store_w || crate::store::is_reserved(&name) || name == "de.conf" {
        return Err(EACCES);
    }
    match crate::store::with(|s| s.delete(&name)) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(crate::store::StoreErr::NotFound)) => Err(ENOENT),
        _ => Err(EIO),
    }
}

pub fn flush(f: &mut OpenFile) -> Result<(), i64> {
    if !f.writable || !f.dirty {
        return Ok(());
    }
    if f.name.starts_with("tmp/") {
        return match crate::fs::tmpfs::write(&f.name, f.bytes()) {
            Ok(()) => {
                f.dirty = false;
                Ok(())
            }
            Err(e) => Err(tmp_err(e)),
        };
    }
    let path = pfs_rel(&f.name).unwrap_or(&f.name);
    let r = crate::store::with(|s| s.write(path, f.bytes()));
    match r {
        Ok(Ok(())) => {
            f.dirty = false;
            Ok(())
        }
        Ok(Err(e)) => Err(e.errno()),
        _ => Err(EIO),
    }
}

/// A duplicate sharing the same underlying object (pipes) or an independent cursor over immutable data.
pub fn clone_open(f: &OpenFile) -> Option<OpenFile> {
    let data = match &f.data {
        Data::Static(s) => Data::Static(s),
        Data::Shared(v) => Data::Shared(v.clone()),
        Data::Pipe(p) => Data::Pipe(p.dup()),
        Data::Event(e) => Data::Event(EventFd { counter: e.counter.clone(), semaphore: e.semaphore, nonblock: e.nonblock }),
        _ => return None,
    };
    Some(OpenFile { name: f.name.clone(), data, pos: f.pos, writable: f.writable, dirty: false, eof: f.eof })
}

pub fn new_pipe() -> (OpenFile, OpenFile) {
    let buf = Arc::new(PipeBuf { q: crate::sync::IrqMutex::new(alloc::collections::VecDeque::new()), writers: core::sync::atomic::AtomicUsize::new(1), readers: core::sync::atomic::AtomicUsize::new(1) });
    let r = OpenFile { name: String::from("pipe"), data: Data::Pipe(PipeEnd { buf: buf.clone(), write: false, nonblock: false }), pos: 0, writable: false, dirty: false, eof: false };
    let w = OpenFile { name: String::from("pipe"), data: Data::Pipe(PipeEnd { buf, write: true, nonblock: false }), pos: 0, writable: true, dirty: false, eof: false };
    (r, w)
}

pub fn read(f: &mut OpenFile, out: &mut [u8]) -> usize {
    if matches!(f.data, Data::Random) {
        crate::rand::fill(out);
        return out.len();
    }
    if matches!(f.data, Data::Zero) {
        out.fill(0);
        return out.len();
    }
    if matches!(f.data, Data::Null) {
        return 0;
    }
    if let Data::Pipe(p) = &f.data {
        let mut q = p.buf.q.lock();
        let n = out.len().min(q.len());
        for o in out.iter_mut().take(n) {
            *o = q.pop_front().unwrap();
        }
        return n;
    }
    let b = f.bytes();
    if f.pos >= b.len() {
        return 0;
    }
    let n = out.len().min(b.len() - f.pos);
    out[..n].copy_from_slice(&b[f.pos..f.pos + n]);
    f.pos += n;
    n
}

pub fn write(f: &mut OpenFile, data: &[u8]) -> Result<usize, i64> {
    if matches!(f.data, Data::Null | Data::Zero | Data::Random) {
        return Ok(data.len());
    }
    if !f.writable {
        return Err(EBADF);
    }
    if let Data::Pipe(p) = &f.data {
        if !p.write {
            return Err(EBADF);
        }
        if p.buf.readers.load(core::sync::atomic::Ordering::SeqCst) == 0 {
            return Err(32); // EPIPE: nobody will ever read this
        }
        let mut q = p.buf.q.lock();
        if q.len() + data.len() > 1 << 20 {
            return Err(EFBIG);
        }
        q.extend(data.iter().copied());
        return Ok(data.len());
    }
    let Data::Buf(buf) = &mut f.data else { return Err(EBADF) };
    let end = f.pos.checked_add(data.len()).ok_or(EFBIG)?;
    if end > crate::store::MAX_FILE_BYTES {
        return Err(EFBIG);
    }
    if buf.len() < end {
        buf.resize(end, 0);
    }
    buf[f.pos..end].copy_from_slice(data);
    f.pos = end;
    f.dirty = true;
    Ok(data.len())
}

/// `whence`: 0 SET, 1 CUR, 2 END.
pub fn seek(f: &mut OpenFile, off: i64, whence: u64) -> Result<u64, i64> {
    let base = match whence {
        0 => 0i64,
        1 => f.pos as i64,
        2 => f.len() as i64,
        _ => return Err(EINVAL),
    };
    let np = base.checked_add(off).ok_or(EINVAL)?;
    if np < 0 {
        return Err(EINVAL);
    }
    f.pos = np as usize;
    Ok(np as u64)
}

/// Install in the first free slot; returns the slot index.
pub fn alloc(p: &Arc<Process>, f: OpenFile) -> Result<usize, i64> {
    let mut g = p.foreign.lock();
    if let Some(i) = g.fds.iter().position(|s| s.is_none()) {
        g.fds[i] = Some(f);
        return Ok(i);
    }
    if g.fds.len() >= MAX_FDS {
        return Err(EMFILE);
    }
    g.fds.push(Some(f));
    Ok(g.fds.len() - 1)
}

/// Close slot `i`, committing buffered writes.
pub fn close(p: &Arc<Process>, i: usize) -> Result<(), i64> {
    let f = {
        let mut g = p.foreign.lock();
        g.fds.get_mut(i).and_then(|s| s.take())
    };
    match f {
        None => Err(EBADF),
        Some(mut f) => flush(&mut f),
    }
}

/// Commit every dirty writable file but keep the descriptors open (execve: the new image inherits them).
pub fn sync_all(p: &Arc<Process>) {
    let mut g = p.foreign.lock();
    for f in g.fds.iter_mut().flatten() {
        if f.dirty {
            let _ = flush(f);
        }
    }
}

/// Commit every open writable file (process exit).
pub fn flush_all(p: &Arc<Process>) {
    let files: Vec<OpenFile> = {
        let mut g = p.foreign.lock();
        g.fds.iter_mut().filter_map(|s| s.take()).collect()
    };
    for mut f in files {
        let _ = flush(&mut f);
    }
}
