//! Milestone-8 syscalls: TTY, initramfs files, process control, capability listing, network consent,
//! the updater and power. Every one resolves a capability first; there is no path-based or global access.
//!
//! 21 tty_read(h, buf, max, timeout_ms)   22 tty_write(h, buf, len)    23 fs_list(dir, index, buf, max)
//! 24 fs_open(dir, name, len)             25 file_read(f, off, buf, len)
//! 26 proc_spawn(spawn, file, args, args_len, errbuf, errmax)           27 proc_wait(proc, out_ptr)
//! 28 proc_list(sys, index, buf)          29 cap_list(index, buf)       30 net_grant(admin, ip, port, secs, bytes)
//! 31 upd(net, req_ptr)                   32 power(h, op)
//! 33 store_list(h, index, buf, max)      34 store_open(h, name, len)    35 store_write(h, name, len, data, dlen)
//! 36 store_ctl(h, op, name, len, out)    (op 0 delete, 1 stats, 2 format)
//! 38 store_fs(h, op, path, plen, a4, a5) hierarchical store: stat/readdir/mkdir/rmdir/unlink/rename/symlink/readlink/chmod/read/write

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::errno::*;
use super::uaccess;
use crate::arch::x86_64::syscall::SyscallFrame;
use crate::cap::{CapObject, Rights};
use crate::task;

pub const SYS_TTY_READ: u64 = 21;
pub const SYS_TTY_WRITE: u64 = 22;
pub const SYS_FS_LIST: u64 = 23;
pub const SYS_FS_OPEN: u64 = 24;
pub const SYS_FILE_READ: u64 = 25;
pub const SYS_PROC_SPAWN: u64 = 26;
pub const SYS_PROC_WAIT: u64 = 27;
pub const SYS_PROC_LIST: u64 = 28;
pub const SYS_CAP_LIST: u64 = 29;
pub const SYS_NET_GRANT: u64 = 30;
pub const SYS_UPD: u64 = 31;
pub const SYS_POWER: u64 = 32;
pub const SYS_STORE_LIST: u64 = 33;
pub const SYS_STORE_OPEN: u64 = 34;
pub const SYS_STORE_WRITE: u64 = 35;
pub const SYS_STORE_CTL: u64 = 36;
pub const SYS_PERM: u64 = 37;
pub const SYS_STORE_FS: u64 = 38;

pub const ENOEXEC: i64 = 8;
const MAX_ARGS_BYTES: usize = 512;
const MAX_ARGS: usize = 16;
const MAX_TTY_IO: usize = 512;

pub fn handle(nr: u64, f: &SyscallFrame) -> i64 {
    let (a0, a1, a2, a3, a4, a5) = (f.rdi, f.rsi, f.rdx, f.r10, f.r8, f.r9);
    match nr {
        SYS_TTY_READ => tty_read(a0, a1, a2 as usize, a3),
        SYS_TTY_WRITE => tty_write(a0, a1, a2 as usize),
        SYS_FS_LIST => fs_list(a0, a1, a2, a3 as usize),
        SYS_FS_OPEN => fs_open(a0, a1, a2 as usize),
        SYS_FILE_READ => file_read(a0, a1, a2, a3 as usize),
        SYS_PROC_SPAWN => proc_spawn(a0, a1, a2, a3 as usize, a4, a5 as usize),
        SYS_PROC_WAIT => proc_wait(a0, a1),
        SYS_PROC_LIST => proc_list(a0, a1, a2),
        SYS_CAP_LIST => cap_list(a0, a1),
        SYS_NET_GRANT => net_grant(a0, a1, a2, a3, a4),
        SYS_UPD => upd(a0, a1),
        SYS_POWER => power(a0, a1),
        SYS_STORE_LIST => store_list(a0, a1, a2, a3 as usize),
        SYS_STORE_OPEN => store_open(a0, a1, a2 as usize),
        SYS_STORE_WRITE => store_write(a0, a1, a2 as usize, a3, a4 as usize),
        SYS_STORE_CTL => store_ctl(a0, a1, a2, a3 as usize, a4),
        SYS_PERM => perm_ctl(a0, a1, a2, a3 as usize, a4),
        SYS_STORE_FS => store_fs(a0, a1, a2, a3 as usize, a4, a5),
        _ => -ENOSYS,
    }
}

fn lookup(h: u64, need: Rights) -> Result<CapObject, i64> {
    task::current_process().caps.lock().lookup(h, need).map(|(o, _)| o)
}

fn tty_read(h: u64, buf: u64, max: usize, timeout_ms: u64) -> i64 {
    match lookup(h, Rights::READ) {
        Ok(CapObject::Tty) => {}
        Ok(_) => return -EINVAL,
        Err(e) => return -e,
    }
    let max = max.min(MAX_TTY_IO);
    if max == 0 {
        return -EINVAL;
    }
    let p = task::current_process();
    let t0 = crate::time::uptime_ms();
    let mut tmp = [0u8; MAX_TTY_IO];
    loop {
        let n = crate::tty::read_input(&mut tmp[..max]);
        if n > 0 {
            return match uaccess::copy_to_user(&p, buf, &tmp[..n]) {
                Ok(()) => n as i64,
                Err(e) => -e,
            };
        }
        if timeout_ms != u64::MAX && crate::time::uptime_ms().saturating_sub(t0) >= timeout_ms {
            return 0;
        }
        task::sleep_ms(2);
    }
}

fn tty_write(h: u64, buf: u64, len: usize) -> i64 {
    match lookup(h, Rights::WRITE) {
        Ok(CapObject::Tty) => {}
        Ok(_) => return -EINVAL,
        Err(e) => return -e,
    }
    if len > MAX_TTY_IO {
        return -EINVAL;
    }
    let mut tmp = [0u8; MAX_TTY_IO];
    if let Err(e) = uaccess::copy_from_user(&task::current_process(), &mut tmp[..len], buf) {
        return -e;
    }
    crate::tty::write(&tmp[..len]);
    len as i64
}

/// Returns `size << 8 | name_len`; the name (<= 100 bytes) is copied to `buf`.
fn fs_list(h: u64, index: u64, buf: u64, max: usize) -> i64 {
    let dir = match lookup(h, Rights::READ) {
        Ok(CapObject::Dir(d)) => d,
        Ok(_) => return -EINVAL,
        Err(e) => return -e,
    };
    let Some(f) = dir.files.get(index as usize) else { return -ENOENT };
    let name = f.name.as_bytes();
    if max < name.len() {
        return -ERANGE;
    }
    if let Err(e) = uaccess::copy_to_user(&task::current_process(), buf, name) {
        return -e;
    }
    ((f.data.len() as i64) << 8) | name.len() as i64
}

fn user_bytes(p: &task::Process, ptr: u64, len: usize, max: usize) -> Result<Vec<u8>, i64> {
    if len > max {
        return Err(EINVAL);
    }
    let mut v = alloc::vec![0u8; len];
    uaccess::copy_from_user(p, &mut v, ptr)?;
    Ok(v)
}

fn fs_open(h: u64, name: u64, len: usize) -> i64 {
    let dir = match lookup(h, Rights::READ) {
        Ok(CapObject::Dir(d)) => d,
        Ok(_) => return -EINVAL,
        Err(e) => return -e,
    };
    let p = task::current_process();
    let raw = match user_bytes(&p, name, len, 100) {
        Ok(v) => v,
        Err(e) => return -e,
    };
    let Ok(n) = core::str::from_utf8(&raw) else { return -EINVAL };
    let Some(file) = dir.lookup(n) else { return -ENOENT };
    let r = p.caps.lock().insert(CapObject::File(file), Rights::READ | Rights::EXEC);
    match r {
        Ok(h) => h as i64,
        Err(e) => -e,
    }
}

fn file_read(h: u64, off: u64, buf: u64, len: usize) -> i64 {
    let obj = match lookup(h, Rights::READ) {
        Ok(o) => o,
        Err(e) => return -e,
    };
    let data: &[u8] = match &obj {
        CapObject::File(f) => f.data,
        CapObject::StoreFile(f) => &f.data[..],
        _ => return -EINVAL,
    };
    let len = len.min(4096);
    let off = off as usize;
    if off >= data.len() {
        return 0;
    }
    let n = len.min(data.len() - off);
    match uaccess::copy_to_user(&task::current_process(), buf, &data[off..off + n]) {
        Ok(()) => n as i64,
        Err(e) => -e,
    }
}

fn put_err(p: &task::Process, buf: u64, max: usize, msg: &str) {
    if buf != 0 && max > 0 {
        let b = msg.as_bytes();
        let n = b.len().min(max - 1);
        let mut out = alloc::vec::Vec::from(&b[..n]);
        out.push(0);
        let _ = uaccess::copy_to_user(p, buf, &out);
    }
}

fn proc_spawn(spawn_h: u64, file_h: u64, args_ptr: u64, args_len: usize, errbuf: u64, errmax: usize) -> i64 {
    let p = task::current_process();
    let (console, files) = match lookup(spawn_h, Rights::EXEC) {
        Ok(CapObject::Spawn { console, files }) => (console, files),
        Ok(_) => return -EINVAL,
        Err(e) => return -e,
    };
    let (fname, fdata): (String, alloc::sync::Arc<dyn AsRef<[u8]> + Send + Sync>) = match lookup(file_h, Rights::READ | Rights::EXEC) {
        Ok(CapObject::File(f)) => (f.name.clone(), alloc::sync::Arc::new(f.data)),
        Ok(CapObject::StoreFile(f)) => (f.name.clone(), f as alloc::sync::Arc<dyn AsRef<[u8]> + Send + Sync>),
        Ok(_) => return -EINVAL,
        Err(e) => return -e,
    };
    let raw = match user_bytes(&p, args_ptr, args_len, MAX_ARGS_BYTES) {
        Ok(v) => v,
        Err(e) => return -e,
    };
    let mut args: Vec<&str> = Vec::new();
    for part in raw.split(|&b| b == 0) {
        if part.is_empty() {
            continue;
        }
        if args.len() >= MAX_ARGS {
            return -EINVAL;
        }
        match core::str::from_utf8(part) {
            Ok(s) => args.push(s),
            Err(_) => return -EINVAL,
        }
    }
    let caps: &[(CapObject, Rights)] = if console { &[(CapObject::Tty, Rights::WRITE)] } else { &[] };
    let mut fcaps: Vec<(CapObject, Rights)> = Vec::new();
    if files {
        // only foreign (Linux/NT) programs get these; they find them in their own cap table (see abi::vfs)
        if let Some(root) = crate::fs::root() {
            fcaps.push((CapObject::Dir(root), Rights::READ));
        }
        fcaps.push((CapObject::Store, Rights::READ | Rights::WRITE));
    }
    match crate::exec::spawn(&fname, (*fdata).as_ref(), &crate::exec::SpawnOpts { args: &args, console, caps, foreign_caps: &fcaps }) {
        Ok(child) => {
            let r = p.caps.lock().insert(CapObject::Proc(child), Rights::READ);
            match r {
                Ok(h) => h as i64,
                Err(e) => -e,
            }
        }
        Err(e) => {
            put_err(&p, errbuf, errmax, &format!("{}", e));
            -ENOEXEC
        }
    }
}

fn proc_wait(h: u64, out: u64) -> i64 {
    let child = match lookup(h, Rights::READ) {
        Ok(CapObject::Proc(c)) => c,
        Ok(_) => return -EINVAL,
        Err(e) => return -e,
    };
    while !child.has_exited() {
        task::sleep_ms(2);
    }
    let code = child.exit_code.load(Ordering::SeqCst);
    match uaccess::copy_to_user(&task::current_process(), out, &code.to_le_bytes()) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

/// 64-byte record: pid u64, threads u32, abi u8, exited u8, pad[2], name[40], mem KiB u32, pad[4].
fn proc_list(h: u64, index: u64, buf: u64) -> i64 {
    match lookup(h, Rights::READ) {
        Ok(CapObject::Sys) => {}
        Ok(_) => return -EINVAL,
        Err(e) => return -e,
    }
    let procs = task::list_processes();
    let Some(pr) = procs.get(index as usize) else { return -ENOENT };
    let mut rec = [0u8; 64];
    rec[0..8].copy_from_slice(&pr.pid.to_le_bytes());
    rec[8..12].copy_from_slice(&(pr.live_threads.load(Ordering::Relaxed) as u32).to_le_bytes());
    rec[12] = pr.abi() as u8;
    rec[13] = pr.has_exited() as u8;
    let nb = pr.name.as_bytes();
    let n = nb.len().min(39);
    rec[16..16 + n].copy_from_slice(&nb[..n]);
    rec[56..60].copy_from_slice(&((pr.mem_pages() * 4) as u32).to_le_bytes()); // KiB
    match uaccess::copy_to_user(&task::current_process(), buf, &rec) {
        Ok(()) => 64,
        Err(e) => -e,
    }
}

/// 16-byte record: handle u64, kind u32, rights u32 (the caller's own table only).
fn cap_list(index: u64, buf: u64) -> i64 {
    let p = task::current_process();
    let Some((h, kind, r)) = p.caps.lock().nth_live(index as usize) else { return -ENOENT };
    let mut rec = [0u8; 16];
    rec[0..8].copy_from_slice(&h.to_le_bytes());
    rec[8..12].copy_from_slice(&(kind as u32).to_le_bytes());
    rec[12..16].copy_from_slice(&r.0.to_le_bytes());
    match uaccess::copy_to_user(&p, buf, &rec) {
        Ok(()) => 16,
        Err(e) => -e,
    }
}

fn net_grant(admin: u64, ip: u64, port: u64, secs: u64, bytes: u64) -> i64 {
    match lookup(admin, Rights::GRANT) {
        Ok(CapObject::NetAdmin) => {}
        Ok(_) => return -EINVAL,
        Err(e) => return -e,
    }
    if ip > u32::MAX as u64 || port == 0 || port > 65535 || secs == 0 || secs > 3600 || bytes == 0 {
        return -EINVAL;
    }
    let g = match crate::net::issue_grant(crate::net::Proto::Tcp, (ip as u32).to_be_bytes(), 32, (port as u16, port as u16), secs * 1000, bytes) {
        Ok(g) => g,
        Err(_) => return -EINVAL,
    };
    let p = task::current_process();
    let r = p.caps.lock().insert(CapObject::Net(g), Rights::NET | Rights::DUP);
    match r {
        Ok(h) => h as i64,
        Err(e) => -e,
    }
}

const UPD_REQ_SIZE: usize = 256;

fn upd_code(e: &crate::upd::UpdError) -> i32 {
    use crate::upd::UpdError::*;
    match e {
        Net(_) => 1,
        Http(_) => 2,
        BadResponse(_) => 3,
        TooLarge => 4,
        BadPath => 5,
        SigFormat(_) => 6,
        UnknownKey => 7,
        BadSignature => 8,
        ManifestFormat(_) => 9,
        NotNewer { .. } => 10,
        BelowMinVersion { .. } => 11,
        ArtifactSize(_) => 12,
        ArtifactHash(_) => 13,
    }
}

/// Request layout (256 bytes): ip[4] @0, port u16 @4, op u16 @6 (0 = check, 1 = check + stage), base_len u32 @8,
/// code i32 @12 (out), version[3] u16 @16 (out), base[64] @24, message[168] @88 (out, NUL-terminated).
fn upd(net_h: u64, req_ptr: u64) -> i64 {
    let g = match lookup(net_h, Rights::NET) {
        Ok(CapObject::Net(g)) => g,
        Ok(_) => return -EINVAL,
        Err(e) => return -e,
    };
    let p = task::current_process();
    let mut req = [0u8; UPD_REQ_SIZE];
    if let Err(e) = uaccess::copy_from_user(&p, &mut req, req_ptr) {
        return -e;
    }
    let ip = [req[0], req[1], req[2], req[3]];
    let port = u16::from_le_bytes([req[4], req[5]]);
    let op = u16::from_le_bytes([req[6], req[7]]);
    let blen = u32::from_le_bytes([req[8], req[9], req[10], req[11]]) as usize;
    if blen > 64 || op > 1 {
        return -EINVAL;
    }
    let Ok(base) = core::str::from_utf8(&req[24..24 + blen]) else { return -EINVAL };
    let base: String = String::from(base);
    let srv = crate::upd::Server { ip, port };
    let mut msg = String::new();
    let (code, ver) = match crate::upd::check(&g, srv, &base) {
        Err(e) => {
            msg = format!("{:?}", e);
            (upd_code(&e), [0u16; 3])
        }
        Ok(info) => {
            let v = info.manifest.version;
            if op == 1 {
                match crate::upd::fetch_and_stage(&g, srv, &base, &info) {
                    Ok(()) => {
                        let disk = match crate::upd::persist_staged() {
                            crate::upd::PersistOutcome::Saved(_) => "and saved to the store".into(),
                            crate::upd::PersistOutcome::NoStore => String::from("only (no store disk)"),
                            crate::upd::PersistOutcome::Failed(e) => format!("but saving failed: {:?}", e),
                        };
                        msg = format!("staged {}.{}.{} in RAM {} ({} files); activation is not implemented", v[0], v[1], v[2], disk, info.manifest.artifacts.len())
                    }
                    Err(e) => {
                        msg = format!("{:?}", e);
                        return finish_upd(&p, req_ptr, &mut req, upd_code(&e), v, &msg);
                    }
                }
            } else {
                msg = format!("update available: {}.{}.{} ({} artifacts)", v[0], v[1], v[2], info.manifest.artifacts.len());
            }
            (0, v)
        }
    };
    finish_upd(&p, req_ptr, &mut req, code, ver, &msg)
}

fn finish_upd(p: &task::Process, req_ptr: u64, req: &mut [u8; UPD_REQ_SIZE], code: i32, ver: [u16; 3], msg: &str) -> i64 {
    req[12..16].copy_from_slice(&code.to_le_bytes());
    for i in 0..3 {
        req[16 + 2 * i..18 + 2 * i].copy_from_slice(&ver[i].to_le_bytes());
    }
    let b = msg.as_bytes();
    let n = b.len().min(167);
    req[88..88 + n].copy_from_slice(&b[..n]);
    req[88 + n] = 0;
    match uaccess::copy_to_user(p, req_ptr, &req[..]) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

fn power(h: u64, op: u64) -> i64 {
    match lookup(h, Rights::EXEC) {
        Ok(CapObject::Power) => {}
        Ok(_) => return -EINVAL,
        Err(e) => return -e,
    }
    crate::audit_log!(crate::audit::EV_SYSCALL, SYS_POWER, h, op, 0, 0);
    crate::tty::write(if op == 0 { b"powering off\n" } else { b"rebooting\n" });
    crate::arch::x86_64::power(op == 1)
}

// ---------------------------------------------------------------- persistent store ---

fn store_err(e: crate::store::StoreErr) -> i64 {
    e.errno()
}

/// `upd.*` belongs to the kernel updater: user programs may read it but never create, replace or delete it.
fn kernel_reserved(name: &str) -> bool {
    crate::store::is_reserved(name)
}

fn store_name(p: &task::Process, ptr: u64, len: usize) -> Result<String, i64> {
    let raw = user_bytes(p, ptr, len, crate::store::NAME_MAX)?;
    let s = core::str::from_utf8(&raw).map_err(|_| EINVAL)?;
    if !crate::store::valid_name(s) {
        return Err(EINVAL);
    }
    Ok(String::from(s))
}

fn need_store(h: u64, need: Rights) -> Result<(), i64> {
    match lookup(h, need) {
        Ok(CapObject::Store) => Ok(()),
        Ok(_) => Err(EINVAL),
        Err(e) => Err(e),
    }
}

/// Returns `size << 8 | name_len`; name copied to `buf` (>= 47 bytes). -ENOENT past the last file.
fn store_list(h: u64, index: u64, buf: u64, max: usize) -> i64 {
    if let Err(e) = need_store(h, Rights::READ) {
        return -e;
    }
    let r = crate::store::with(|s| s.list().get(index as usize).map(|e| (e.name.clone(), e.size)));
    let (name, size) = match r {
        Err(e) => return -store_err(e),
        Ok(None) => return -ENOENT,
        Ok(Some(x)) => x,
    };
    if max < name.len() {
        return -ERANGE;
    }
    if let Err(e) = uaccess::copy_to_user(&task::current_process(), buf, name.as_bytes()) {
        return -e;
    }
    ((size as i64) << 8) | name.len() as i64
}

fn store_open(h: u64, name: u64, len: usize) -> i64 {
    if let Err(e) = need_store(h, Rights::READ) {
        return -e;
    }
    let p = task::current_process();
    let n = match store_name(&p, name, len) {
        Ok(n) => n,
        Err(e) => return -e,
    };
    let data = match crate::store::with(|s| s.read(&n)) {
        Err(e) | Ok(Err(e)) => return -store_err(e),
        Ok(Ok(d)) => d,
    };
    let f = alloc::sync::Arc::new(crate::store::StoredFile { name: n, data });
    let r = p.caps.lock().insert(CapObject::StoreFile(f), Rights::READ | Rights::EXEC);
    match r {
        Ok(h) => h as i64,
        Err(e) => -e,
    }
}

fn store_write(h: u64, name: u64, len: usize, data: u64, dlen: usize) -> i64 {
    if let Err(e) = need_store(h, Rights::WRITE) {
        return -e;
    }
    let p = task::current_process();
    let n = match store_name(&p, name, len) {
        Ok(n) => n,
        Err(e) => return -e,
    };
    if kernel_reserved(&n) {
        return -EPERM;
    }
    let bytes = match user_bytes(&p, data, dlen, crate::store::MAX_FILE_BYTES) {
        Ok(v) => v,
        Err(_) => return -EFBIG,
    };
    let r = crate::store::with(|s| s.write(&n, &bytes));
    crate::audit_log!(crate::audit::EV_SYSCALL, SYS_STORE_WRITE, h, dlen as u64, 0, if matches!(r, Ok(Ok(()))) { 0 } else { -1 });
    match r {
        Err(e) | Ok(Err(e)) => -store_err(e),
        Ok(Ok(())) => 0,
    }
}

/// A store path from user memory: UTF-8, leading '/' and an optional "store/" prefix tolerated.
fn store_path(p: &task::Process, ptr: u64, len: usize) -> Result<String, i64> {
    let raw = user_bytes(p, ptr, len, crate::store::PATH_MAX)?;
    let s = core::str::from_utf8(&raw).map_err(|_| EINVAL)?;
    if s.bytes().any(|b| b == 0) {
        return Err(EINVAL);
    }
    let s = s.trim_start_matches('/');
    let s = if s == "store" { "" } else { s.strip_prefix("store/").unwrap_or(s) };
    Ok(String::from(s))
}

fn guarded(path: &str, destructive: bool) -> bool {
    let c = path.split('/').find(|c| !c.is_empty() && *c != ".").unwrap_or("");
    crate::store::is_reserved(c) || (destructive && c == "de.conf")
}

/// Hierarchical store access. ops (need READ unless marked W = WRITE):
/// 0 stat(path) -> 32-byte record at a4 {kind u8 @0 (1 file, 2 dir, 3 symlink), mode u16 @2, size u64 @8, mtime u64 @16, ino u32 @24}
/// 1 readdir(path, a5 = index) -> 320-byte record at a4 {kind u8 @0, size u64 @8, name from @16}; returns name length, -ENOENT past the end
/// 2 mkdir W | 3 rmdir W | 4 unlink W | 5 rename W (a4/a5 = destination ptr/len) | 6 symlink W (a4/a5 = target ptr/len)
/// 7 readlink(path) -> bytes at a4 (capacity a5), returns length | 8 chmod W (a4 = mode)
/// 9 read(path) -> bytes at a4 (capacity a5), returns the file size (larger than a5 means "truncated, retry bigger")
/// 10 write W (a4/a5 = data ptr/len): create or atomically replace.
fn store_fs(h: u64, op: u64, path: u64, plen: usize, a4: u64, a5: u64) -> i64 {
    let need = if matches!(op, 0 | 1 | 7 | 9) { Rights::READ } else { Rights::WRITE };
    if let Err(e) = need_store(h, need) {
        return -e;
    }
    let p = task::current_process();
    let path = match store_path(&p, path, plen) {
        Ok(s) => s,
        Err(e) => return -e,
    };
    if need == Rights::WRITE && guarded(&path, op != 10 && op != 8) {
        return -EPERM;
    }
    macro_rules! st {
        ($e:expr) => {
            match crate::store::with($e) {
                Err(e) | Ok(Err(e)) => return -store_err(e),
                Ok(Ok(v)) => v,
            }
        };
    }
    let out = |buf: u64, data: &[u8]| -> i64 {
        match uaccess::copy_to_user(&p, buf, data) {
            Ok(()) => 0,
            Err(e) => -e,
        }
    };
    let kind_code = |k: crate::store::Kind| -> u8 {
        match k {
            crate::store::Kind::File => 1,
            crate::store::Kind::Dir => 2,
            crate::store::Kind::Symlink => 3,
        }
    };
    let r = match op {
        0 => {
            let s = st!(|s| s.stat(&path, false));
            let mut rec = [0u8; 32];
            rec[0] = kind_code(s.kind);
            rec[2..4].copy_from_slice(&s.mode.to_le_bytes());
            rec[8..16].copy_from_slice(&s.size.to_le_bytes());
            rec[16..24].copy_from_slice(&s.mtime.to_le_bytes());
            rec[24..28].copy_from_slice(&s.ino.to_le_bytes());
            out(a4, &rec)
        }
        1 => {
            let ents = st!(|s| s.readdir(&path));
            let Some(e) = ents.get(a5 as usize) else { return -ENOENT };
            let mut rec = [0u8; 320];
            rec[0] = kind_code(e.kind);
            rec[8..16].copy_from_slice(&e.size.to_le_bytes());
            let n = e.name.len().min(300);
            rec[16..16 + n].copy_from_slice(&e.name.as_bytes()[..n]);
            let r = out(a4, &rec);
            if r < 0 {
                return r;
            }
            return n as i64;
        }
        2 => {
            st!(|s| s.mkdir(&path));
            0
        }
        3 => {
            st!(|s| s.rmdir(&path));
            0
        }
        4 => {
            st!(|s| s.unlink(&path));
            0
        }
        5 => {
            let to = match store_path(&p, a4, a5 as usize) {
                Ok(s) => s,
                Err(e) => return -e,
            };
            if guarded(&to, true) {
                return -EPERM;
            }
            st!(|s| s.rename(&path, &to));
            0
        }
        6 => {
            let raw = match user_bytes(&p, a4, a5 as usize, crate::store::SYMLINK_MAX) {
                Ok(v) => v,
                Err(e) => return -e,
            };
            let Ok(t) = core::str::from_utf8(&raw) else { return -EINVAL };
            st!(|s| s.symlink(t, &path));
            0
        }
        7 => {
            let t = st!(|s| s.readlink(&path));
            let n = t.len().min(a5 as usize);
            let r = out(a4, &t.as_bytes()[..n]);
            if r < 0 {
                return r;
            }
            return n as i64;
        }
        8 => {
            st!(|s| s.chmod(&path, a4 as u16));
            0
        }
        9 => {
            let d = st!(|s| s.read(&path));
            let n = d.len().min(a5 as usize);
            let r = out(a4, &d[..n]);
            if r < 0 {
                return r;
            }
            return d.len() as i64;
        }
        10 => {
            let bytes = match user_bytes(&p, a4, a5 as usize, crate::store::MAX_FILE_BYTES) {
                Ok(v) => v,
                Err(_) => return -EFBIG,
            };
            st!(|s| s.write(&path, &bytes));
            0
        }
        _ => -EINVAL,
    };
    if need == Rights::WRITE {
        crate::audit_log!(crate::audit::EV_SYSCALL, SYS_STORE_FS, h, op, 0, r);
    }
    r
}

/// op 0: delete `name` (WRITE) | op 1: stats -> six u64 at `out`: total, data, used bytes, files, generation, directories (READ)
/// | op 2: format the disk, destroying all data (GRANT).
fn store_ctl(h: u64, op: u64, name: u64, len: usize, out: u64) -> i64 {
    let p = task::current_process();
    match op {
        0 => {
            if let Err(e) = need_store(h, Rights::WRITE) {
                return -e;
            }
            let n = match store_name(&p, name, len) {
                Ok(n) => n,
                Err(e) => return -e,
            };
            if kernel_reserved(&n) {
                return -EPERM;
            }
            match crate::store::with(|s| s.delete(&n)) {
                Err(e) | Ok(Err(e)) => -store_err(e),
                Ok(Ok(())) => 0,
            }
        }
        1 => {
            if let Err(e) = need_store(h, Rights::READ) {
                return -e;
            }
            let st = match crate::store::with(|s| s.stats()) {
                Ok(s) => s,
                Err(e) => return -store_err(e),
            };
            let mut rec = [0u8; 48];
            for (i, v) in [st.total_bytes, st.data_bytes, st.used_bytes, st.files as u64, st.generation, st.dirs as u64].iter().enumerate() {
                rec[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
            }
            match uaccess::copy_to_user(&p, out, &rec) {
                Ok(()) => 0,
                Err(e) => -e,
            }
        }
        2 => {
            if let Err(e) = need_store(h, Rights::GRANT) {
                return -e;
            }
            crate::audit_log!(crate::audit::EV_SYSCALL, SYS_STORE_CTL, h, 2, 0, 0);
            match crate::store::format_device() {
                Ok(()) => 0,
                Err(e) => -store_err(e),
            }
        }
        _ => -EINVAL,
    }
}

/// op 0 list (a2 = index, a4 = out 64-byte record: name[40] hash[16] flags(1=R,2=W)@56 once@57), READ;
/// op 1 set (a2/a3 = program file name in the initramfs or store, a4 = flags: bit0 R, bit1 W, bit8 once), WRITE;
/// op 2 revoke (a2/a3 = name), WRITE.
fn perm_ctl(h: u64, op: u64, a2: u64, a3: usize, a4: u64) -> i64 {
    let p = task::current_process();
    let need = if op == 0 { Rights::READ } else { Rights::WRITE };
    match lookup(h, need) {
        Ok(CapObject::Policy) => {}
        Ok(_) => return -EINVAL,
        Err(e) => return -e,
    }
    match op {
        0 => {
            let list = crate::perm::list();
            let Some(e) = list.get(a2 as usize) else { return -ENOENT };
            let mut rec = [0u8; 80];
            let n = e.name.len().min(39);
            rec[..n].copy_from_slice(&e.name.as_bytes()[..n]);
            rec[40..56].copy_from_slice(e.hash.as_bytes());
            rec[56] = e.read as u8 | (e.write as u8) << 1;
            rec[57] = e.once as u8;
            if let Some(r) = e.net {
                rec[58] = 1; // network rule: rec[56] bit0 = allowed
                if let Some((ip, port)) = r.dest {
                    rec[60..64].copy_from_slice(&ip);
                    rec[64..66].copy_from_slice(&port.to_le_bytes());
                }
                rec[66] = r.dest.is_none() as u8 | (r.public_only as u8) << 1; // bit0 any host, bit1 internet only
                rec[68..72].copy_from_slice(&r.secs.to_le_bytes());
                rec[72..76].copy_from_slice(&r.kib.to_le_bytes());
            }
            match uaccess::copy_to_user(&p, a4, &rec) {
                Ok(()) => 80,
                Err(e) => -e,
            }
        }
        1 | 2 | 3 => {
            let name = match store_name(&p, a2, a3) {
                Ok(n) => n,
                Err(e) => return -e,
            };
            if op == 2 {
                return if crate::perm::revoke(&name) { 0 } else { -ENOENT };
            }
            let data = if let Some(f) = crate::fs::root().and_then(|d| d.lookup(&name)) {
                f.data.to_vec()
            } else {
                match crate::store::with(|s| s.read(&name)) {
                    Ok(Ok(d)) => d,
                    _ => return -ENOENT,
                }
            };
            let hash = crate::perm::image_hash(&data);
            if op == 3 {
                // network rule: a4 -> 16-byte struct { ip[4], port u16, allow u8, flags u8 (bit0 any host, bit1 internet only), secs u32, kib u32 }
                let mut b = [0u8; 16];
                if let Err(e) = uaccess::copy_from_user(&p, &mut b, a4) {
                    return -e;
                }
                let (ip, port) = ([b[0], b[1], b[2], b[3]], u16::from_le_bytes([b[4], b[5]]));
                let any = b[7] & 1 != 0;
                if !any && port == 0 && ip != [0; 4] {
                    return -EINVAL; // port 0 is only valid for the DNS scope (0.0.0.0:0)
                }
                let rule = crate::perm::NetRule {
                    dest: if any { None } else { Some((ip, port)) },
                    secs: u32::from_le_bytes(b[8..12].try_into().unwrap()),
                    kib: u32::from_le_bytes(b[12..16].try_into().unwrap()),
                    public_only: b[7] & 2 != 0,
                };
                crate::perm::set_net(&name, &hash, rule, b[6] != 0);
                return 0;
            }
            crate::perm::set(&name, &hash, a4 & 1 != 0, a4 & 2 != 0, a4 & 0x100 != 0);
            crate::audit_log!(crate::audit::EV_SYSCALL, SYS_PERM, h, a4, 0, 0);
            0
        }
        _ => -EINVAL,
    }
}
