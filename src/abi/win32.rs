//! kernel32 file/console API for PE programs, on top of the capability-gated `vfs` (see `msvcrt` for stdio).
//! Handles: 4/8/12 = stdin/stdout/stderr; files and directory searches are `0x100 + 4 * fd slot`.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::nt::{set_err, write_file as write_std};
use super::{msvcrt::read_cstr, vfs};
use crate::sys::uaccess::copy_to_user;
use crate::task::Process;

type A = [u64; 4];
const INVALID: u64 = u64::MAX;
const STD_IN: u64 = 4;
const ERR_FILE_NOT_FOUND: u32 = 2;
const ERR_ACCESS_DENIED: u32 = 5;
const ERR_INVALID_HANDLE: u32 = 6;
const ERR_FILE_EXISTS: u32 = 80;
const ERR_NO_MORE_FILES: u32 = 18;

fn slot(h: u64) -> Option<usize> {
    if h >= 0x100 && h % 4 == 0 { Some(((h - 0x100) / 4) as usize) } else { None }
}
fn handle(slot: usize) -> u64 {
    0x100 + slot as u64 * 4
}
fn stack(p: &Arc<Process>, k: usize) -> u64 {
    let rsp = p.foreign.lock().nt_rsp;
    let mut b = [0u8; 8];
    let _ = crate::sys::uaccess::copy_from_user(p, &mut b, rsp + super::msvcrt::STACK_ARG0 + 8 * (k as u64 - 4));
    u64::from_le_bytes(b)
}
/// A Win32 path from user memory: backslashes become '/', a leading drive letter ("C:") is dropped.
fn path_arg(p: &Arc<Process>, va: u64) -> String {
    let s = String::from_utf8_lossy(&read_cstr(p, va, 260)).replace('\\', "/");
    let b = s.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        return String::from(&s[2..]);
    }
    s
}
fn err_for(e: i64) -> u32 {
    match e {
        vfs::ENOENT => ERR_FILE_NOT_FOUND,
        vfs::EACCES => ERR_ACCESS_DENIED,
        _ => ERR_ACCESS_DENIED,
    }
}

pub fn create_file(p: &Arc<Process>, a: A) -> u64 {
    let path = path_arg(p, a[0]);
    let access = a[1] as u32;
    let disp = stack(p, 4) as u32;
    let write = access & 0x4000_0000 != 0;
    if vfs::is_dir_path(path.trim_end_matches('/')) || path == "." {
        set_err(p, ERR_ACCESS_DENIED);
        return INVALID;
    }
    let exists = vfs::open(p, &path, false, false, false, false).is_ok();
    let (create, trunc) = match disp {
        1 => {
            if exists {
                set_err(p, ERR_FILE_EXISTS);
                return INVALID;
            }
            (true, false)
        }
        2 => (true, true),
        3 => (false, false),
        4 => (true, false),
        5 => (false, true),
        _ => (false, false),
    };
    if !write && (create || trunc) && disp != 4 {
        // opening for read only with a create disposition: treat as plain open
    }
    let w = write || (create && disp != 4 && disp != 3) || trunc;
    match vfs::open(p, &path, w, create && w, trunc && w, false) {
        Ok(f) => match vfs::alloc(p, f) {
            Ok(i) => handle(i),
            Err(_) => {
                set_err(p, 4); // ERROR_TOO_MANY_OPEN_FILES
                INVALID
            }
        },
        Err(e) => {
            set_err(p, err_for(e));
            INVALID
        }
    }
}

pub fn read_file(p: &Arc<Process>, a: A) -> u64 {
    let (h, buf, n) = (a[0], a[1], a[2] as u32 as usize);
    let data: Vec<u8> = if h == STD_IN {
        match super::stdin_read(p, n.min(64 * 1024)) {
            Ok(v) => v,
            Err(_) => {
                set_err(p, ERR_INVALID_HANDLE);
                return 0;
            }
        }
    } else if let Some(i) = slot(h) {
        let mut tmp = alloc::vec![0u8; n.min(8 << 20)];
        let mut g = p.foreign.lock();
        match g.fds.get_mut(i).and_then(|s| s.as_mut()) {
            Some(f) if !f.is_dir() => {
                let got = vfs::read(f, &mut tmp);
                tmp.truncate(got);
                tmp
            }
            _ => {
                drop(g);
                set_err(p, ERR_INVALID_HANDLE);
                return 0;
            }
        }
    } else {
        set_err(p, ERR_INVALID_HANDLE);
        return 0;
    };
    if copy_to_user(p, buf, &data).is_err() {
        set_err(p, 998);
        return 0;
    }
    if a[3] != 0 {
        let _ = copy_to_user(p, a[3], &(data.len() as u32).to_le_bytes());
    }
    1
}

pub fn write_file(p: &Arc<Process>, a: A) -> u64 {
    let Some(i) = slot(a[0]) else { return write_std(p, a) };
    let n = a[2] as u32 as usize;
    if n > 8 << 20 {
        set_err(p, 8);
        return 0;
    }
    let mut data = alloc::vec![0u8; n];
    if crate::sys::uaccess::copy_from_user(p, &mut data, a[1]).is_err() {
        set_err(p, 998);
        return 0;
    }
    let r = {
        let mut g = p.foreign.lock();
        match g.fds.get_mut(i).and_then(|s| s.as_mut()) {
            Some(f) => vfs::write(f, &data).map_err(|e| e),
            None => Err(vfs::EBADF),
        }
    };
    match r {
        Ok(w) => {
            if a[3] != 0 {
                let _ = copy_to_user(p, a[3], &(w as u32).to_le_bytes());
            }
            1
        }
        Err(e) => {
            set_err(p, if e == vfs::EBADF { ERR_INVALID_HANDLE } else { ERR_ACCESS_DENIED });
            0
        }
    }
}

pub fn close_handle(p: &Arc<Process>, a: A) -> u64 {
    if matches!(a[0], 4 | 8 | 12) {
        return 1;
    }
    match slot(a[0]).map(|i| vfs::close(p, i)) {
        Some(Ok(())) => 1,
        _ => {
            set_err(p, ERR_INVALID_HANDLE);
            0
        }
    }
}

pub fn get_file_size(p: &Arc<Process>, a: A) -> u64 {
    let Some(i) = slot(a[0]) else {
        set_err(p, ERR_INVALID_HANDLE);
        return 0xFFFF_FFFF;
    };
    let len = {
        let g = p.foreign.lock();
        g.fds.get(i).and_then(|s| s.as_ref()).map(|f| f.len() as u64)
    };
    match len {
        Some(l) => {
            if a[1] != 0 {
                let _ = copy_to_user(p, a[1], &((l >> 32) as u32).to_le_bytes());
            }
            l & 0xFFFF_FFFF
        }
        None => {
            set_err(p, ERR_INVALID_HANDLE);
            0xFFFF_FFFF
        }
    }
}

pub fn set_file_pointer(p: &Arc<Process>, a: A) -> u64 {
    let Some(i) = slot(a[0]) else {
        set_err(p, ERR_INVALID_HANDLE);
        return 0xFFFF_FFFF;
    };
    let mut g = p.foreign.lock();
    match g.fds.get_mut(i).and_then(|s| s.as_mut()) {
        Some(f) => match vfs::seek(f, a[1] as u32 as i32 as i64, a[3] & 3) {
            Ok(v) => v & 0xFFFF_FFFF,
            Err(_) => 0xFFFF_FFFF,
        },
        None => 0xFFFF_FFFF,
    }
}

pub fn flush_file_buffers(p: &Arc<Process>, a: A) -> u64 {
    if let Some(i) = slot(a[0]) {
        let mut g = p.foreign.lock();
        if let Some(Some(f)) = g.fds.get_mut(i) {
            return vfs::flush(f).is_ok() as u64;
        }
    }
    1
}

pub fn delete_file(p: &Arc<Process>, a: A) -> u64 {
    match vfs::unlink(p, &path_arg(p, a[0])) {
        Ok(()) => 1,
        Err(e) => {
            set_err(p, err_for(e));
            0
        }
    }
}

pub fn get_file_attributes(p: &Arc<Process>, a: A) -> u64 {
    let path = path_arg(p, a[0]);
    if vfs::is_dir_path(path.trim_end_matches('/')) || path == "C:" || path == "C:/" || vfs::is_dir_abs(p, &vfs::resolve_abs(p, &path)) {
        return 0x10;
    }
    if vfs::open(p, &path, false, false, false, false).is_ok() {
        0x80
    } else {
        set_err(p, ERR_FILE_NOT_FOUND);
        0xFFFF_FFFF
    }
}

pub fn get_file_type(_: &Arc<Process>, a: A) -> u64 {
    if matches!(a[0], 4 | 8 | 12) { 2 } else { 1 }
}

fn glob(pat: &[u8], s: &[u8]) -> bool {
    match (pat.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => glob(&pat[1..], s) || (!s.is_empty() && glob(pat, &s[1..])),
        (Some(b'?'), Some(_)) => glob(&pat[1..], &s[1..]),
        (Some(c), Some(d)) if c.eq_ignore_ascii_case(d) => glob(&pat[1..], &s[1..]),
        _ => false,
    }
}

/// `entry` is a directory listing name ("name" or "name/" for directories); `dirpath` the listed directory.
fn fill_find(p: &Arc<Process>, out: u64, entry: &str, dirpath: &str) {
    let is_dir = entry.ends_with('/');
    let name = entry.trim_end_matches('/');
    let size = if is_dir {
        0
    } else {
        vfs::open(p, &alloc::format!("{}/{}", dirpath.trim_end_matches('/'), name), false, false, false, false).map(|f| f.len() as u64).unwrap_or(0)
    };
    let mut d = alloc::vec![0u8; 320];
    d[0..4].copy_from_slice(&(if is_dir { 0x10u32 } else { 0x80 }).to_le_bytes());
    d[28..32].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
    d[32..36].copy_from_slice(&(size as u32).to_le_bytes());
    let n = name.len().min(259);
    d[44..44 + n].copy_from_slice(&name.as_bytes()[..n]);
    let _ = copy_to_user(p, out, &d);
}

/// Advance the directory search in slot `i` to the next entry matching its pattern.
fn find_step(p: &Arc<Process>, i: usize) -> Option<(String, String)> {
    let mut g = p.foreign.lock();
    let f = g.fds.get_mut(i)?.as_mut()?;
    let vfs::Data::Dir(names) = &f.data else { return None };
    // f.name = "<directory path>\0<pattern>"
    let (dirpath, pat) = match f.name.split_once('\0') {
        Some((d, pt)) => (String::from(d), String::from(pt)),
        None => (String::from("/"), f.name.clone()),
    };
    while f.pos < names.len() {
        let n = names[f.pos].clone();
        f.pos += 1;
        if glob(pat.as_bytes(), n.trim_end_matches('/').as_bytes()) {
            return Some((n, dirpath));
        }
    }
    None
}

pub fn find_first_file(p: &Arc<Process>, a: A) -> u64 {
    let pat = path_arg(p, a[0]);
    let (dirpart, last) = match pat.rfind('/') {
        Some(i) => (&pat[..i], &pat[i + 1..]),
        None => ("", pat.as_str()),
    };
    let mut dir = if dirpart.is_empty() {
        vfs::open_dir(p)
    } else {
        match vfs::open(p, dirpart, false, false, false, false) {
            Ok(f) if f.is_dir() => f,
            _ => {
                set_err(p, 3); // ERROR_PATH_NOT_FOUND
                return INVALID;
            }
        }
    };
    dir.name = alloc::format!("{}\0{}", dir.name, if last.is_empty() { "*" } else { last });
    let Ok(i) = vfs::alloc(p, dir) else {
        set_err(p, 4);
        return INVALID;
    };
    match find_step(p, i) {
        Some((n, d)) => {
            fill_find(p, a[1], &n, &d);
            handle(i)
        }
        None => {
            let _ = vfs::close(p, i);
            set_err(p, ERR_FILE_NOT_FOUND);
            INVALID
        }
    }
}

pub fn find_next_file(p: &Arc<Process>, a: A) -> u64 {
    let Some(i) = slot(a[0]) else {
        set_err(p, ERR_INVALID_HANDLE);
        return 0;
    };
    match find_step(p, i) {
        Some((n, d)) => {
            fill_find(p, a[1], &n, &d);
            1
        }
        None => {
            set_err(p, ERR_NO_MORE_FILES);
            0
        }
    }
}

pub fn find_close(p: &Arc<Process>, a: A) -> u64 {
    close_handle(p, a)
}

pub fn get_module_file_name(p: &Arc<Process>, a: A) -> u64 {
    let mut s: alloc::vec::Vec<u8> = match crate::exec::dll::module_name(p, a[0]) {
        Some(n) => alloc::format!("C:\\deloxy\\{}", n).into_bytes(),
        None => b"C:\\deloxy\\app.exe".to_vec(),
    };
    s.push(0);
    let n = s.len().min(a[2] as usize);
    let _ = copy_to_user(p, a[1], &s[..n]);
    (s.len() - 1).min(n) as u64
}

pub fn get_current_directory(p: &Arc<Process>, a: A) -> u64 {
    if a[0] < 4 {
        return 4;
    }
    let _ = copy_to_user(p, a[1], b"C:\\\0");
    3
}

pub fn get_env_var(p: &Arc<Process>, _: A) -> u64 {
    set_err(p, 203); // ERROR_ENVVAR_NOT_FOUND
    0
}

pub fn get_console_mode(p: &Arc<Process>, a: A) -> u64 {
    if !matches!(a[0], 4 | 8 | 12) {
        set_err(p, ERR_INVALID_HANDLE);
        return 0;
    }
    if a[1] != 0 {
        let _ = copy_to_user(p, a[1], &7u32.to_le_bytes());
    }
    1
}

pub fn one(_: &Arc<Process>, _: A) -> u64 {
    1
}

pub fn get_local_time(p: &Arc<Process>, a: A) -> u64 {
    let c = crate::time::wall_clock();
    let (y, mo, d, h, mi, s) = match c {
        Some(c) => (c.year, c.month, c.day, c.hour, c.min, c.sec),
        None => (2026, 1, 1, 0, 0, 0),
    };
    let mut b = [0u8; 16];
    for (i, v) in [y, mo as u16, 0, d as u16, h as u16, mi as u16, s as u16, (crate::time::uptime_ms() % 1000) as u16].iter().enumerate() {
        b[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
    }
    let _ = copy_to_user(p, a[0], &b);
    0
}

pub fn create_directory(p: &Arc<Process>, a: A) -> u64 {
    match vfs::mkdir(p, &path_arg(p, a[0])) {
        Ok(()) => 1,
        Err(17) => {
            set_err(p, 183); // ERROR_ALREADY_EXISTS
            0
        }
        Err(e) => {
            set_err(p, if e == vfs::ENOENT { 3 } else { ERR_ACCESS_DENIED }); // ERROR_PATH_NOT_FOUND
            0
        }
    }
}

pub fn remove_directory(p: &Arc<Process>, a: A) -> u64 {
    match vfs::rmdir(p, &path_arg(p, a[0])) {
        Ok(()) => 1,
        Err(e) => {
            set_err(p, match e {
                vfs::ENOENT => 3,
                39 => 145, // ERROR_DIR_NOT_EMPTY
                _ => ERR_ACCESS_DENIED,
            });
            0
        }
    }
}

pub fn move_file(p: &Arc<Process>, a: A) -> u64 {
    match vfs::rename(p, &path_arg(p, a[0]), &path_arg(p, a[1])) {
        Ok(()) => 1,
        Err(e) => {
            set_err(p, err_for(e));
            0
        }
    }
}
