//! A hand-written subset of the Microsoft C runtime (`msvcrt.dll`) for PE programs built with MinGW-w64.
//! Implemented in the kernel behind the same SYSCALL thunks as kernel32 (Windows x64 calling convention);
//! files go through `vfs` (capability-gated). Limits: no wide-char stdio, no scanf, no locale, no signals,
//! `qsort`/`bsearch`/`atexit` (they must call user code) are NOT provided, `%e`/`%g` print like `%f`, and
//! `malloc` never reuses freed memory (bump allocator).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::nt::{heap_alloc, heap_realloc, set_err, DATA_PAGE3, NT_THUNK_BASE};
use super::{console_write, vfs};
use crate::exec::write_user;
use crate::sys::uaccess::{copy_from_user, copy_to_user};
use crate::task::{self, Process};

// ---- layout of the msvcrt globals page (NT_DATA_BASE + 3 pages) ----
pub const G_FMODE: u64 = DATA_PAGE3;
pub const G_COMMODE: u64 = DATA_PAGE3 + 0x08;
pub const G_INITENV: u64 = DATA_PAGE3 + 0x10;
pub const G_ENVIRON: u64 = DATA_PAGE3 + 0x18;
pub const G_ENVARR: u64 = DATA_PAGE3 + 0x20; // char*[2] = { NULL, NULL }
pub const G_ERRNO: u64 = DATA_PAGE3 + 0x40;
pub const G_STRERR: u64 = DATA_PAGE3 + 0x60; // "error\0"
pub const G_DOT: u64 = DATA_PAGE3 + 0x80; // ".\0"
pub const G_EMPTY: u64 = DATA_PAGE3 + 0x84; // "\0"
pub const G_LCONV: u64 = DATA_PAGE3 + 0xA0; // struct lconv (0x60 bytes)
pub const G_IOB: u64 = DATA_PAGE3 + 0x100; // FILE[3 + MAX_FDS], 48 bytes each
pub const G_ATEXIT_TAB: u64 = DATA_PAGE3 + 0xDC0; // 32 function pointers
pub const G_ATEXIT_N: u64 = DATA_PAGE3 + 0xEC0;
pub const FILE_SIZE: u64 = 48;

pub const STACK_ARG0: u64 = 8 + 32; // offset of the 5th argument from the user rsp at SYSCALL time

pub fn init_globals(p: &Arc<Process>) -> Result<(), crate::exec::ExecError> {
    let mut page = alloc::vec![0u8; 0x100];
    page[0x60..0x66].copy_from_slice(b"error\0");
    page[0x80..0x82].copy_from_slice(b".\0");
    // lconv: decimal_point -> ".", every other string member -> ""
    for i in 0..10 {
        let ptr = if i == 0 { G_DOT } else { G_EMPTY };
        page[0xA0 + i * 8..0xA0 + i * 8 + 8].copy_from_slice(&ptr.to_le_bytes());
    }
    page[0x40..0x44].copy_from_slice(&0u32.to_le_bytes());
    write_user(p, DATA_PAGE3, &page)
}

// ------------------------------------------------------------ helpers ---

pub fn stack_arg(p: &Arc<Process>, k: usize) -> u64 {
    let rsp = p.foreign.lock().nt_rsp;
    let mut b = [0u8; 8];
    if copy_from_user(p, &mut b, rsp + STACK_ARG0 + 8 * (k as u64 - 4)).is_err() {
        return 0;
    }
    u64::from_le_bytes(b)
}

fn read_u64(p: &Arc<Process>, va: u64) -> u64 {
    let mut b = [0u8; 8];
    if copy_from_user(p, &mut b, va).is_err() {
        return 0;
    }
    u64::from_le_bytes(b)
}

pub fn read_cstr(p: &Arc<Process>, va: u64, max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    while out.len() < max {
        if copy_from_user(p, &mut b, va + out.len() as u64).is_err() || b[0] == 0 {
            break;
        }
        out.push(b[0]);
    }
    out
}

fn read_bytes(p: &Arc<Process>, va: u64, n: usize) -> Option<Vec<u8>> {
    if n > 32 << 20 {
        return None;
    }
    let mut v = alloc::vec![0u8; n];
    copy_from_user(p, &mut v, va).ok()?;
    Some(v)
}

/// Variadic argument source: registers/stack of the call (`first` = index of the first variadic argument),
/// or a `va_list` pointer (Win64: a pointer to consecutive 8-byte slots).
struct Va<'a> {
    p: &'a Arc<Process>,
    regs: [u64; 4],
    idx: usize,
    list: Option<u64>,
}

impl<'a> Va<'a> {
    fn call(p: &'a Arc<Process>, regs: [u64; 4], first: usize) -> Va<'a> {
        Va { p, regs, idx: first, list: None }
    }
    fn list(p: &'a Arc<Process>, ptr: u64) -> Va<'a> {
        Va { p, regs: [0; 4], idx: 0, list: Some(ptr) }
    }
    fn next(&mut self) -> u64 {
        if let Some(ptr) = self.list {
            self.list = Some(ptr + 8);
            return read_u64(self.p, ptr);
        }
        let v = if self.idx < 4 { self.regs[self.idx] } else { stack_arg(self.p, self.idx) };
        self.idx += 1;
        v
    }
}

// ----------------------------------------------------------- printf ---

fn pad(out: &mut Vec<u8>, body: &[u8], width: usize, left: bool, zero: bool) {
    let n = body.len();
    if n >= width {
        out.extend_from_slice(body);
    } else if left {
        out.extend_from_slice(body);
        out.resize(out.len() + width - n, b' ');
    } else if zero {
        // zeros go after any sign / 0x prefix
        let split = if body.first().map_or(false, |c| *c == b'-' || *c == b'+' || *c == b' ') { 1 } else { 0 };
        out.extend_from_slice(&body[..split]);
        out.resize(out.len() + width - n, b'0');
        out.extend_from_slice(&body[split..]);
    } else {
        out.resize(out.len() + width - n, b' ');
        out.extend_from_slice(body);
    }
}

fn utoa(mut v: u64, base: u64, upper: bool) -> Vec<u8> {
    if v == 0 {
        return alloc::vec![b'0'];
    }
    let digits = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut b = Vec::new();
    while v > 0 {
        b.push(digits[(v % base) as usize]);
        v /= base;
    }
    b.reverse();
    b
}

/// Fixed-point decimal text of an f64 with `prec` fractional digits (integer arithmetic only).
fn fixed(v: f64, prec: usize) -> Vec<u8> {
    let bits = v.to_bits();
    let neg = bits >> 63 != 0;
    let exp = ((bits >> 52) & 0x7FF) as i32;
    let frac = bits & ((1u64 << 52) - 1);
    let mut out = Vec::new();
    if exp == 0x7FF {
        out.extend_from_slice(if frac != 0 { b"nan" } else if neg { b"-inf" } else { b"inf" });
        return out;
    }
    let (mant, e) = if exp == 0 { (frac, -1074) } else { (frac | (1u64 << 52), exp - 1075) };
    let prec = prec.min(18);
    let scale = 10u128.pow(prec as u32);
    let scaled: u128 = if e >= 0 {
        if e > 60 {
            out.extend_from_slice(b"1e+999");
            return out;
        }
        ((mant as u128) << e) * scale
    } else {
        let s = (-e) as u32;
        if s >= 120 {
            0
        } else {
            let prod = (mant as u128) * scale; // < 2^53 * 10^18 < 2^113
            (prod + (1u128 << (s - 1))) >> s
        }
    };
    if neg {
        out.push(b'-');
    }
    let mut digits = Vec::new();
    let mut t = scaled;
    if t == 0 {
        digits.push(b'0');
    }
    while t > 0 {
        digits.push(b'0' + (t % 10) as u8);
        t /= 10;
    }
    while digits.len() <= prec {
        digits.push(b'0');
    }
    digits.reverse();
    let int_len = digits.len() - prec;
    out.extend_from_slice(&digits[..int_len]);
    if prec > 0 {
        out.push(b'.');
        out.extend_from_slice(&digits[int_len..]);
    }
    out
}

fn format(p: &Arc<Process>, fmt: &[u8], va: &mut Va) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < fmt.len() {
        let c = fmt[i];
        i += 1;
        if c != b'%' {
            out.push(c);
            continue;
        }
        let (mut left, mut plus, mut space, mut alt, mut zero) = (false, false, false, false, false);
        while i < fmt.len() {
            match fmt[i] {
                b'-' => left = true,
                b'+' => plus = true,
                b' ' => space = true,
                b'#' => alt = true,
                b'0' => zero = true,
                _ => break,
            }
            i += 1;
        }
        let mut width = 0usize;
        if i < fmt.len() && fmt[i] == b'*' {
            let w = va.next() as i32;
            if w < 0 {
                left = true;
            }
            width = w.unsigned_abs() as usize;
            i += 1;
        } else {
            while i < fmt.len() && fmt[i].is_ascii_digit() {
                width = width * 10 + (fmt[i] - b'0') as usize;
                i += 1;
            }
        }
        let mut prec: Option<usize> = None;
        if i < fmt.len() && fmt[i] == b'.' {
            i += 1;
            let mut pr = 0usize;
            if i < fmt.len() && fmt[i] == b'*' {
                let v = va.next() as i32;
                pr = v.max(0) as usize;
                i += 1;
            } else {
                while i < fmt.len() && fmt[i].is_ascii_digit() {
                    pr = pr * 10 + (fmt[i] - b'0') as usize;
                    i += 1;
                }
            }
            prec = Some(pr);
        }
        // length modifiers: h hh l ll I64 I32 I z j t L w
        let mut long = false; // 64-bit integer argument
        loop {
            match fmt.get(i) {
                Some(b'h') | Some(b'l') | Some(b'L') | Some(b'w') => {
                    if fmt[i] == b'l' && fmt.get(i + 1) == Some(&b'l') {
                        long = true;
                        i += 1;
                    }
                    i += 1;
                }
                Some(b'z') | Some(b'j') | Some(b't') => {
                    long = true;
                    i += 1;
                }
                Some(b'I') => {
                    if fmt.get(i + 1) == Some(&b'6') && fmt.get(i + 2) == Some(&b'4') {
                        long = true;
                        i += 3;
                    } else if fmt.get(i + 1) == Some(&b'3') && fmt.get(i + 2) == Some(&b'2') {
                        i += 3;
                    } else {
                        long = true; // %Id = ptrdiff-sized
                        i += 1;
                    }
                }
                _ => break,
            }
        }
        let Some(&conv) = fmt.get(i) else { break };
        i += 1;
        match conv {
            b'%' => out.push(b'%'),
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' => {
                let v = f64::from_bits(va.next());
                let mut body = super::winmath::fmt_float(v, conv, prec, alt, conv.is_ascii_uppercase());
                if !v.is_nan() && !v.is_sign_negative() {
                    if plus {
                        body.insert(0, b'+');
                    } else if space {
                        body.insert(0, b' ');
                    }
                }
                pad(&mut out, &body, width, left, zero && v.is_finite());
            }
            b'c' => {
                let ch = va.next() as u8;
                pad(&mut out, &[ch], width, left, false);
            }
            b's' => {
                let ptr = va.next();
                let s = if ptr == 0 { b"(null)".to_vec() } else { read_cstr(p, ptr, prec.unwrap_or(4096).min(1 << 16)) };
                let s = match prec {
                    Some(n) if s.len() > n => s[..n].to_vec(),
                    _ => s,
                };
                pad(&mut out, &s, width, left, false);
            }
            b'd' | b'i' => {
                let raw = va.next();
                let v: i64 = if long { raw as i64 } else { raw as u32 as i32 as i64 };
                let mut body = Vec::new();
                if v < 0 {
                    body.push(b'-');
                } else if plus {
                    body.push(b'+');
                } else if space {
                    body.push(b' ');
                }
                let mut digits = utoa(v.unsigned_abs(), 10, false);
                if let Some(pr) = prec {
                    while digits.len() < pr {
                        digits.insert(0, b'0');
                    }
                }
                body.extend_from_slice(&digits);
                pad(&mut out, &body, width, left, zero && prec.is_none());
            }
            b'u' | b'x' | b'X' | b'o' => {
                let raw = va.next();
                let v: u64 = if long { raw } else { raw as u32 as u64 };
                let base = match conv {
                    b'o' => 8,
                    b'u' => 10,
                    _ => 16,
                };
                let mut body = Vec::new();
                if alt && v != 0 && base == 16 {
                    body.extend_from_slice(if conv == b'X' { b"0X" } else { b"0x" });
                }
                let mut digits = utoa(v, base, conv == b'X');
                if let Some(pr) = prec {
                    while digits.len() < pr {
                        digits.insert(0, b'0');
                    }
                }
                body.extend_from_slice(&digits);
                pad(&mut out, &body, width, left, zero && prec.is_none());
            }
            b'p' => {
                let v = va.next();
                let mut body = b"0x".to_vec();
                body.extend_from_slice(&utoa(v, 16, false));
                pad(&mut out, &body, width, left, false);
            }
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' => {
                let v = f64::from_bits(va.next());
                let mut body = fixed(v, prec.unwrap_or(6));
                if conv == b'g' || conv == b'G' {
                    // %g: drop trailing zeros of the fractional part
                    if body.contains(&b'.') {
                        while body.last() == Some(&b'0') {
                            body.pop();
                        }
                        if body.last() == Some(&b'.') {
                            body.pop();
                        }
                    }
                }
                if body.first() != Some(&b'-') {
                    if plus {
                        body.insert(0, b'+');
                    } else if space {
                        body.insert(0, b' ');
                    }
                }
                pad(&mut out, &body, width, left, zero);
            }
            _ => {
                out.push(b'%');
                out.push(conv);
            }
        }
    }
    out
}

// ------------------------------------------------------------ streams ---

enum Stream {
    Stdin,
    Out,
    File(usize),
    Invalid,
}

fn stream(f: u64) -> Stream {
    if f < G_IOB || (f - G_IOB) % FILE_SIZE != 0 {
        return Stream::Invalid;
    }
    let id = (f - G_IOB) / FILE_SIZE;
    match id {
        0 => Stream::Stdin,
        1 | 2 => Stream::Out,
        n if (n as usize) < 3 + vfs::MAX_FDS => Stream::File(n as usize - 3),
        _ => Stream::Invalid,
    }
}

fn file_ptr(slot: usize) -> u64 {
    G_IOB + (3 + slot as u64) * FILE_SIZE
}

fn stream_write(p: &Arc<Process>, f: u64, data: &[u8]) -> Option<usize> {
    match stream(f) {
        Stream::Out => console_write(p, "pe", data).ok().map(|_| data.len()),
        Stream::File(i) => {
            let mut g = p.foreign.lock();
            let file = g.fds.get_mut(i)?.as_mut()?;
            vfs::write(file, data).ok()
        }
        _ => None,
    }
}

fn stream_read(p: &Arc<Process>, f: u64, n: usize) -> Vec<u8> {
    if let Stream::Stdin = stream(f) {
        if p.foreign.lock().stdin_eof {
            return Vec::new();
        }
        return match super::stdin_read(p, n.min(64 * 1024)) {
            Ok(v) => {
                if v.is_empty() {
                    p.foreign.lock().stdin_eof = true;
                }
                v
            }
            Err(_) => Vec::new(),
        };
    }
    if let Stream::File(i) = stream(f) {
        let mut g = p.foreign.lock();
        if let Some(Some(file)) = g.fds.get_mut(i) {
            let mut v = alloc::vec![0u8; n.min(8 << 20)];
            let got = vfs::read(file, &mut v);
            v.truncate(got);
            if got < n {
                file.eof = true;
            }
            return v;
        }
    }
    Vec::new()
}

// -------------------------------------------------------------- shims ---
type A = [u64; 4];

pub fn iob_func(_: &Arc<Process>, _: A) -> u64 {
    G_IOB
}

pub fn fopen(p: &Arc<Process>, a: A) -> u64 {
    let path = read_cstr(p, a[0], 256);
    let mode = read_cstr(p, a[1], 8);
    let path = match String::from_utf8(path) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let plus = mode.contains(&b'+');
    let (write, create, trunc, append) = match mode.first() {
        Some(b'r') => (plus, false, false, false),
        Some(b'w') => (true, true, true, false),
        Some(b'a') => (true, true, false, true),
        _ => return 0,
    };
    match vfs::open(p, &path, write, create, trunc, append) {
        Ok(f) => match vfs::alloc(p, f) {
            Ok(i) => file_ptr(i),
            Err(_) => 0,
        },
        Err(e) => {
            let _ = write_user(p, G_ERRNO, &(e as u32).to_le_bytes());
            0
        }
    }
}

pub fn fclose(p: &Arc<Process>, a: A) -> u64 {
    match stream(a[0]) {
        Stream::File(i) => match vfs::close(p, i) {
            Ok(()) => 0,
            Err(_) => u64::MAX,
        },
        Stream::Invalid => u64::MAX,
        _ => 0,
    }
}

pub fn fwrite(p: &Arc<Process>, a: A) -> u64 {
    let (size, n) = (a[1], a[2]);
    let total = (size.saturating_mul(n)) as usize;
    if size == 0 || n == 0 {
        return 0;
    }
    let Some(data) = read_bytes(p, a[0], total) else { return 0 };
    match stream_write(p, a[3], &data) {
        Some(w) => w as u64 / size,
        None => 0,
    }
}

pub fn fread(p: &Arc<Process>, a: A) -> u64 {
    let (size, n) = (a[1], a[2]);
    if size == 0 || n == 0 {
        return 0;
    }
    let v = stream_read(p, a[3], (size.saturating_mul(n)) as usize);
    let items = v.len() as u64 / size;
    if copy_to_user(p, a[0], &v[..(items * size) as usize]).is_err() {
        return 0;
    }
    items
}

pub fn fputc(p: &Arc<Process>, a: A) -> u64 {
    let c = a[0] as u8;
    match stream_write(p, a[1], &[c]) {
        Some(_) => c as u64,
        None => u64::MAX & 0xFFFF_FFFF,
    }
}

pub fn putchar(p: &Arc<Process>, a: A) -> u64 {
    fputc(p, [a[0], G_IOB + FILE_SIZE, 0, 0])
}

pub fn fputs(p: &Arc<Process>, a: A) -> u64 {
    let s = read_cstr(p, a[0], 1 << 20);
    match stream_write(p, a[1], &s) {
        Some(_) => 1,
        None => 0xFFFF_FFFF,
    }
}

pub fn puts(p: &Arc<Process>, a: A) -> u64 {
    let mut s = read_cstr(p, a[0], 1 << 20);
    s.push(b'\n');
    match stream_write(p, G_IOB + FILE_SIZE, &s) {
        Some(_) => 1,
        None => 0xFFFF_FFFF,
    }
}

pub fn fgetc(p: &Arc<Process>, a: A) -> u64 {
    let v = stream_read(p, a[0], 1);
    v.first().map_or(0xFFFF_FFFF, |b| *b as u64)
}

pub fn fgets(p: &Arc<Process>, a: A) -> u64 {
    let max = (a[1] as u32 as usize).min(1 << 16);
    if max < 2 {
        return 0;
    }
    let mut line = Vec::new();
    while line.len() < max - 1 {
        let b = stream_read(p, a[2], 1);
        let Some(&c) = b.first() else { break };
        line.push(c);
        if c == b'\n' {
            break;
        }
    }
    if line.is_empty() {
        return 0;
    }
    line.push(0);
    if copy_to_user(p, a[0], &line).is_err() {
        return 0;
    }
    a[0]
}

pub fn fseek(p: &Arc<Process>, a: A) -> u64 {
    if let Stream::File(i) = stream(a[0]) {
        let mut g = p.foreign.lock();
        if let Some(Some(f)) = g.fds.get_mut(i) {
            f.eof = false;
            return if vfs::seek(f, a[1] as u32 as i32 as i64, a[2] & 3).is_ok() { 0 } else { u64::MAX & 0xFFFF_FFFF };
        }
    }
    0xFFFF_FFFF
}

pub fn ftell(p: &Arc<Process>, a: A) -> u64 {
    if let Stream::File(i) = stream(a[0]) {
        let g = p.foreign.lock();
        if let Some(Some(f)) = g.fds.get(i) {
            return f.pos as u64;
        }
    }
    0xFFFF_FFFF
}

pub fn rewind(p: &Arc<Process>, a: A) -> u64 {
    fseek(p, [a[0], 0, 0, 0]);
    0
}

pub fn feof(p: &Arc<Process>, a: A) -> u64 {
    match stream(a[0]) {
        Stream::File(i) => {
            let g = p.foreign.lock();
            g.fds.get(i).and_then(|s| s.as_ref()).map_or(1, |f| f.eof as u64)
        }
        Stream::Stdin => p.foreign.lock().stdin_eof as u64,
        _ => 0,
    }
}

pub fn fflush(p: &Arc<Process>, a: A) -> u64 {
    if let Stream::File(i) = stream(a[0]) {
        let mut g = p.foreign.lock();
        if let Some(Some(f)) = g.fds.get_mut(i) {
            return if vfs::flush(f).is_ok() { 0 } else { 0xFFFF_FFFF };
        }
    }
    0
}

pub fn remove(p: &Arc<Process>, a: A) -> u64 {
    let path = String::from_utf8_lossy(&read_cstr(p, a[0], 256)).into_owned();
    crate::perm::resolve(p);
    let (w,) = { let g = p.foreign.lock(); (g.fs_store_write,) };
    let Ok((name, _)) = vfs::normalize(&path) else { return 0xFFFF_FFFF };
    if !w || crate::store::is_reserved(&name) {
        return 0xFFFF_FFFF;
    }
    match crate::store::with(|s| s.delete(&name)) {
        Ok(Ok(())) => 0,
        _ => 0xFFFF_FFFF,
    }
}

pub fn printf(p: &Arc<Process>, a: A) -> u64 {
    let fmt = read_cstr(p, a[0], 1 << 16);
    let out = format(p, &fmt, &mut Va::call(p, a, 1));
    stream_write(p, G_IOB + FILE_SIZE, &out).map_or(0xFFFF_FFFF, |n| n as u64)
}

pub fn fprintf(p: &Arc<Process>, a: A) -> u64 {
    let fmt = read_cstr(p, a[1], 1 << 16);
    let out = format(p, &fmt, &mut Va::call(p, a, 2));
    stream_write(p, a[0], &out).map_or(0xFFFF_FFFF, |n| n as u64)
}

pub fn vfprintf(p: &Arc<Process>, a: A) -> u64 {
    let fmt = read_cstr(p, a[1], 1 << 16);
    let out = format(p, &fmt, &mut Va::list(p, a[2]));
    stream_write(p, a[0], &out).map_or(0xFFFF_FFFF, |n| n as u64)
}

pub fn vprintf(p: &Arc<Process>, a: A) -> u64 {
    vfprintf(p, [G_IOB + FILE_SIZE, a[0], a[1], 0])
}

fn put_buf(p: &Arc<Process>, buf: u64, cap: usize, data: &[u8]) -> u64 {
    // write at most cap-1 bytes + NUL; returns the full length (C99 snprintf semantics)
    if cap > 0 {
        let n = data.len().min(cap - 1);
        let mut v = data[..n].to_vec();
        v.push(0);
        let _ = copy_to_user(p, buf, &v);
    }
    data.len() as u64
}

pub fn sprintf(p: &Arc<Process>, a: A) -> u64 {
    let fmt = read_cstr(p, a[1], 1 << 16);
    let out = format(p, &fmt, &mut Va::call(p, a, 2));
    put_buf(p, a[0], usize::MAX >> 1, &out)
}

pub fn snprintf(p: &Arc<Process>, a: A) -> u64 {
    let fmt = read_cstr(p, a[2], 1 << 16);
    let out = format(p, &fmt, &mut Va::call(p, a, 3));
    put_buf(p, a[0], a[1] as usize, &out)
}

pub fn vsnprintf(p: &Arc<Process>, a: A) -> u64 {
    let fmt = read_cstr(p, a[2], 1 << 16);
    let out = format(p, &fmt, &mut Va::list(p, a[3]));
    put_buf(p, a[0], a[1] as usize, &out)
}

pub fn vsprintf(p: &Arc<Process>, a: A) -> u64 {
    let fmt = read_cstr(p, a[1], 1 << 16);
    let out = format(p, &fmt, &mut Va::list(p, a[2]));
    put_buf(p, a[0], usize::MAX >> 1, &out)
}

// ---- memory ----
pub fn malloc(p: &Arc<Process>, a: A) -> u64 {
    heap_alloc(p, [0, 0, a[0], 0])
}
pub fn calloc(p: &Arc<Process>, a: A) -> u64 {
    heap_alloc(p, [0, 8, a[0].saturating_mul(a[1]), 0]) // flag 8: zero recycled blocks (fresh pages are already zero)
}
pub fn realloc(p: &Arc<Process>, a: A) -> u64 {
    heap_realloc(p, [0, 0, a[0], a[1]])
}
pub fn free(p: &Arc<Process>, a: A) -> u64 {
    super::nt::heap_free(p, a[0]);
    0
}
pub fn msize(p: &Arc<Process>, a: A) -> u64 {
    super::nt::heap_size(p, [0, 0, a[0], 0])
}

pub fn memcpy(p: &Arc<Process>, a: A) -> u64 {
    if let Some(v) = read_bytes(p, a[1], a[2] as usize) {
        let _ = copy_to_user(p, a[0], &v);
    }
    a[0]
}
pub fn memset(p: &Arc<Process>, a: A) -> u64 {
    let n = (a[2] as usize).min(32 << 20);
    let v = alloc::vec![a[1] as u8; n];
    let _ = copy_to_user(p, a[0], &v);
    a[0]
}
pub fn memcmp(p: &Arc<Process>, a: A) -> u64 {
    let (Some(x), Some(y)) = (read_bytes(p, a[0], a[2] as usize), read_bytes(p, a[1], a[2] as usize)) else { return 0 };
    for (c, d) in x.iter().zip(y.iter()) {
        if c != d {
            return (*c as i32 - *d as i32) as u32 as u64;
        }
    }
    0
}
pub fn strlen(p: &Arc<Process>, a: A) -> u64 {
    read_cstr(p, a[0], 16 << 20).len() as u64
}
pub fn strcpy(p: &Arc<Process>, a: A) -> u64 {
    let mut s = read_cstr(p, a[1], 16 << 20);
    s.push(0);
    let _ = copy_to_user(p, a[0], &s);
    a[0]
}
pub fn strncpy(p: &Arc<Process>, a: A) -> u64 {
    let n = (a[2] as usize).min(16 << 20);
    let mut s = read_cstr(p, a[1], n);
    s.resize(n, 0);
    let _ = copy_to_user(p, a[0], &s);
    a[0]
}
pub fn strcat(p: &Arc<Process>, a: A) -> u64 {
    let d = read_cstr(p, a[0], 16 << 20).len() as u64;
    let mut s = read_cstr(p, a[1], 16 << 20);
    s.push(0);
    let _ = copy_to_user(p, a[0] + d, &s);
    a[0]
}
fn cmp_bytes(x: &[u8], y: &[u8]) -> u64 {
    for i in 0..x.len().max(y.len()) {
        let (c, d) = (x.get(i).copied().unwrap_or(0), y.get(i).copied().unwrap_or(0));
        if c != d {
            return (c as i32 - d as i32) as u32 as u64;
        }
    }
    0
}
pub fn strcmp(p: &Arc<Process>, a: A) -> u64 {
    cmp_bytes(&read_cstr(p, a[0], 1 << 20), &read_cstr(p, a[1], 1 << 20))
}
pub fn strncmp(p: &Arc<Process>, a: A) -> u64 {
    let n = (a[2] as usize).min(1 << 20);
    cmp_bytes(&read_cstr(p, a[0], n), &read_cstr(p, a[1], n))
}
pub fn strchr(p: &Arc<Process>, a: A) -> u64 {
    let s = read_cstr(p, a[0], 16 << 20);
    let c = a[1] as u8;
    if c == 0 {
        return a[0] + s.len() as u64;
    }
    s.iter().position(|&b| b == c).map_or(0, |i| a[0] + i as u64)
}
pub fn strrchr(p: &Arc<Process>, a: A) -> u64 {
    let s = read_cstr(p, a[0], 16 << 20);
    let c = a[1] as u8;
    if c == 0 {
        return a[0] + s.len() as u64;
    }
    s.iter().rposition(|&b| b == c).map_or(0, |i| a[0] + i as u64)
}
pub fn strstr(p: &Arc<Process>, a: A) -> u64 {
    let h = read_cstr(p, a[0], 16 << 20);
    let n = read_cstr(p, a[1], 1 << 16);
    if n.is_empty() {
        return a[0];
    }
    h.windows(n.len()).position(|w| w == &n[..]).map_or(0, |i| a[0] + i as u64)
}
pub fn wcslen(p: &Arc<Process>, a: A) -> u64 {
    let mut n = 0u64;
    let mut b = [0u8; 2];
    while n < 1 << 20 && copy_from_user(p, &mut b, a[0] + n * 2).is_ok() && b != [0, 0] {
        n += 1;
    }
    n
}
pub fn toupper(_: &Arc<Process>, a: A) -> u64 {
    (a[0] as u8).to_ascii_uppercase() as u64
}
pub fn tolower(_: &Arc<Process>, a: A) -> u64 {
    (a[0] as u8).to_ascii_lowercase() as u64
}
pub fn atoi(p: &Arc<Process>, a: A) -> u64 {
    let s = read_cstr(p, a[0], 64);
    let t = String::from_utf8_lossy(&s);
    let t = t.trim_start();
    let (neg, d) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let mut v: i64 = 0;
    for c in d.bytes().take_while(|c| c.is_ascii_digit()) {
        v = v.wrapping_mul(10).wrapping_add((c - b'0') as i64);
    }
    (if neg { -v } else { v }) as i32 as u32 as u64
}
pub fn abs(_: &Arc<Process>, a: A) -> u64 {
    (a[0] as u32 as i32).unsigned_abs() as u64
}

// ---- process / environment ----
pub fn exit(p: &Arc<Process>, a: A) -> u64 {
    vfs::flush_all(p);
    task::sched::exit_process(a[0] as u32 as i64)
}
pub fn abort(p: &Arc<Process>, _: A) -> u64 {
    vfs::flush_all(p);
    task::sched::exit_process(3)
}
pub fn amsg_exit(p: &Arc<Process>, _: A) -> u64 {
    vfs::flush_all(p);
    task::sched::exit_process(255)
}
pub fn getmainargs(p: &Arc<Process>, a: A) -> u64 {
    let (argc, argv) = {
        let f = p.foreign.lock();
        (f.argc, f.argv_va)
    };
    let _ = write_user(p, a[0], &(argc as u32).to_le_bytes());
    let _ = write_user(p, a[1], &argv.to_le_bytes());
    let _ = write_user(p, a[2], &G_ENVARR.to_le_bytes());
    0
}
pub fn errno_ptr(_: &Arc<Process>, _: A) -> u64 {
    G_ERRNO
}
pub fn strerror(_: &Arc<Process>, _: A) -> u64 {
    G_STRERR
}
pub fn localeconv(_: &Arc<Process>, _: A) -> u64 {
    G_LCONV
}
pub fn one_(_: &Arc<Process>, _: A) -> u64 {
    1
}
pub fn zero_(_: &Arc<Process>, _: A) -> u64 {
    0
}
pub fn echo_arg0(_: &Arc<Process>, a: A) -> u64 {
    a[0]
}
pub fn time_(p: &Arc<Process>, a: A) -> u64 {
    let t = 1_790_000_000u64 + crate::time::uptime_ms() / 1000;
    if a[0] != 0 {
        let _ = copy_to_user(p, a[0], &t.to_le_bytes());
    }
    t
}
pub fn clock_(_: &Arc<Process>, _: A) -> u64 {
    crate::time::uptime_ms()
}
pub fn rand_(p: &Arc<Process>, _: A) -> u64 {
    p.foreign.lock().next_random() & 0x7FFF
}
pub fn srand_(p: &Arc<Process>, a: A) -> u64 {
    p.foreign.lock().rng = a[0] | 1;
    0
}

// ---- extra kernel32 pieces the MinGW startup code imports ----
pub fn multi_byte_to_wide(p: &Arc<Process>, a: A) -> u64 {
    // (cp, flags, src, srclen, dst, dstlen): ASCII/Latin-1 widening
    let srclen = a[3] as u32 as i32;
    let src = if srclen < 0 { let mut s = read_cstr(p, a[2], 1 << 20); s.push(0); s } else { read_bytes(p, a[2], srclen as usize).unwrap_or_default() };
    let dstlen = stack_arg(p, 5) as u32 as usize;
    let dst = stack_arg(p, 4);
    if dstlen == 0 {
        return src.len() as u64;
    }
    let mut w = Vec::new();
    for b in src.iter().take(dstlen) {
        w.extend_from_slice(&(*b as u16).to_le_bytes());
    }
    let _ = copy_to_user(p, dst, &w);
    src.len().min(dstlen) as u64
}
pub fn wide_to_multi_byte(p: &Arc<Process>, a: A) -> u64 {
    // (cp, flags, src, srclen, dst, dstlen, defchar, used): narrowing, non-Latin-1 -> '?'
    let srclen = a[3] as u32 as i32;
    let mut chars: Vec<u16> = Vec::new();
    let mut b = [0u8; 2];
    let mut i = 0u64;
    loop {
        if srclen >= 0 && i as i32 >= srclen {
            break;
        }
        if i > 1 << 20 || copy_from_user(p, &mut b, a[2] + i * 2).is_err() {
            break;
        }
        let c = u16::from_le_bytes(b);
        chars.push(c);
        i += 1;
        if srclen < 0 && c == 0 {
            break;
        }
    }
    let dstlen = stack_arg(p, 5) as u32 as usize;
    let dst = stack_arg(p, 4);
    if dstlen == 0 {
        return chars.len() as u64;
    }
    let out: Vec<u8> = chars.iter().take(dstlen).map(|&c| if c < 256 { c as u8 } else { b'?' }).collect();
    let _ = copy_to_user(p, dst, &out);
    out.len() as u64
}

pub fn set_errno_unused(p: &Arc<Process>) {
    set_err(p, 0);
}

/// Machine code run in user mode (loops that call user function pointers), placed in the thunk page at
/// `NT_THUNK_BASE + CODE_OFF + k * CODE_STRIDE`.
pub const CODE_OFF: u64 = 8192;
pub const CODE_STRIDE: u64 = 192;
pub static CODE_STUBS: &[(&str, &[u8])] = &[
    ("_initterm", &[0x53, 0x56, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x89, 0xCB, 0x48, 0x89, 0xD6, 0x48, 0x39, 0xF3, 0x73, 0x10, 0x48, 0x8B, 0x03, 0x48, 0x85, 0xC0, 0x74, 0x02, 0xFF, 0xD0, 0x48, 0x83, 0xC3, 0x08, 0xEB, 0xEB, 0x48, 0x83, 0xC4, 0x28, 0x5E, 0x5B, 0xC3]),
    ("_initterm_e", &[0x53, 0x56, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x89, 0xCB, 0x48, 0x89, 0xD6, 0x48, 0x39, 0xF3, 0x73, 0x14, 0x48, 0x8B, 0x03, 0x48, 0x85, 0xC0, 0x74, 0x06, 0xFF, 0xD0, 0x85, 0xC0, 0x75, 0x08, 0x48, 0x83, 0xC3, 0x08, 0xEB, 0xE7, 0x31, 0xC0, 0x48, 0x83, 0xC4, 0x28, 0x5E, 0x5B, 0xC3]),
    ("__C_specific_handler", &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]),
    ("qsort", &[0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x28, 0x49, 0x89, 0xCC, 0x49, 0x89, 0xD5, 0x4D, 0x89, 0xC6, 0x4D, 0x89, 0xCF, 0x49, 0x83, 0xFD, 0x02, 0x72, 0x53, 0x4D, 0x85, 0xF6, 0x74, 0x4E, 0x4C, 0x89, 0xED, 0x48, 0xFF, 0xCD, 0x48, 0x85, 0xED, 0x74, 0x43, 0x31, 0xDB, 0x48, 0x39, 0xEB, 0x73, 0x37, 0x48, 0x89, 0xD8, 0x49, 0x0F, 0xAF, 0xC6, 0x49, 0x8D, 0x34, 0x04, 0x4A, 0x8D, 0x3C, 0x36, 0x48, 0x89, 0xF1, 0x48, 0x89, 0xFA, 0x41, 0xFF, 0xD7, 0x85, 0xC0, 0x7E, 0x16, 0x4C, 0x89, 0xF1, 0x8A, 0x06, 0x8A, 0x17, 0x88, 0x16, 0x88, 0x07, 0x48, 0xFF, 0xC6, 0x48, 0xFF, 0xC7, 0x48, 0xFF, 0xC9, 0x75, 0xED, 0x48, 0xFF, 0xC3, 0xEB, 0xC4, 0x48, 0xFF, 0xCD, 0xEB, 0xB8, 0x48, 0x83, 0xC4, 0x28, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5F, 0x5E, 0x5B, 0x5D, 0xC3]),
    ("<thread_start>", &[0x48, 0x8B, 0x04, 0x24, 0x48, 0x8B, 0x4C, 0x24, 0x08, 0x48, 0x83, 0xEC, 0x20, 0xFF, 0xD0, 0x89, 0xC1, 0x48, 0xB8, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xFF, 0xD0, 0xCC]),
    ("exit", &[0x53, 0x56, 0x48, 0x83, 0xEC, 0x28, 0x89, 0xCB, 0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0x8B, 0x30, 0x48, 0x85, 0xF6, 0x74, 0x1D, 0x48, 0xFF, 0xCE, 0x48, 0x89, 0x30, 0x48, 0xB8, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x48, 0x8B, 0x04, 0xF0, 0x48, 0x85, 0xC0, 0x74, 0xD5, 0xFF, 0xD0, 0xEB, 0xD1, 0x89, 0xD9, 0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xFF, 0xD0, 0xCC]),
];

pub fn code_stub_addr(name: &str) -> Option<u64> {
    CODE_STUBS.iter().position(|(n, _)| *n == name).map(|k| NT_THUNK_BASE + CODE_OFF + k as u64 * CODE_STRIDE)
}

/// Data symbols: name -> address inside the globals page.
pub fn data_sym(name: &str) -> Option<u64> {
    Some(match name {
        "_fmode" => G_FMODE,
        "_commode" => G_COMMODE,
        "__initenv" => G_INITENV,
        "_environ" => G_ENVIRON,
        _ => return None,
    })
}


// ---- atexit table (run by the user-mode `exit` stub) ----
pub fn atexit(p: &Arc<Process>, a: A) -> u64 {
    let n = read_u64(p, G_ATEXIT_N);
    if n >= 32 || a[0] == 0 {
        return 0xFFFF_FFFF;
    }
    let _ = write_user(p, G_ATEXIT_TAB + n * 8, &a[0].to_le_bytes());
    let _ = write_user(p, G_ATEXIT_N, &(n + 1).to_le_bytes());
    0
}
pub fn onexit(p: &Arc<Process>, a: A) -> u64 {
    if atexit(p, a) == 0 { a[0] } else { 0 }
}

// ---- ctype ----
macro_rules! ctype {
    ($name:ident, $f:expr) => {
        pub fn $name(_: &Arc<Process>, a: A) -> u64 {
            let c = a[0] as u32;
            if c < 256 { ($f)(c as u8) as u64 } else { 0 }
        }
    };
}
ctype!(isalpha, |c: u8| c.is_ascii_alphabetic());
ctype!(isdigit, |c: u8| c.is_ascii_digit());
ctype!(isalnum, |c: u8| c.is_ascii_alphanumeric());
ctype!(isspace, |c: u8| c.is_ascii_whitespace() || c == 0x0B);
ctype!(isupper, |c: u8| c.is_ascii_uppercase());
ctype!(islower, |c: u8| c.is_ascii_lowercase());
ctype!(ispunct, |c: u8| c.is_ascii_punctuation());
ctype!(isxdigit, |c: u8| c.is_ascii_hexdigit());
ctype!(isprint, |c: u8| (0x20..0x7F).contains(&c));
ctype!(iscntrl, |c: u8| c < 0x20 || c == 0x7F);

// ---- numbers ----
fn parse_int(s: &[u8], base: u32) -> (i128, usize) {
    let mut i = 0;
    while i < s.len() && (s[i].is_ascii_whitespace() || s[i] == 0x0B) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'-' || s[i] == b'+') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut base = base;
    if (base == 0 || base == 16) && i + 1 < s.len() && s[i] == b'0' && (s[i + 1] | 0x20) == b'x' {
        base = 16;
        i += 2;
    } else if base == 0 {
        base = if i < s.len() && s[i] == b'0' { 8 } else { 10 };
    }
    let start = i;
    let mut v: i128 = 0;
    while i < s.len() {
        let d = match s[i] {
            c @ b'0'..=b'9' => (c - b'0') as u32,
            c @ b'a'..=b'z' => (c - b'a') as u32 + 10,
            c @ b'A'..=b'Z' => (c - b'A') as u32 + 10,
            _ => break,
        };
        if d >= base {
            break;
        }
        v = (v * base as i128 + d as i128).min(1 << 100);
        i += 1;
    }
    if i == start {
        return (0, 0);
    }
    (if neg { -v } else { v }, i)
}

fn strtox(p: &Arc<Process>, a: A, bits: u32, signed: bool) -> u64 {
    let s = read_cstr(p, a[0], 256);
    let (v, used) = parse_int(&s, a[2] as u32);
    if a[1] != 0 {
        let _ = write_user(p, a[1], &(a[0] + used as u64).to_le_bytes());
    }
    if bits == 32 {
        if signed { v.clamp(i32::MIN as i128, i32::MAX as i128) as i32 as u32 as u64 } else { v.clamp(0, u32::MAX as i128) as u32 as u64 }
    } else if signed {
        v.clamp(i64::MIN as i128, i64::MAX as i128) as i64 as u64
    } else {
        v.clamp(0, u64::MAX as i128) as u64
    }
}
pub fn strtol(p: &Arc<Process>, a: A) -> u64 {
    strtox(p, a, 32, true)
}
pub fn strtoul(p: &Arc<Process>, a: A) -> u64 {
    strtox(p, a, 32, false)
}
pub fn strtoll(p: &Arc<Process>, a: A) -> u64 {
    strtox(p, a, 64, true)
}
pub fn strtoull(p: &Arc<Process>, a: A) -> u64 {
    strtox(p, a, 64, false)
}
pub fn atol(p: &Arc<Process>, a: A) -> u64 {
    strtox(p, [a[0], 0, 10, 0], 32, true)
}
pub fn atoll(p: &Arc<Process>, a: A) -> u64 {
    strtox(p, [a[0], 0, 10, 0], 64, true)
}

// ---- scanf family (integers, hex, chars, strings; no floats) ----
fn scan(p: &Arc<Process>, input: &[u8], fmt: &[u8], va: &mut Va) -> (u64, usize) {
    let (mut i, mut f, mut assigned) = (0usize, 0usize, 0u64);
    let ws = |c: u8| c.is_ascii_whitespace();
    while f < fmt.len() {
        let c = fmt[f];
        f += 1;
        if ws(c) {
            while i < input.len() && ws(input[i]) {
                i += 1;
            }
            continue;
        }
        if c != b'%' {
            if i < input.len() && input[i] == c {
                i += 1;
                continue;
            }
            break;
        }
        let mut suppress = false;
        if fmt.get(f) == Some(&b'*') {
            suppress = true;
            f += 1;
        }
        let mut width = 0usize;
        while f < fmt.len() && fmt[f].is_ascii_digit() {
            width = width * 10 + (fmt[f] - b'0') as usize;
            f += 1;
        }
        let mut size = 4usize;
        loop {
            match fmt.get(f) {
                Some(b'h') => {
                    size = if fmt.get(f + 1) == Some(&b'h') { f += 1; 1 } else { 2 };
                    f += 1;
                }
                Some(b'l') => {
                    if fmt.get(f + 1) == Some(&b'l') {
                        size = 8;
                        f += 1;
                    }
                    f += 1;
                }
                Some(b'z') | Some(b'j') => {
                    size = 8;
                    f += 1;
                }
                Some(b'I') if fmt.get(f + 1) == Some(&b'6') => {
                    size = 8;
                    f += 3;
                }
                _ => break,
            }
        }
        let Some(&conv) = fmt.get(f) else { break };
        f += 1;
        if conv != b'c' && conv != b'%' {
            while i < input.len() && ws(input[i]) {
                i += 1;
            }
        }
        let max = if width == 0 { usize::MAX } else { width };
        match conv {
            b'%' => {
                if i < input.len() && input[i] == b'%' {
                    i += 1;
                } else {
                    break;
                }
            }
            b'd' | b'i' | b'u' | b'x' | b'X' | b'o' => {
                if i >= input.len() {
                    break;
                }
                let base = match conv {
                    b'x' | b'X' => 16,
                    b'o' => 8,
                    b'i' => 0,
                    _ => 10,
                };
                let end = i.saturating_add(max).min(input.len());
                let (v, used) = parse_int(&input[i..end], base);
                if used == 0 {
                    break;
                }
                i += used;
                if !suppress {
                    let ptr = va.next();
                    let bytes = (v as i64).to_le_bytes();
                    let _ = write_user(p, ptr, &bytes[..size.min(8)]);
                    assigned += 1;
                }
            }
            b'f' | b'e' | b'g' | b'E' | b'G' => {
                let end = i.saturating_add(max).min(input.len());
                let (v, used) = super::winmath::parse_float(&input[i..end]);
                if used == 0 {
                    break;
                }
                i += used;
                if !suppress {
                    let ptr = va.next();
                    let long = f >= 2 && matches!(fmt.get(f - 2), Some(b'l') | Some(b'L'));
                    if long {
                        let _ = write_user(p, ptr, &v.to_bits().to_le_bytes());
                    } else {
                        let _ = write_user(p, ptr, &(v as f32).to_bits().to_le_bytes());
                    }
                    assigned += 1;
                }
            }
            b'c' => {
                let n = if width == 0 { 1 } else { width };
                if i + n > input.len() {
                    break;
                }
                if !suppress {
                    let ptr = va.next();
                    let _ = write_user(p, ptr, &input[i..i + n]);
                    assigned += 1;
                }
                i += n;
            }
            b's' => {
                let st = i;
                while i < input.len() && !ws(input[i]) && i - st < max {
                    i += 1;
                }
                if i == st {
                    break;
                }
                if !suppress {
                    let ptr = va.next();
                    let mut v = input[st..i].to_vec();
                    v.push(0);
                    let _ = write_user(p, ptr, &v);
                    assigned += 1;
                }
            }
            _ => break,
        }
    }
    (assigned, i)
}

pub fn sscanf(p: &Arc<Process>, a: A) -> u64 {
    let input = read_cstr(p, a[0], 1 << 16);
    let fmt = read_cstr(p, a[1], 1 << 12);
    let (n, _) = scan(p, &input, &fmt, &mut Va::call(p, a, 2));
    if n == 0 && input.is_empty() { 0xFFFF_FFFF } else { n }
}

pub fn scanf(p: &Arc<Process>, a: A) -> u64 {
    let fmt = read_cstr(p, a[0], 1 << 12);
    let line = stream_read(p, G_IOB, 4096);
    if line.is_empty() {
        return 0xFFFF_FFFF;
    }
    let (n, _) = scan(p, &line, &fmt, &mut Va::call(p, a, 1));
    n
}

pub fn getchar(p: &Arc<Process>, _: A) -> u64 {
    fgetc(p, [G_IOB, 0, 0, 0])
}

/// Replace the placeholder constants in the assembled stubs with this layout's addresses.
pub fn build_stub(code: &[u8], exit_thunk: u64, thread_exit_thunk: u64) -> Vec<u8> {
    let mut v = code.to_vec();
    for (magic, val) in [(0xAAAA_AAAA_AAAA_AAAAu64, G_ATEXIT_N), (0xBBBB_BBBB_BBBB_BBBB, G_ATEXIT_TAB), (0xCCCC_CCCC_CCCC_CCCC, exit_thunk), (0xDDDD_DDDD_DDDD_DDDD, thread_exit_thunk)] {
        let m = magic.to_le_bytes();
        let mut i = 0;
        while i + 8 <= v.len() {
            if v[i..i + 8] == m {
                v[i..i + 8].copy_from_slice(&val.to_le_bytes());
                i += 8;
            } else {
                i += 1;
            }
        }
    }
    v
}


// ---- more common C runtime functions ----
pub fn ungetc(p: &Arc<Process>, a: A) -> u64 {
    let c = a[0] as u8;
    if a[0] as u32 == 0xFFFF_FFFF {
        return 0xFFFF_FFFF;
    }
    match stream(a[1]) {
        Stream::Stdin => {
            let mut f = p.foreign.lock();
            f.stdin_buf.insert(0, c);
            f.stdin_eof = false;
        }
        Stream::File(i) => {
            let mut g = p.foreign.lock();
            match g.fds.get_mut(i).and_then(|s| s.as_mut()) {
                Some(f) if f.pos > 0 => {
                    f.pos -= 1;
                    f.eof = false;
                }
                _ => return 0xFFFF_FFFF,
            }
        }
        _ => return 0xFFFF_FFFF,
    }
    c as u64
}

pub fn strdup(p: &Arc<Process>, a: A) -> u64 {
    let mut s = read_cstr(p, a[0], 16 << 20);
    s.push(0);
    let m = heap_alloc(p, [0, 0, s.len() as u64, 0]);
    if m != 0 {
        let _ = copy_to_user(p, m, &s);
    }
    m
}

pub fn perror(p: &Arc<Process>, a: A) -> u64 {
    let mut s = if a[0] != 0 { read_cstr(p, a[0], 256) } else { Vec::new() };
    if !s.is_empty() {
        s.extend_from_slice(b": ");
    }
    s.extend_from_slice(b"error\n");
    let _ = stream_write(p, G_IOB + 2 * FILE_SIZE, &s);
    0
}

pub fn setlocale(_: &Arc<Process>, _: A) -> u64 {
    G_DOT + 2 // "" -> use the empty string "C"-like locale (pointer to a NUL byte)
}

pub fn strcspn(p: &Arc<Process>, a: A) -> u64 {
    let (s, rej) = (read_cstr(p, a[0], 1 << 20), read_cstr(p, a[1], 1 << 12));
    s.iter().position(|c| rej.contains(c)).unwrap_or(s.len()) as u64
}
pub fn strspn(p: &Arc<Process>, a: A) -> u64 {
    let (s, acc) = (read_cstr(p, a[0], 1 << 20), read_cstr(p, a[1], 1 << 12));
    s.iter().position(|c| !acc.contains(c)).unwrap_or(s.len()) as u64
}
pub fn stricmp(p: &Arc<Process>, a: A) -> u64 {
    let (x, y) = (read_cstr(p, a[0], 1 << 20).to_ascii_lowercase(), read_cstr(p, a[1], 1 << 20).to_ascii_lowercase());
    cmp_bytes(&x, &y)
}
pub fn strnicmp(p: &Arc<Process>, a: A) -> u64 {
    let n = (a[2] as usize).min(1 << 20);
    let (x, y) = (read_cstr(p, a[0], n).to_ascii_lowercase(), read_cstr(p, a[1], n).to_ascii_lowercase());
    cmp_bytes(&x, &y)
}
pub fn memchr(p: &Arc<Process>, a: A) -> u64 {
    match read_bytes(p, a[0], a[2] as usize) {
        Some(v) => v.iter().position(|&b| b == a[1] as u8).map_or(0, |i| a[0] + i as u64),
        None => 0,
    }
}
pub fn fileno(_: &Arc<Process>, a: A) -> u64 {
    match stream(a[0]) {
        Stream::Stdin => 0,
        Stream::Out => (a[0] - G_IOB) / FILE_SIZE,
        Stream::File(i) => i as u64 + 3,
        Stream::Invalid => 0xFFFF_FFFF,
    }
}
pub fn minus1(_: &Arc<Process>, _: A) -> u64 {
    0xFFFF_FFFF
}
