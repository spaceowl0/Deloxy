//! Winsock (`ws2_32.dll` / `wsock32.dll`) subset for PE programs, on top of `abi::sock` (same consent rules as Linux:
//! connect/sendto ask per destination, `listen`/UDP `bind` ask per port, name lookups need the `dns` decision).
//! SOCKET values are `0x100 + 4 * fd slot` like file handles. Missing: overlapped I/O / WSAEventSelect, IPv6.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::msvcrt::{read_cstr, stack_arg};
use super::nt::{heap_alloc, set_err};
use super::sock::{self, Ty};
use super::vfs;
use crate::sys::uaccess::{copy_from_user, copy_to_user};
use crate::task::Process;

type A = [u64; 4];
const INVALID_SOCKET: u64 = u64::MAX;
const SOCKET_ERROR: u64 = u64::MAX;
const WSAEINVAL: u32 = 10022;
const WSAEFAULT: u32 = 10014;
const WSAEWOULDBLOCK: u32 = 10035;
const WSAEALREADY: u32 = 10037;
const WSAENOTSOCK: u32 = 10038;
const WSAEDESTADDRREQ: u32 = 10039;
const WSAEAFNOSUPPORT: u32 = 10047;
const WSAEADDRINUSE: u32 = 10048;
const WSAEACCES: u32 = 10013;
const WSAENETUNREACH: u32 = 10051;
const WSAECONNABORTED: u32 = 10053;
const WSAEISCONN: u32 = 10056;
const WSAENOTCONN: u32 = 10057;
const WSAETIMEDOUT: u32 = 10060;
const WSAECONNREFUSED: u32 = 10061;
const WSAEOPNOTSUPP: u32 = 10045;
const WSAEMSGSIZE: u32 = 10040;
const WSAHOST_NOT_FOUND: u32 = 11001;

fn slot(h: u64) -> Option<usize> {
    if h >= 0x100 && h % 4 == 0 { Some(((h - 0x100) / 4) as usize) } else { None }
}
fn wsa_err(e: i64) -> u32 {
    match e {
        sock::EAGAIN | sock::EINPROGRESS => WSAEWOULDBLOCK,
        sock::EALREADY => WSAEALREADY,
        sock::EACCES => WSAEACCES,
        sock::EPIPE => WSAECONNABORTED,
        sock::ENOTSOCK | vfs::EBADF => WSAENOTSOCK,
        sock::EISCONN => WSAEISCONN,
        sock::ENOTCONN => WSAENOTCONN,
        sock::ENETUNREACH => WSAENETUNREACH,
        sock::ETIMEDOUT => WSAETIMEDOUT,
        sock::ECONNREFUSED => WSAECONNREFUSED,
        sock::EADDRINUSE => WSAEADDRINUSE,
        sock::EDESTADDRREQ => WSAEDESTADDRREQ,
        sock::EOPNOTSUPP => WSAEOPNOTSUPP,
        sock::EINVAL => WSAEINVAL,
        90 => WSAEMSGSIZE,
        _ => WSAEACCES,
    }
}
fn fail(p: &Arc<Process>, e: u32) -> u64 {
    set_err(p, e);
    SOCKET_ERROR
}
fn fail_e(p: &Arc<Process>, e: i64) -> u64 {
    fail(p, wsa_err(e))
}
fn sock_slot(p: &Arc<Process>, h: u64) -> Result<usize, u64> {
    match slot(h) {
        Some(i) if sock::is_sock(p, i) => Ok(i),
        _ => Err(fail(p, WSAENOTSOCK)),
    }
}
fn read_sin(p: &Arc<Process>, ptr: u64, len: u64) -> Option<([u8; 4], u16)> {
    let mut b = [0u8; 8];
    if len < 8 || copy_from_user(p, &mut b, ptr).is_err() || u16::from_le_bytes([b[0], b[1]]) != 2 {
        return None;
    }
    Some(([b[4], b[5], b[6], b[7]], u16::from_be_bytes([b[2], b[3]])))
}
fn sin_bytes(ip: [u8; 4], port: u16) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..2].copy_from_slice(&2u16.to_le_bytes());
    b[2..4].copy_from_slice(&port.to_be_bytes());
    b[4..8].copy_from_slice(&ip);
    b
}
/// Write a sockaddr_in to `ptr` and the length to `lenp` (int*), if both are given.
fn write_sin(p: &Arc<Process>, ptr: u64, lenp: u64, ip: [u8; 4], port: u16) {
    if ptr == 0 || lenp == 0 {
        return;
    }
    let mut lb = [0u8; 4];
    if copy_from_user(p, &mut lb, lenp).is_err() {
        return;
    }
    let cap = (u32::from_le_bytes(lb) as usize).min(16);
    let _ = copy_to_user(p, ptr, &sin_bytes(ip, port)[..cap]);
    let _ = copy_to_user(p, lenp, &16u32.to_le_bytes());
}

pub fn startup(p: &Arc<Process>, a: A) -> u64 {
    let mut d = [0u8; 408];
    d[0..2].copy_from_slice(&0x0202u16.to_le_bytes());
    d[2..4].copy_from_slice(&0x0202u16.to_le_bytes());
    let _ = copy_to_user(p, a[1], &d);
    0
}
pub fn zero(_: &Arc<Process>, _: A) -> u64 {
    0
}
pub fn set_wsa_error(p: &Arc<Process>, a: A) -> u64 {
    set_err(p, a[0] as u32);
    0
}

pub fn socket(p: &Arc<Process>, a: A) -> u64 {
    if a[0] as u32 != 2 {
        set_err(p, WSAEAFNOSUPPORT);
        return INVALID_SOCKET;
    }
    let t = match a[1] as u32 {
        1 => Ty::Stream,
        2 => Ty::Dgram,
        _ => {
            set_err(p, 10044); // WSAESOCKTNOSUPPORT (no raw sockets)
            return INVALID_SOCKET;
        }
    };
    match sock::create(p, t, false) {
        Ok(i) => 0x100 + i as u64 * 4,
        Err(e) => {
            set_err(p, wsa_err(e));
            INVALID_SOCKET
        }
    }
}

pub fn connect(p: &Arc<Process>, a: A) -> u64 {
    let i = match sock_slot(p, a[0]) { Ok(i) => i, Err(e) => return e };
    let Some((ip, port)) = read_sin(p, a[1], a[2]) else { return fail(p, WSAEAFNOSUPPORT) };
    match sock::connect(p, i, ip, port) {
        Ok(()) => 0,
        Err(e) => fail_e(p, e),
    }
}

pub fn bind(p: &Arc<Process>, a: A) -> u64 {
    let i = match sock_slot(p, a[0]) { Ok(i) => i, Err(e) => return e };
    let Some((_ip, port)) = read_sin(p, a[1], a[2]) else { return fail(p, WSAEAFNOSUPPORT) };
    match sock::bind(p, i, port) {
        Ok(()) => 0,
        Err(e) => fail_e(p, e),
    }
}

pub fn listen(p: &Arc<Process>, a: A) -> u64 {
    let i = match sock_slot(p, a[0]) { Ok(i) => i, Err(e) => return e };
    match sock::listen(p, i, (a[1] as i32).max(1) as usize) {
        Ok(()) => 0,
        Err(e) => fail_e(p, e),
    }
}

/// accept(s, addr*, int* addrlen) -> SOCKET
pub fn accept(p: &Arc<Process>, a: A) -> u64 {
    let i = match sock_slot(p, a[0]) { Ok(i) => i, Err(_) => return INVALID_SOCKET };
    match sock::accept(p, i, false) {
        Ok((ns, (ip, port))) => {
            write_sin(p, a[1], a[2], ip, port);
            0x100 + ns as u64 * 4
        }
        Err(e) => {
            set_err(p, wsa_err(e));
            INVALID_SOCKET
        }
    }
}

pub fn send(p: &Arc<Process>, a: A) -> u64 {
    let i = match sock_slot(p, a[0]) { Ok(i) => i, Err(e) => return e };
    let n = (a[2] as u32 as usize).min(1 << 20);
    let mut buf = alloc::vec![0u8; n];
    if copy_from_user(p, &mut buf, a[1]).is_err() {
        return fail(p, WSAEFAULT);
    }
    match sock::send(p, i, &buf, false) {
        Ok(n) => n as u64,
        Err(e) => fail_e(p, e),
    }
}

pub fn recv(p: &Arc<Process>, a: A) -> u64 {
    let i = match sock_slot(p, a[0]) { Ok(i) => i, Err(e) => return e };
    match sock::recv(p, i, a[2] as u32 as usize, false) {
        Ok(v) => {
            if copy_to_user(p, a[1], &v).is_err() {
                return fail(p, WSAEFAULT);
            }
            v.len() as u64
        }
        Err(e) => fail_e(p, e),
    }
}

/// sendto(s, buf, len, flags, to*, tolen)
pub fn sendto(p: &Arc<Process>, a: A) -> u64 {
    let i = match sock_slot(p, a[0]) { Ok(i) => i, Err(e) => return e };
    let n = (a[2] as u32 as usize).min(1 << 20);
    let mut buf = alloc::vec![0u8; n];
    if copy_from_user(p, &mut buf, a[1]).is_err() {
        return fail(p, WSAEFAULT);
    }
    let (to, tolen) = (stack_arg(p, 4), stack_arg(p, 5));
    let r = if to != 0 {
        let Some(d) = read_sin(p, to, tolen) else { return fail(p, WSAEAFNOSUPPORT) };
        sock::sendto(p, i, &buf, Some(d))
    } else {
        sock::send(p, i, &buf, false)
    };
    match r {
        Ok(n) => n as u64,
        Err(e) => fail_e(p, e),
    }
}

/// recvfrom(s, buf, len, flags, from*, fromlen*)
pub fn recvfrom(p: &Arc<Process>, a: A) -> u64 {
    let i = match sock_slot(p, a[0]) { Ok(i) => i, Err(e) => return e };
    match sock::recvfrom(p, i, a[2] as u32 as usize, false) {
        Ok((v, from)) => {
            if copy_to_user(p, a[1], &v).is_err() {
                return fail(p, WSAEFAULT);
            }
            if let Some((ip, port)) = from {
                write_sin(p, stack_arg(p, 4), stack_arg(p, 5), ip, port);
            }
            v.len() as u64
        }
        Err(e) => fail_e(p, e),
    }
}

pub fn closesocket(p: &Arc<Process>, a: A) -> u64 {
    match slot(a[0]).map(|i| vfs::close(p, i)) {
        Some(Ok(())) => 0,
        _ => fail(p, WSAENOTSOCK),
    }
}

pub fn shutdown(p: &Arc<Process>, a: A) -> u64 {
    // Winsock SD_RECEIVE 0, SD_SEND 1, SD_BOTH 2 == POSIX SHUT_RD/WR/RDWR
    let i = match sock_slot(p, a[0]) { Ok(i) => i, Err(e) => return e };
    match sock::shutdown(p, i, a[1] as u32) {
        Ok(()) => 0,
        Err(e) => fail_e(p, e),
    }
}

/// ioctlsocket(s, cmd, u_long* argp): FIONBIO, FIONREAD
pub fn ioctlsocket(p: &Arc<Process>, a: A) -> u64 {
    let i = match sock_slot(p, a[0]) { Ok(i) => i, Err(e) => return e };
    match a[1] as u32 {
        0x8004_667E => {
            let mut b = [0u8; 4];
            let _ = copy_from_user(p, &mut b, a[2]);
            match sock::set_nonblock(p, i, u32::from_ne_bytes(b) != 0) {
                Ok(()) => 0,
                Err(e) => fail_e(p, e),
            }
        }
        0x4004_667F => {
            let n = sock::pending_bytes(p, i) as u32;
            let _ = copy_to_user(p, a[2], &n.to_le_bytes());
            0
        }
        _ => fail(p, WSAEINVAL),
    }
}

/// setsockopt(s, level, optname, optval*, optlen): SO_REUSEADDR, SO_RCVTIMEO (DWORD ms); the rest is accepted.
pub fn setsockopt(p: &Arc<Process>, a: A) -> u64 {
    let i = match sock_slot(p, a[0]) { Ok(i) => i, Err(e) => return e };
    let (level, name, val, len) = (a[1] as u32, a[2] as u32, a[3], stack_arg(p, 4));
    if level == 0xFFFF {
        let mut b = [0u8; 4];
        let ok = len >= 4 && copy_from_user(p, &mut b, val).is_ok();
        match name {
            4 if ok => { let _ = sock::set_reuse(p, i, u32::from_le_bytes(b) != 0); }
            0x1006 if ok => { let _ = sock::set_rcvtimeo(p, i, u32::from_le_bytes(b) as u64); }
            _ => {}
        }
    }
    0
}

/// getsockopt(s, level, optname, optval*, optlen*): SO_ERROR, SO_TYPE, SO_REUSEADDR, buffer sizes.
pub fn getsockopt(p: &Arc<Process>, a: A) -> u64 {
    let i = match sock_slot(p, a[0]) { Ok(i) => i, Err(e) => return e };
    let (level, name, val, lenp) = (a[1] as u32, a[2] as u32, a[3], stack_arg(p, 4));
    let v: u32 = if level == 0xFFFF {
        match name {
            0x1007 => { let e = sock::take_error(p, i); if e == 0 { 0 } else { wsa_err(e) } }
            0x1008 => if sock::ty(p, i) == Ok(Ty::Stream) { 1 } else { 2 },
            4 => sock::reuse(p, i) as u32,
            0x1001 | 0x1002 => 65536,
            _ => 0,
        }
    } else {
        0
    };
    if val != 0 {
        let _ = copy_to_user(p, val, &v.to_le_bytes());
    }
    if lenp != 0 {
        let _ = copy_to_user(p, lenp, &4u32.to_le_bytes());
    }
    0
}

pub fn getsockname(p: &Arc<Process>, a: A) -> u64 {
    let i = match sock_slot(p, a[0]) { Ok(i) => i, Err(e) => return e };
    match sock::local_addr(p, i) {
        Ok((ip, port)) => { write_sin(p, a[1], a[2], ip, port); 0 }
        Err(e) => fail_e(p, e),
    }
}

pub fn getpeername(p: &Arc<Process>, a: A) -> u64 {
    let i = match sock_slot(p, a[0]) { Ok(i) => i, Err(e) => return e };
    match sock::peer(p, i) {
        Some((ip, port)) => { write_sin(p, a[1], a[2], ip, port); 0 }
        None => fail(p, WSAENOTCONN),
    }
}

// ---- select / WSAPoll ----

fn read_fdset(p: &Arc<Process>, ptr: u64) -> Vec<u64> {
    let mut v = Vec::new();
    if ptr == 0 {
        return v;
    }
    let mut c = [0u8; 4];
    if copy_from_user(p, &mut c, ptr).is_err() {
        return v;
    }
    for k in 0..(u32::from_le_bytes(c) as usize).min(64) {
        let mut b = [0u8; 8];
        if copy_from_user(p, &mut b, ptr + 8 + 8 * k as u64).is_ok() {
            v.push(u64::from_le_bytes(b));
        }
    }
    v
}
fn write_fdset(p: &Arc<Process>, ptr: u64, v: &[u64]) {
    if ptr == 0 {
        return;
    }
    let _ = copy_to_user(p, ptr, &(v.len() as u32).to_le_bytes());
    for (k, s) in v.iter().enumerate() {
        let _ = copy_to_user(p, ptr + 8 + 8 * k as u64, &s.to_le_bytes());
    }
}

/// select(nfds, readfds, writefds, exceptfds, timeval*)
pub fn select(p: &Arc<Process>, a: A) -> u64 {
    let (rp, wp, ep, tv) = (a[1], a[2], stack_arg(p, 3), stack_arg(p, 4));
    let (rs, ws) = (read_fdset(p, rp), read_fdset(p, wp));
    let timeout: i64 = if tv == 0 {
        -1
    } else {
        let mut b = [0u8; 8];
        if copy_from_user(p, &mut b, tv).is_err() {
            return fail(p, WSAEFAULT);
        }
        i32::from_le_bytes(b[0..4].try_into().unwrap()) as i64 * 1000 + i32::from_le_bytes(b[4..8].try_into().unwrap()) as i64 / 1000
    };
    let t0 = crate::time::uptime_ms();
    loop {
        let mut ro = Vec::new();
        let mut wo = Vec::new();
        for s in &rs {
            if let Some(i) = slot(*s) {
                let (r, _) = sock::readiness(p, i);
                if r || sock::hangup(p, i) {
                    ro.push(*s);
                }
            }
        }
        for s in &ws {
            if let Some(i) = slot(*s) {
                let (_, w) = sock::readiness(p, i);
                if w {
                    wo.push(*s);
                }
            }
        }
        let n = ro.len() + wo.len();
        if n > 0 || timeout == 0 || (timeout > 0 && crate::time::uptime_ms().saturating_sub(t0) >= timeout as u64) {
            write_fdset(p, rp, &ro);
            write_fdset(p, wp, &wo);
            write_fdset(p, ep, &[]);
            return n as u64;
        }
        crate::task::sleep_ms(1);
    }
}

pub fn wsa_fd_isset(p: &Arc<Process>, a: A) -> u64 {
    read_fdset(p, a[1]).contains(&a[0]) as u64
}

/// WSAPoll(WSAPOLLFD*, ULONG n, INT timeout_ms)
pub fn wsa_poll(p: &Arc<Process>, a: A) -> u64 {
    let n = (a[1] as usize).min(64);
    let timeout = a[2] as i32 as i64;
    let t0 = crate::time::uptime_ms();
    loop {
        let mut ready = 0u64;
        for k in 0..n {
            let at = a[0] + 16 * k as u64;
            let mut b = [0u8; 16];
            if copy_from_user(p, &mut b, at).is_err() {
                return fail(p, WSAEFAULT);
            }
            let fd = u64::from_le_bytes(b[..8].try_into().unwrap());
            let ev = i16::from_le_bytes(b[8..10].try_into().unwrap());
            let mut rev: i16 = 0;
            match slot(fd).filter(|i| sock::is_sock(p, *i)) {
                None => rev = 4, // POLLNVAL
                Some(i) => {
                    let (r, w) = sock::readiness(p, i);
                    if r && ev & 0x300 != 0 { rev |= ev & 0x300; }
                    if w && ev & 0x10 != 0 { rev |= 0x10; }
                    if sock::hangup(p, i) { rev |= 2; }
                }
            }
            b[10..12].copy_from_slice(&rev.to_le_bytes());
            let _ = copy_to_user(p, at, &b);
            if rev != 0 { ready += 1; }
        }
        if ready > 0 || timeout == 0 || (timeout > 0 && crate::time::uptime_ms().saturating_sub(t0) >= timeout as u64) {
            return ready;
        }
        crate::task::sleep_ms(1);
    }
}

// ---- byte order, address text ----

pub fn htons(_: &Arc<Process>, a: A) -> u64 {
    (a[0] as u16).swap_bytes() as u64
}
pub fn htonl(_: &Arc<Process>, a: A) -> u64 {
    (a[0] as u32).swap_bytes() as u64
}

/// inet_addr("a.b.c.d") -> address in network byte order (INADDR_NONE on error)
pub fn inet_addr(p: &Arc<Process>, a: A) -> u64 {
    let s = read_cstr(p, a[0], 32);
    let t = core::str::from_utf8(&s).unwrap_or("");
    match crate::perm::parse_dest(&alloc::format!("{}:1", t)) {
        Some((ip, _)) => u32::from_le_bytes(ip) as u64,
        None => 0xFFFF_FFFF,
    }
}

fn user_alloc(p: &Arc<Process>, n: u64) -> u64 {
    heap_alloc(p, [0, 0, n, 0])
}

/// inet_ntoa(in_addr) -> char* (static buffer per call site is not needed: one per call, never freed)
pub fn inet_ntoa(p: &Arc<Process>, a: A) -> u64 {
    let ip = (a[0] as u32).to_le_bytes();
    let s = alloc::format!("{}.{}.{}.{}\0", ip[0], ip[1], ip[2], ip[3]);
    let va = user_alloc(p, 32);
    if va == 0 || copy_to_user(p, va, s.as_bytes()).is_err() {
        return 0;
    }
    va
}

pub fn gethostname(p: &Arc<Process>, a: A) -> u64 {
    let name = b"deloxy\0";
    if (a[1] as usize) < name.len() || copy_to_user(p, a[0], name).is_err() {
        return fail(p, WSAEFAULT);
    }
    0
}

// ---- name resolution (needs the `dns` permission; numeric addresses never do) ----

fn lookup(p: &Arc<Process>, name: &str) -> Result<[u8; 4], u32> {
    match sock::resolve_host(p, name) {
        Ok(ip) => Ok(ip),
        Err(sock::EACCES) => Err(WSAEACCES),
        Err(2) => Err(WSAHOST_NOT_FOUND),
        Err(_) => Err(WSAETIMEDOUT),
    }
}

/// gethostbyname(name) -> hostent*
pub fn gethostbyname(p: &Arc<Process>, a: A) -> u64 {
    let nm = read_cstr(p, a[0], 255);
    let name = core::str::from_utf8(&nm).unwrap_or("");
    let ip = match lookup(p, name) {
        Ok(ip) => ip,
        Err(e) => {
            set_err(p, e);
            return 0;
        }
    };
    let base = user_alloc(p, 128);
    if base == 0 {
        return 0;
    }
    // layout: hostent @0 (32) | aliases[1] @32 | addr_list[2] @40 | addr @56 | name @64
    let mut blk = [0u8; 128];
    blk[0..8].copy_from_slice(&(base + 64).to_le_bytes());
    blk[8..16].copy_from_slice(&(base + 32).to_le_bytes());
    blk[16..18].copy_from_slice(&2u16.to_le_bytes());
    blk[18..20].copy_from_slice(&4u16.to_le_bytes());
    blk[24..32].copy_from_slice(&(base + 40).to_le_bytes());
    blk[40..48].copy_from_slice(&(base + 56).to_le_bytes());
    blk[56..60].copy_from_slice(&ip);
    let n = nm.len().min(60);
    blk[64..64 + n].copy_from_slice(&nm[..n]);
    if copy_to_user(p, base, &blk).is_err() {
        return 0;
    }
    base
}

/// getaddrinfo(node, service, hints*, ADDRINFOA** res): IPv4 only; one result per requested socket type.
pub fn getaddrinfo(p: &Arc<Process>, a: A) -> u64 {
    let node = read_cstr(p, a[0], 255);
    let service = read_cstr(p, a[1], 32);
    let res_pp = a[3];
    let port: u16 = core::str::from_utf8(&service).ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let (mut flags, mut family, mut socktype, mut proto) = (0i32, 0i32, 0i32, 0i32);
    if a[2] != 0 {
        let mut h = [0u8; 16];
        if copy_from_user(p, &mut h, a[2]).is_ok() {
            flags = i32::from_le_bytes(h[0..4].try_into().unwrap());
            family = i32::from_le_bytes(h[4..8].try_into().unwrap());
            socktype = i32::from_le_bytes(h[8..12].try_into().unwrap());
            proto = i32::from_le_bytes(h[12..16].try_into().unwrap());
        }
    }
    if family != 0 && family != 2 {
        return WSAEAFNOSUPPORT as u64;
    }
    let ip = if node.is_empty() {
        if flags & 1 != 0 { [0; 4] } else { [127, 0, 0, 1] } // AI_PASSIVE
    } else {
        match lookup(p, core::str::from_utf8(&node).unwrap_or("")) {
            Ok(ip) => ip,
            Err(e) => return e as u64,
        }
    };
    let kinds: &[(i32, i32)] = match socktype {
        1 => &[(1, 6)],
        2 => &[(2, 17)],
        _ => &[(1, 6), (2, 17)],
    };
    let mut first = 0u64;
    let mut prev = 0u64;
    for (st, pr) in kinds {
        let b = user_alloc(p, 96);
        if b == 0 {
            return 10055; // WSAENOBUFS
        }
        let mut rec = [0u8; 96];
        rec[4..8].copy_from_slice(&2i32.to_le_bytes());
        rec[8..12].copy_from_slice(&st.to_le_bytes());
        rec[12..16].copy_from_slice(&(if proto != 0 { proto } else { *pr }).to_le_bytes());
        rec[16..24].copy_from_slice(&16u64.to_le_bytes());
        rec[32..40].copy_from_slice(&(b + 48).to_le_bytes());
        rec[48..64].copy_from_slice(&sin_bytes(ip, port));
        if copy_to_user(p, b, &rec).is_err() {
            return 10014;
        }
        if first == 0 {
            first = b;
        } else {
            let _ = copy_to_user(p, prev + 40, &b.to_le_bytes());
        }
        prev = b;
    }
    let _ = copy_to_user(p, res_pp, &first.to_le_bytes());
    0
}

pub fn freeaddrinfo(_: &Arc<Process>, _: A) -> u64 {
    0
}
