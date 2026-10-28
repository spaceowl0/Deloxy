//! Linux network syscalls (x86_64 numbers) on top of `abi::sock`: socket/connect/bind/listen/accept(4)/send*/recv*/
//! sendmsg/recvmsg/sendmmsg/shutdown/getsockname/getpeername/get+setsockopt, select/pselect6 and epoll.
//! All policy lives in `sock` / `perm`; this file only translates the Linux ABI.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::sock::{self, Ty};
use super::vfs::{self, Data, OpenFile};
use crate::sys::uaccess::{copy_from_user, copy_to_user};
use crate::task::{self, Process};
use crate::time;

const EBADF: i64 = 9;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const EAFNOSUPPORT: i64 = 97;
const EPROTONOSUPPORT: i64 = 93;
const ENOPROTOOPT: i64 = 92;
const EEXIST: i64 = 17;
const ENOENT: i64 = 2;

const MSG_DONTWAIT: u64 = 0x40;
const SOCK_NONBLOCK: u64 = 0x800;

pub fn fd_slot(fd: u64) -> Option<usize> {
    if fd >= 3 {
        Some(fd as usize - 3)
    } else {
        None
    }
}

fn slot_of(p: &Arc<Process>, fd: u64) -> Result<usize, i64> {
    let i = fd_slot(fd).ok_or(sock::ENOTSOCK)?;
    if sock::is_sock(p, i) {
        Ok(i)
    } else if p.foreign.lock().fds.get(i).map_or(true, |s| s.is_none()) {
        Err(EBADF)
    } else {
        Err(sock::ENOTSOCK)
    }
}

fn read_sockaddr(p: &Arc<Process>, addr: u64, len: u64) -> Result<([u8; 4], u16), i64> {
    if len < 8 {
        return Err(EINVAL);
    }
    let mut b = [0u8; 8];
    copy_from_user(p, &mut b, addr).map_err(|_| EFAULT)?;
    if u16::from_le_bytes([b[0], b[1]]) != 2 {
        return Err(EAFNOSUPPORT);
    }
    Ok(([b[4], b[5], b[6], b[7]], u16::from_be_bytes([b[2], b[3]])))
}

/// Write a `sockaddr_in` honouring the caller's buffer length (`lenp` is in/out).
fn write_sockaddr(p: &Arc<Process>, addr: u64, lenp: u64, ip: [u8; 4], port: u16) -> Result<(), i64> {
    if addr == 0 || lenp == 0 {
        return Ok(());
    }
    let mut lb = [0u8; 4];
    copy_from_user(p, &mut lb, lenp).map_err(|_| EFAULT)?;
    let cap = u32::from_le_bytes(lb) as usize;
    let mut b = [0u8; 16];
    b[0..2].copy_from_slice(&2u16.to_le_bytes());
    b[2..4].copy_from_slice(&port.to_be_bytes());
    b[4..8].copy_from_slice(&ip);
    copy_to_user(p, addr, &b[..cap.min(16)]).map_err(|_| EFAULT)?;
    copy_to_user(p, lenp, &16u32.to_le_bytes()).map_err(|_| EFAULT)?;
    Ok(())
}

pub fn socket(p: &Arc<Process>, domain: u64, ty: u64, proto: u64) -> i64 {
    if domain != 2 {
        return -EAFNOSUPPORT;
    }
    let t = match ty & 0xF {
        1 if proto == 0 || proto == 6 => Ty::Stream,
        2 if proto == 0 || proto == 17 => Ty::Dgram,
        1 | 2 => return -EPROTONOSUPPORT,
        _ => return -EPROTONOSUPPORT, // SOCK_RAW etc.: no raw sockets, ever
    };
    match sock::create(p, t, ty & SOCK_NONBLOCK != 0) {
        Ok(i) => i as i64 + 3,
        Err(e) => -e,
    }
}

pub fn connect(p: &Arc<Process>, fd: u64, addr: u64, len: u64) -> i64 {
    let i = match slot_of(p, fd) {
        Ok(i) => i,
        Err(e) => return -e,
    };
    let (ip, port) = match read_sockaddr(p, addr, len) {
        Ok(x) => x,
        Err(e) => return -e,
    };
    match sock::connect(p, i, ip, port) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

pub fn bind(p: &Arc<Process>, fd: u64, addr: u64, len: u64) -> i64 {
    let i = match slot_of(p, fd) {
        Ok(i) => i,
        Err(e) => return -e,
    };
    let (_ip, port) = match read_sockaddr(p, addr, len) {
        Ok(x) => x,
        Err(e) => return -e,
    };
    match sock::bind(p, i, port) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

pub fn listen(p: &Arc<Process>, fd: u64, backlog: u64) -> i64 {
    let i = match slot_of(p, fd) {
        Ok(i) => i,
        Err(e) => return -e,
    };
    match sock::listen(p, i, backlog as usize) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

pub fn accept(p: &Arc<Process>, fd: u64, addr: u64, lenp: u64, flags: u64) -> i64 {
    let i = match slot_of(p, fd) {
        Ok(i) => i,
        Err(e) => return -e,
    };
    match sock::accept(p, i, flags & SOCK_NONBLOCK != 0) {
        Ok((ns, (ip, port))) => {
            let _ = write_sockaddr(p, addr, lenp, ip, port);
            ns as i64 + 3
        }
        Err(e) => -e,
    }
}

pub fn shutdown(p: &Arc<Process>, fd: u64, how: u64) -> i64 {
    match slot_of(p, fd).and_then(|i| sock::shutdown(p, i, how as u32)) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

pub fn getsockname(p: &Arc<Process>, fd: u64, addr: u64, lenp: u64) -> i64 {
    let r = slot_of(p, fd).and_then(|i| sock::local_addr(p, i)).and_then(|(ip, port)| write_sockaddr(p, addr, lenp, ip, port));
    match r {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

pub fn getpeername(p: &Arc<Process>, fd: u64, addr: u64, lenp: u64) -> i64 {
    let i = match slot_of(p, fd) {
        Ok(i) => i,
        Err(e) => return -e,
    };
    let Some((ip, port)) = sock::peer(p, i) else { return -sock::ENOTCONN };
    match write_sockaddr(p, addr, lenp, ip, port) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

pub fn sendto(p: &Arc<Process>, fd: u64, buf: u64, len: u64, flags: u64, addr: u64, alen: u64) -> i64 {
    let i = match slot_of(p, fd) {
        Ok(i) => i,
        Err(e) => return -e,
    };
    let mut tmp = alloc::vec![0u8; (len as usize).min(1 << 20)];
    if copy_from_user(p, &mut tmp, buf).is_err() {
        return -EFAULT;
    }
    let dest = if addr != 0 {
        match read_sockaddr(p, addr, alen) {
            Ok(d) => Some(d),
            Err(e) => return -e,
        }
    } else {
        None
    };
    let r = match (dest, sock::ty(p, i)) {
        (Some(d), Ok(Ty::Dgram)) => sock::sendto(p, i, &tmp, Some(d)),
        _ => sock::send(p, i, &tmp, flags & MSG_DONTWAIT != 0),
    };
    match r {
        Ok(n) => n as i64,
        Err(e) => -e,
    }
}

pub fn recvfrom(p: &Arc<Process>, fd: u64, buf: u64, len: u64, flags: u64, addr: u64, lenp: u64) -> i64 {
    let i = match slot_of(p, fd) {
        Ok(i) => i,
        Err(e) => return -e,
    };
    match sock::recvfrom(p, i, len as usize, flags & MSG_DONTWAIT != 0) {
        Ok((v, from)) => {
            if copy_to_user(p, buf, &v).is_err() {
                return -EFAULT;
            }
            if let Some((ip, port)) = from {
                let _ = write_sockaddr(p, addr, lenp, ip, port);
            }
            v.len() as i64
        }
        Err(e) => -e,
    }
}

// ---- sendmsg / recvmsg / sendmmsg ----

struct MsgHdr {
    name: u64,
    namelen: u32,
    iov: u64,
    iovlen: usize,
}

fn read_msghdr(p: &Arc<Process>, m: u64) -> Result<MsgHdr, i64> {
    let mut b = [0u8; 56];
    copy_from_user(p, &mut b, m).map_err(|_| EFAULT)?;
    Ok(MsgHdr {
        name: u64::from_le_bytes(b[0..8].try_into().unwrap()),
        namelen: u32::from_le_bytes(b[8..12].try_into().unwrap()),
        iov: u64::from_le_bytes(b[16..24].try_into().unwrap()),
        iovlen: (u64::from_le_bytes(b[24..32].try_into().unwrap()) as usize).min(64),
    })
}

fn gather(p: &Arc<Process>, h: &MsgHdr) -> Result<Vec<u8>, i64> {
    let mut out = Vec::new();
    for k in 0..h.iovlen {
        let mut e = [0u8; 16];
        copy_from_user(p, &mut e, h.iov + k as u64 * 16).map_err(|_| EFAULT)?;
        let base = u64::from_le_bytes(e[..8].try_into().unwrap());
        let n = (u64::from_le_bytes(e[8..].try_into().unwrap()) as usize).min(1 << 20);
        if out.len() + n > 1 << 20 {
            break;
        }
        let at = out.len();
        out.resize(at + n, 0);
        copy_from_user(p, &mut out[at..], base).map_err(|_| EFAULT)?;
    }
    Ok(out)
}

fn do_sendmsg(p: &Arc<Process>, fd: u64, m: u64, flags: u64) -> i64 {
    let i = match slot_of(p, fd) {
        Ok(i) => i,
        Err(e) => return -e,
    };
    let h = match read_msghdr(p, m) {
        Ok(h) => h,
        Err(e) => return -e,
    };
    let data = match gather(p, &h) {
        Ok(d) => d,
        Err(e) => return -e,
    };
    let dest = if h.name != 0 && h.namelen >= 8 {
        match read_sockaddr(p, h.name, h.namelen as u64) {
            Ok(d) => Some(d),
            Err(e) => return -e,
        }
    } else {
        None
    };
    let r = match (dest, sock::ty(p, i)) {
        (d, Ok(Ty::Dgram)) => sock::sendto(p, i, &data, d),
        _ => sock::send(p, i, &data, flags & MSG_DONTWAIT != 0),
    };
    match r {
        Ok(n) => n as i64,
        Err(e) => -e,
    }
}

pub fn sendmsg(p: &Arc<Process>, fd: u64, m: u64, flags: u64) -> i64 {
    do_sendmsg(p, fd, m, flags)
}

pub fn sendmmsg(p: &Arc<Process>, fd: u64, vec: u64, vlen: u64, flags: u64) -> i64 {
    let mut done = 0i64;
    for k in 0..(vlen as usize).min(16) {
        let at = vec + k as u64 * 64;
        let r = do_sendmsg(p, fd, at, flags);
        if r < 0 {
            return if done > 0 { done } else { r };
        }
        if copy_to_user(p, at + 56, &(r as u32).to_le_bytes()).is_err() {
            return -EFAULT;
        }
        done += 1;
    }
    done
}

pub fn recvmsg(p: &Arc<Process>, fd: u64, m: u64, flags: u64) -> i64 {
    let i = match slot_of(p, fd) {
        Ok(i) => i,
        Err(e) => return -e,
    };
    let h = match read_msghdr(p, m) {
        Ok(h) => h,
        Err(e) => return -e,
    };
    let mut total = 0usize;
    let mut segs: Vec<(u64, usize)> = Vec::new();
    for k in 0..h.iovlen {
        let mut e = [0u8; 16];
        if copy_from_user(p, &mut e, h.iov + k as u64 * 16).is_err() {
            return -EFAULT;
        }
        let n = (u64::from_le_bytes(e[8..].try_into().unwrap()) as usize).min(1 << 20);
        segs.push((u64::from_le_bytes(e[..8].try_into().unwrap()), n));
        total += n;
    }
    match sock::recvfrom(p, i, total, flags & MSG_DONTWAIT != 0) {
        Ok((v, from)) => {
            let mut off = 0;
            for (base, n) in segs {
                if off >= v.len() {
                    break;
                }
                let take = n.min(v.len() - off);
                if copy_to_user(p, base, &v[off..off + take]).is_err() {
                    return -EFAULT;
                }
                off += take;
            }
            if let Some((ip, port)) = from {
                if h.name != 0 {
                    let mut lb = [0u8; 4];
                    lb.copy_from_slice(&h.namelen.to_le_bytes());
                    let mut sa = [0u8; 16];
                    sa[0..2].copy_from_slice(&2u16.to_le_bytes());
                    sa[2..4].copy_from_slice(&port.to_be_bytes());
                    sa[4..8].copy_from_slice(&ip);
                    let _ = copy_to_user(p, h.name, &sa[..(h.namelen as usize).min(16)]);
                    let _ = copy_to_user(p, m + 8, &16u32.to_le_bytes());
                }
            }
            let _ = copy_to_user(p, m + 40, &0u64.to_le_bytes()); // msg_controllen
            let _ = copy_to_user(p, m + 48, &0u32.to_le_bytes()); // msg_flags
            v.len() as i64
        }
        Err(e) => -e,
    }
}

// ---- socket options ----

const SOL_SOCKET: u64 = 1;
const IPPROTO_TCP: u64 = 6;

pub fn setsockopt(p: &Arc<Process>, fd: u64, level: u64, name: u64, val: u64, len: u64) -> i64 {
    let i = match slot_of(p, fd) {
        Ok(i) => i,
        Err(e) => return -e,
    };
    if level == SOL_SOCKET {
        match name {
            2 => {
                let mut b = [0u8; 4];
                if len >= 4 && copy_from_user(p, &mut b, val).is_ok() {
                    let _ = sock::set_reuse(p, i, u32::from_le_bytes(b) != 0);
                }
            }
            20 => {
                // SO_RCVTIMEO: struct timeval
                let mut b = [0u8; 16];
                if len >= 16 && copy_from_user(p, &mut b, val).is_ok() {
                    let ms = u64::from_le_bytes(b[..8].try_into().unwrap()).saturating_mul(1000) + u64::from_le_bytes(b[8..].try_into().unwrap()) / 1000;
                    let _ = sock::set_rcvtimeo(p, i, ms);
                }
            }
            _ => {} // buffer sizes, keepalive, linger, send timeout...: accepted and ignored
        }
    }
    0
}

pub fn getsockopt(p: &Arc<Process>, fd: u64, level: u64, name: u64, val: u64, lenp: u64) -> i64 {
    let i = match slot_of(p, fd) {
        Ok(i) => i,
        Err(e) => return -e,
    };
    let v: u32 = if level == SOL_SOCKET {
        match name {
            4 => sock::take_error(p, i) as u32,                                // SO_ERROR
            3 => match sock::ty(p, i) { Ok(Ty::Stream) => 1, _ => 2 },        // SO_TYPE
            2 => sock::reuse(p, i) as u32,                                      // SO_REUSEADDR
            7 | 8 => 65536,                                                     // SO_SNDBUF / SO_RCVBUF
            30 => 0,                                                            // SO_ACCEPTCONN
            9 => 0,
            _ => 0,
        }
    } else if level == IPPROTO_TCP || level == 0 {
        0
    } else {
        return -ENOPROTOOPT;
    };
    if val != 0 && copy_to_user(p, val, &v.to_le_bytes()).is_err() {
        return -EFAULT;
    }
    if lenp != 0 {
        let _ = copy_to_user(p, lenp, &4u32.to_le_bytes());
    }
    0
}

/// ioctl(FIONREAD) on a socket (glibc's resolver uses it to size the answer buffer).
pub fn fionread(p: &Arc<Process>, fd: u64, arg: u64) -> Option<i64> {
    let i = slot_of(p, fd).ok()?;
    let n = sock::pending_bytes(p, i);
    Some(match copy_to_user(p, arg, &(n as u32).to_le_bytes()) {
        Ok(()) => 0,
        Err(_) => -EFAULT,
    })
}

// ---- select / pselect6 ----

fn read_set(p: &Arc<Process>, ptr: u64, nfds: usize) -> Result<Vec<u64>, i64> {
    let words = (nfds + 63) / 64;
    let mut v = alloc::vec![0u64; words];
    if ptr != 0 {
        for (k, w) in v.iter_mut().enumerate() {
            let mut b = [0u8; 8];
            copy_from_user(p, &mut b, ptr + k as u64 * 8).map_err(|_| EFAULT)?;
            *w = u64::from_le_bytes(b);
        }
    }
    Ok(v)
}

fn write_set(p: &Arc<Process>, ptr: u64, v: &[u64]) {
    if ptr == 0 {
        return;
    }
    for (k, w) in v.iter().enumerate() {
        let _ = copy_to_user(p, ptr + k as u64 * 8, &w.to_le_bytes());
    }
}

/// `timeout_ms`: -1 = block forever.
fn do_select(p: &Arc<Process>, nfds: u64, rp: u64, wp: u64, ep: u64, timeout_ms: i64) -> i64 {
    let nfds = (nfds as usize).min(1024);
    let (rin, win, ein) = match (read_set(p, rp, nfds), read_set(p, wp, nfds), read_set(p, ep, nfds)) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        _ => return -EFAULT,
    };
    let t0 = time::uptime_ms();
    loop {
        let mut rout = alloc::vec![0u64; rin.len()];
        let mut wout = alloc::vec![0u64; win.len()];
        let eout = alloc::vec![0u64; ein.len()];
        let mut n = 0;
        for fd in 0..nfds {
            let (w, b) = (fd / 64, 1u64 << (fd % 64));
            let (wr, ww) = (rin[w] & b != 0, win[w] & b != 0);
            if !wr && !ww {
                continue;
            }
            let ev = (if wr { 1 } else { 0 }) | (if ww { 4 } else { 0 });
            let rev = super::linux::poll_ready(p, fd as i32, ev);
            if rev & 0x20 != 0 {
                return -EBADF;
            }
            if wr && rev & (1 | 0x10 | 8) != 0 {
                rout[w] |= b;
                n += 1;
            }
            if ww && rev & (4 | 8) != 0 {
                wout[w] |= b;
                n += 1;
            }
        }
        if n > 0 || timeout_ms == 0 || (timeout_ms > 0 && time::uptime_ms().saturating_sub(t0) >= timeout_ms as u64) {
            write_set(p, rp, &rout);
            write_set(p, wp, &wout);
            write_set(p, ep, &eout);
            return n;
        }
        if super::signals::interrupted(p) {
            return -super::signals::EINTR;
        }
        task::sleep_ms(1);
    }
}

pub fn select(p: &Arc<Process>, nfds: u64, rp: u64, wp: u64, ep: u64, tv: u64) -> i64 {
    let t = if tv == 0 {
        -1
    } else {
        let mut b = [0u8; 16];
        if copy_from_user(p, &mut b, tv).is_err() {
            return -EFAULT;
        }
        (u64::from_le_bytes(b[..8].try_into().unwrap()).saturating_mul(1000) + u64::from_le_bytes(b[8..].try_into().unwrap()) / 1000).min(i64::MAX as u64 / 2) as i64
    };
    do_select(p, nfds, rp, wp, ep, t)
}

pub fn pselect6(p: &Arc<Process>, nfds: u64, rp: u64, wp: u64, ep: u64, ts: u64) -> i64 {
    let t = if ts == 0 {
        -1
    } else {
        let mut b = [0u8; 16];
        if copy_from_user(p, &mut b, ts).is_err() {
            return -EFAULT;
        }
        (u64::from_le_bytes(b[..8].try_into().unwrap()).saturating_mul(1000) + u64::from_le_bytes(b[8..].try_into().unwrap()) / 1_000_000).min(i64::MAX as u64 / 2) as i64
    };
    do_select(p, nfds, rp, wp, ep, t)
}

// ---- epoll (level-triggered; EPOLLET is accepted and treated as level) ----

pub struct EpollState {
    /// (fd, events, user data, one-shot disabled)
    pub interest: Vec<(i32, u32, u64, bool)>,
}

pub fn epoll_create(p: &Arc<Process>, _flags: u64) -> i64 {
    let f = OpenFile { name: alloc::string::String::from("epoll"), data: Data::Epoll(EpollState { interest: Vec::new() }), pos: 0, writable: false, dirty: false, eof: false };
    match vfs::alloc(p, f) {
        Ok(i) => i as i64 + 3,
        Err(e) => -e,
    }
}

pub fn epoll_ctl(p: &Arc<Process>, epfd: u64, op: u64, fd: u64, ev: u64) -> i64 {
    let Some(ei) = fd_slot(epfd) else { return -EBADF };
    let (events, data) = if op != 2 {
        let mut b = [0u8; 12];
        if copy_from_user(p, &mut b, ev).is_err() {
            return -EFAULT;
        }
        (u32::from_le_bytes(b[0..4].try_into().unwrap()), u64::from_le_bytes(b[4..12].try_into().unwrap()))
    } else {
        (0, 0)
    };
    if fd_slot(fd).is_none() && fd > 2 {
        return -EBADF;
    }
    let mut g = p.foreign.lock();
    if fd_slot(fd).map_or(false, |s| g.fds.get(s).map_or(true, |x| x.is_none())) {
        return -EBADF;
    }
    let Some(Some(OpenFile { data: Data::Epoll(st), .. })) = g.fds.get_mut(ei) else { return -EINVAL };
    let pos = st.interest.iter().position(|x| x.0 == fd as i32);
    match (op, pos) {
        (1, Some(_)) => -EEXIST,
        (1, None) => {
            st.interest.push((fd as i32, events, data, false));
            0
        }
        (2, Some(k)) => {
            st.interest.remove(k);
            0
        }
        (3, Some(k)) => {
            st.interest[k] = (fd as i32, events, data, false);
            0
        }
        _ => -ENOENT,
    }
}

pub fn epoll_wait(p: &Arc<Process>, epfd: u64, out: u64, max: u64, timeout: i64) -> i64 {
    let Some(ei) = fd_slot(epfd) else { return -EBADF };
    let max = (max as usize).clamp(1, 128);
    let t0 = time::uptime_ms();
    loop {
        let interest: Vec<(i32, u32, u64, bool)> = {
            let g = p.foreign.lock();
            match g.fds.get(ei).and_then(|s| s.as_ref()) {
                Some(OpenFile { data: Data::Epoll(st), .. }) => st.interest.clone(),
                _ => return -EINVAL,
            }
        };
        let mut n = 0usize;
        let mut fired: Vec<i32> = Vec::new();
        for (fd, events, data, disabled) in interest.iter() {
            if *disabled || n >= max {
                continue;
            }
            // poll bits and epoll bits agree for IN (1), OUT (4), ERR (8), HUP (0x10)
            let want = (*events & 0x5) as i16 | 0; // EPOLLIN | EPOLLOUT
            let rev = super::linux::poll_ready(p, *fd, want) as u32;
            let rev = rev & (*events | 0x18); // ERR and HUP are always reported
            if rev & 0x20 != 0 || rev == 0 {
                continue;
            }
            let mut rec = [0u8; 12];
            rec[0..4].copy_from_slice(&rev.to_le_bytes());
            rec[4..12].copy_from_slice(&data.to_le_bytes());
            if copy_to_user(p, out + n as u64 * 12, &rec).is_err() {
                return -EFAULT;
            }
            if *events & (1 << 30) != 0 {
                fired.push(*fd); // EPOLLONESHOT
            }
            n += 1;
        }
        if !fired.is_empty() {
            let mut g = p.foreign.lock();
            if let Some(Some(OpenFile { data: Data::Epoll(st), .. })) = g.fds.get_mut(ei) {
                for e in st.interest.iter_mut() {
                    if fired.contains(&e.0) {
                        e.3 = true;
                    }
                }
            }
        }
        if n > 0 || timeout == 0 || (timeout > 0 && time::uptime_ms().saturating_sub(t0) >= timeout as u64) {
            return n as i64;
        }
        if super::signals::interrupted(p) {
            return -super::signals::EINTR;
        }
        task::sleep_ms(1);
    }
}
