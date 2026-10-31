//! Sockets for foreign programs (shared by the Linux and Windows layers): TCP client + server, UDP, name resolution.
//!
//! A socket is an `OpenFile` (`vfs::Data::Sock`). Creating one needs no permission; **using the network does**, and every
//! use is a consent decision the user makes (see `perm`):
//!
//! * `connect` / `sendto` to `ip:port` -> per-destination rule (or full access); the kernel then mints a `NetGrant` that
//!   covers exactly that scope (TCP + UDP share one time/data budget per rule scope and run) and brings the NIC up.
//! * `listen` / `bind` (UDP) on a local port -> a separate `listen:PORT` rule that is never implied by full access; the
//!   kernel mints an inbound grant for that port only, which is what the firewall needs to admit connections.
//! * Name lookups -> the `dns` rule. Programs never talk DNS to the network themselves: the kernel resolver does
//!   (`net::resolve`), and Linux libc resolvers reach it through a **virtual nameserver** (`VDNS`, advertised by the
//!   synthetic `/etc/resolv.conf`): datagrams to `VDNS:53` are forwarded by the kernel to the DHCP-provided server and the
//!   answers come back as if from `VDNS`.
//!
//! Errors are Linux errnos.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::vfs::{self, Data, OpenFile};
use crate::net::{self, NetErr, NetGrant, Proto, TcpState};
use crate::task::{self, Process};

pub const EAGAIN: i64 = 11;
pub const EACCES: i64 = 13;
pub const EINVAL: i64 = 22;
pub const EPIPE: i64 = 32;
pub const ENOTSOCK: i64 = 88;
pub const EDESTADDRREQ: i64 = 89;
pub const EOPNOTSUPP: i64 = 95;
pub const EADDRINUSE: i64 = 98;
pub const ENETUNREACH: i64 = 101;
pub const EISCONN: i64 = 106;
pub const ENOTCONN: i64 = 107;
pub const ETIMEDOUT: i64 = 110;
pub const ECONNREFUSED: i64 = 111;
pub const EALREADY: i64 = 114;
pub const EINPROGRESS: i64 = 115;
const CONNECT_TIMEOUT_MS: u64 = 15_000;

/// The system resolver as programs see it (`nameserver` line of the synthetic resolv.conf). Datagrams to
/// `VDNS:53` are answered by the kernel's resolver path; it is not a routable address.
pub const VDNS: [u8; 4] = [10, 255, 255, 53];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ty {
    Stream,
    Dgram,
}

pub struct SockState {
    pub ty: Ty,
    /// TCP connection id / UDP socket id (a listener has `listener` instead)
    pub id: Option<u32>,
    pub listener: Option<u32>,
    /// connected peer (stream) or default destination (datagram `connect`)
    pub peer: Option<([u8; 4], u16)>,
    pub nonblock: bool,
    /// keeps the grant (and so the NIC) alive for the life of the socket
    pub grant: Option<Arc<NetGrant>>,
    /// non-blocking connect in flight: deadline (uptime ms)
    pub connecting: Option<u64>,
    /// pending asynchronous error (SO_ERROR), cleared when read
    pub so_error: i64,
    pub bind_port: u16,
    pub local_port: u16,
    /// the real DNS server that `VDNS` maps to for this socket
    pub vdns_real: Option<[u8; 4]>,
    /// SO_RCVTIMEO in ms (0 = none)
    pub rcvtimeo_ms: u64,
    pub reuse: bool,
}

impl Drop for SockState {
    fn drop(&mut self) {
        if let Some(l) = self.listener.take() {
            net::listen_close(l);
        }
        if let Some(id) = self.id.take() {
            match self.ty {
                Ty::Stream => net::tcp_close(id),
                Ty::Dgram => net::udp_close(id),
            }
        }
    }
}

impl SockState {
    fn new(ty: Ty, nonblock: bool) -> SockState {
        SockState {
            ty,
            id: None,
            listener: None,
            peer: None,
            nonblock,
            grant: None,
            connecting: None,
            so_error: 0,
            bind_port: 0,
            local_port: 0,
            vdns_real: None,
            rcvtimeo_ms: 0,
            reuse: false,
        }
    }
}

pub fn create(p: &Arc<Process>, ty: Ty, nonblock: bool) -> Result<usize, i64> {
    let f = OpenFile {
        name: alloc::string::String::from("socket"),
        data: Data::Sock(SockState::new(ty, nonblock)),
        pos: 0,
        writable: false,
        dirty: false,
        eof: false,
    };
    vfs::alloc(p, f)
}

fn with_state<R>(p: &Arc<Process>, slot: usize, f: impl FnOnce(&mut SockState) -> R) -> Result<R, i64> {
    let mut g = p.foreign.lock();
    match g.fds.get_mut(slot).and_then(|s| s.as_mut()) {
        Some(OpenFile { data: Data::Sock(s), .. }) => Ok(f(s)),
        Some(_) => Err(ENOTSOCK),
        None => Err(vfs::EBADF),
    }
}

pub fn is_sock(p: &Arc<Process>, slot: usize) -> bool {
    matches!(p.foreign.lock().fds.get(slot).and_then(|s| s.as_ref()), Some(OpenFile { data: Data::Sock(_), .. }))
}

pub fn set_nonblock(p: &Arc<Process>, slot: usize, v: bool) -> Result<(), i64> {
    with_state(p, slot, |s| s.nonblock = v)
}

pub fn is_nonblock(p: &Arc<Process>, slot: usize) -> bool {
    with_state(p, slot, |s| s.nonblock).unwrap_or(false)
}

pub fn ty(p: &Arc<Process>, slot: usize) -> Result<Ty, i64> {
    with_state(p, slot, |s| s.ty)
}

pub fn set_rcvtimeo(p: &Arc<Process>, slot: usize, ms: u64) -> Result<(), i64> {
    with_state(p, slot, |s| s.rcvtimeo_ms = ms)
}

pub fn set_reuse(p: &Arc<Process>, slot: usize, v: bool) -> Result<(), i64> {
    with_state(p, slot, |s| s.reuse = v)
}

pub fn reuse(p: &Arc<Process>, slot: usize) -> bool {
    with_state(p, slot, |s| s.reuse).unwrap_or(false)
}

pub fn peer(p: &Arc<Process>, slot: usize) -> Option<([u8; 4], u16)> {
    with_state(p, slot, |s| s.peer).ok().flatten()
}

/// Read and clear SO_ERROR (an asynchronous connect failure), resolving a finished non-blocking connect first.
pub fn take_error(p: &Arc<Process>, slot: usize) -> i64 {
    let _ = settle_connect(p, slot);
    with_state(p, slot, |s| core::mem::take(&mut s.so_error)).unwrap_or(0)
}

/// (local ip, local port)
pub fn local_addr(p: &Arc<Process>, slot: usize) -> Result<([u8; 4], u16), i64> {
    let (ty, id, lp, bp, listening) = with_state(p, slot, |s| (s.ty, s.id, s.local_port, s.bind_port, s.listener.is_some()))?;
    let ip = net::local_ip().unwrap_or([0; 4]);
    if listening {
        return Ok(([0; 4], bp));
    }
    match (ty, id) {
        (Ty::Stream, Some(i)) => Ok(net::tcp_endpoints(i).map(|(lip, l, _, _)| (lip, l)).unwrap_or((ip, lp))),
        (Ty::Dgram, Some(_)) => Ok((ip, lp)),
        _ => Ok(([0; 4], bp)),
    }
}

// ----------------------------------------------------------------- grants ---

/// The grant for this run and rule scope: reused while live (so time/data limits are per run, not per connection),
/// otherwise minted: narrow for a one-host rule, any-host (optionally unlimited) for "full access". One grant covers
/// TCP and UDP of its scope.
fn session_grant(p: &Arc<Process>, rule: &crate::perm::NetRule, ip: [u8; 4], port: u16, proto: Proto) -> Result<Arc<NetGrant>, i64> {
    let now = crate::time::uptime_ms();
    {
        let g = p.foreign.lock();
        if let Some((_, gr)) = g.net_grants.iter().find(|(d, gr)| *d == rule.dest && !gr.listen && gr.live(now) && gr.covers(proto as u8, ip, port)) {
            return Ok(gr.clone());
        }
    }
    let secs_ms = rule.secs as u64 * 1000;
    let bytes = rule.kib as u64 * 1024;
    let gr = match rule.dest {
        Some(_) => net::issue_grant(
            Proto::All,
            ip,
            32,
            (port, port),
            if secs_ms == 0 { net::grant::MAX_GRANT_MS } else { secs_ms.min(net::grant::MAX_GRANT_MS) },
            if bytes == 0 { net::grant::MAX_GRANT_BYTES } else { bytes.min(net::grant::MAX_GRANT_BYTES) },
        )
        .map_err(|_| ENETUNREACH)?,
        None => net::issue_any_grant(Proto::All, rule.public_only, secs_ms, bytes),
    };
    if !gr.covers(proto as u8, ip, port) {
        return Err(EACCES); // e.g. a LAN address under an internet-only rule, or loopback
    }
    let mut g = p.foreign.lock();
    g.net_grants.retain(|(d, x)| !(*d == rule.dest && !x.listen));
    g.net_grants.push((rule.dest, gr.clone()));
    Ok(gr)
}

/// Inbound grant for one local port (never reused across ports; time/data limits per rule).
fn listen_grant(p: &Arc<Process>, port: u16) -> Result<Arc<NetGrant>, i64> {
    let now = crate::time::uptime_ms();
    {
        let g = p.foreign.lock();
        if let Some((_, gr)) = g.net_grants.iter().find(|(d, gr)| *d == Some(([0; 4], port)) && gr.listen && gr.live(now)) {
            return Ok(gr.clone());
        }
    }
    let Some(rule) = crate::perm::resolve_listen(p, port) else { return Err(EACCES) };
    let gr = net::issue_listen_grant(rule.public_only, (port, port), rule.secs as u64 * 1000, rule.kib as u64 * 1024);
    let mut g = p.foreign.lock();
    g.net_grants.retain(|(d, x)| !(*d == Some(([0; 4], port)) && x.listen));
    g.net_grants.push((Some(([0; 4], port)), gr.clone()));
    Ok(gr)
}

fn wait_ip() -> Result<(), i64> {
    let t0 = crate::time::uptime_ms();
    while net::local_ip().is_none() {
        if crate::time::uptime_ms() - t0 > CONNECT_TIMEOUT_MS {
            return Err(ETIMEDOUT);
        }
        task::sleep_ms(5);
    }
    Ok(())
}

fn net_err(e: NetErr) -> i64 {
    match e {
        NetErr::Denied => EACCES,
        NetErr::WouldBlock => EAGAIN,
        NetErr::NotReady | NetErr::NoNic => ENETUNREACH,
        NetErr::Timeout => ETIMEDOUT,
        NetErr::Closed | NetErr::NoSuchSocket => EPIPE,
        NetErr::Invalid => EADDRINUSE,
    }
}

// ---------------------------------------------------------------- stream ---

pub fn connect(p: &Arc<Process>, slot: usize, ip: [u8; 4], port: u16) -> Result<(), i64> {
    let (ty, has_id, connecting, nb) = with_state(p, slot, |s| (s.ty, s.id.is_some(), s.connecting.is_some(), s.nonblock))?;
    if ty == Ty::Dgram {
        // datagram connect: only fixes the default destination (permission is checked at the first send)
        return with_state(p, slot, |s| {
            s.peer = Some((ip, port));
        });
    }
    if connecting {
        return match settle_connect(p, slot) {
            Ok(true) => Err(EISCONN),
            Ok(false) => Err(EALREADY),
            Err(e) => Err(e),
        };
    }
    if has_id {
        return Err(EISCONN);
    }
    if with_state(p, slot, |s| s.listener.is_some())? {
        return Err(EINVAL);
    }
    let Some(rule) = crate::perm::resolve_net(p, ip, port, "TCP") else { return Err(EACCES) };
    let grant = session_grant(p, &rule, ip, port, Proto::Tcp)?;
    let t0 = crate::time::uptime_ms();
    let id = loop {
        match net::tcp_connect(&grant, ip, port) {
            Ok(id) => break id,
            Err(NetErr::NotReady) if super::signals::interrupted(p) => return Err(super::signals::EINTR),
            Err(NetErr::NotReady) if crate::time::uptime_ms() - t0 < CONNECT_TIMEOUT_MS => task::sleep_ms(5),
            Err(NetErr::NotReady) => return Err(ETIMEDOUT),
            Err(NetErr::Denied) => return Err(EACCES),
            Err(_) => return Err(ENETUNREACH),
        }
    };
    with_state(p, slot, |s| {
        s.id = Some(id);
        s.peer = Some((ip, port));
        s.grant = Some(grant);
    })
    .map_err(|e| {
        net::tcp_close(id);
        e
    })?;
    if nb {
        let deadline = crate::time::uptime_ms() + CONNECT_TIMEOUT_MS;
        let _ = with_state(p, slot, |s| s.connecting = Some(deadline));
        return Err(EINPROGRESS);
    }
    loop {
        match net::tcp_state(id) {
            Ok(TcpState::Established) => return Ok(()),
            Ok(TcpState::Closed) | Err(_) => {
                reset_stream(p, slot);
                return Err(ECONNREFUSED);
            }
            Ok(TcpState::Connecting) => {
                if crate::time::uptime_ms() - t0 > CONNECT_TIMEOUT_MS {
                    reset_stream(p, slot);
                    return Err(ETIMEDOUT);
                }
                if super::signals::interrupted(p) {
                    // like Linux: the handshake carries on in the background; the next connect() reports EALREADY/EISCONN
                    let deadline = t0 + CONNECT_TIMEOUT_MS;
                    let _ = with_state(p, slot, |s| s.connecting = Some(deadline));
                    return Err(super::signals::EINTR);
                }
                task::sleep_ms(2);
            }
        }
    }
}

fn reset_stream(p: &Arc<Process>, slot: usize) {
    let _ = with_state(p, slot, |s| {
        if let Some(id) = s.id.take() {
            net::tcp_close(id);
        }
        s.peer = None;
        s.connecting = None;
    });
}

/// Finish a non-blocking connect if the handshake ended. `Ok(true)` connected, `Ok(false)` still in progress,
/// `Err` it failed (also stored as SO_ERROR).
fn settle_connect(p: &Arc<Process>, slot: usize) -> Result<bool, i64> {
    let (id, deadline) = match with_state(p, slot, |s| (s.id, s.connecting))? {
        (Some(id), Some(d)) => (id, d),
        _ => return Ok(true),
    };
    match net::tcp_state(id) {
        Ok(TcpState::Established) => {
            let _ = with_state(p, slot, |s| s.connecting = None);
            Ok(true)
        }
        Ok(TcpState::Connecting) if crate::time::uptime_ms() < deadline => Ok(false),
        other => {
            let e = if matches!(other, Ok(TcpState::Connecting)) { ETIMEDOUT } else { ECONNREFUSED };
            reset_stream(p, slot);
            let _ = with_state(p, slot, |s| s.so_error = e);
            Err(e)
        }
    }
}

/// bind(2): remember the local port (stream) / open the datagram socket on it (needs the `listen:PORT` decision).
pub fn bind(p: &Arc<Process>, slot: usize, port: u16) -> Result<(), i64> {
    let (ty, bound, opened) = with_state(p, slot, |s| (s.ty, s.bind_port != 0, s.id.is_some() || s.listener.is_some()))?;
    if bound || opened {
        return Err(EINVAL);
    }
    match ty {
        Ty::Stream => with_state(p, slot, |s| s.bind_port = port),
        Ty::Dgram => {
            if port == 0 {
                return Ok(()); // ephemeral: opened lazily at the first send
            }
            let grant = listen_grant(p, port)?;
            wait_ip()?;
            let (id, lport) = net::udp_open(&grant, port).map_err(net_err)?;
            with_state(p, slot, |s| {
                s.id = Some(id);
                s.bind_port = lport;
                s.local_port = lport;
                s.grant = Some(grant);
            })
        }
    }
}

pub fn listen(p: &Arc<Process>, slot: usize, backlog: usize) -> Result<(), i64> {
    let (ty, port, active) = with_state(p, slot, |s| (s.ty, s.bind_port, s.id.is_some() || s.listener.is_some()))?;
    if ty != Ty::Stream {
        return Err(EOPNOTSUPP);
    }
    if active {
        return Err(EINVAL);
    }
    if port == 0 {
        return Err(EINVAL); // we do not invent a port: the program must bind() one, which is what the user approves
    }
    let grant = listen_grant(p, port)?;
    wait_ip()?;
    let id = net::tcp_listen(&grant, port, backlog.clamp(1, 8)).map_err(net_err)?;
    with_state(p, slot, |s| {
        s.listener = Some(id);
        s.grant = Some(grant);
    })
}

/// accept(2): the new connection as an `OpenFile` plus the peer address. Blocks unless non-blocking.
pub fn accept(p: &Arc<Process>, slot: usize, nonblock_new: bool) -> Result<(usize, ([u8; 4], u16)), i64> {
    let (lid, nb, grant, port) = with_state(p, slot, |s| (s.listener, s.nonblock, s.grant.clone(), s.bind_port))?;
    let Some(lid) = lid else { return Err(EINVAL) };
    loop {
        match net::tcp_accept(lid) {
            Ok((pip, pport, cid)) => {
                let mut st = SockState::new(Ty::Stream, nonblock_new);
                st.id = Some(cid);
                st.peer = Some((pip, pport));
                st.grant = grant;
                st.local_port = port;
                let f = OpenFile { name: alloc::string::String::from("socket"), data: Data::Sock(st), pos: 0, writable: false, dirty: false, eof: false };
                let ns = vfs::alloc(p, f)?;
                return Ok((ns, (pip, pport)));
            }
            Err(NetErr::WouldBlock) => {
                if nb {
                    return Err(EAGAIN);
                }
                if super::signals::interrupted(p) {
                    return Err(super::signals::ERESTART);
                }
                task::sleep_ms(1);
            }
            Err(_) => return Err(EINVAL),
        }
    }
}

pub fn shutdown(p: &Arc<Process>, slot: usize, how: u32) -> Result<(), i64> {
    let (ty, id) = with_state(p, slot, |s| (s.ty, s.id))?;
    match (ty, id) {
        (Ty::Stream, Some(i)) => {
            if how == 1 || how == 2 {
                net::tcp_shutdown_write(i);
            }
            Ok(())
        }
        (_, None) => Err(ENOTCONN),
        _ => Ok(()),
    }
}

/// (tcp id, nonblocking, rcv timeout) of a connected stream socket.
fn conn(p: &Arc<Process>, slot: usize) -> Result<(u32, bool, u64), i64> {
    with_state(p, slot, |s| match (s.ty, s.id, s.connecting) {
        (Ty::Stream, Some(i), None) => Ok((i, s.nonblock, s.rcvtimeo_ms)),
        (Ty::Stream, Some(_), Some(_)) => Err(ENOTCONN),
        (Ty::Stream, None, _) => Err(ENOTCONN),
        (Ty::Dgram, _, _) => Err(EINVAL),
    })?
}

/// Send all of `data` (blocking unless the socket is non-blocking and nothing could be sent).
pub fn send(p: &Arc<Process>, slot: usize, data: &[u8], dontwait: bool) -> Result<usize, i64> {
    if ty(p, slot)? == Ty::Dgram {
        return sendto(p, slot, data, None);
    }
    let _ = settle_connect(p, slot);
    let (id, nb, _) = conn(p, slot)?;
    let nb = nb || dontwait;
    let mut sent = 0;
    while sent < data.len() {
        match net::tcp_send(id, &data[sent..]) {
            Ok(n) => sent += n,
            Err(NetErr::WouldBlock) => {
                if nb {
                    return if sent > 0 { Ok(sent) } else { Err(EAGAIN) };
                }
                task::sleep_ms(1);
            }
            Err(_) => return if sent > 0 { Ok(sent) } else { Err(EPIPE) },
        }
    }
    Ok(sent)
}

/// Receive up to `max` bytes; an empty result is end of stream.
pub fn recv(p: &Arc<Process>, slot: usize, max: usize, dontwait: bool) -> Result<Vec<u8>, i64> {
    if ty(p, slot)? == Ty::Dgram {
        return recvfrom(p, slot, max, dontwait).map(|(v, _)| v);
    }
    let _ = settle_connect(p, slot);
    let (id, nb, tmo) = conn(p, slot)?;
    let nb = nb || dontwait;
    let t0 = crate::time::uptime_ms();
    let mut buf = alloc::vec![0u8; max.min(64 * 1024)];
    loop {
        match net::tcp_recv(id, &mut buf) {
            Ok(n) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Err(NetErr::WouldBlock) => {
                if nb {
                    return Err(EAGAIN);
                }
                if tmo != 0 && crate::time::uptime_ms() - t0 >= tmo {
                    return Err(EAGAIN);
                }
                if super::signals::interrupted(p) {
                    return Err(super::signals::ERESTART);
                }
                task::sleep_ms(1);
            }
            Err(_) => return Ok(Vec::new()),
        }
    }
}

// -------------------------------------------------------------- datagram ---

/// Open the datagram socket on first use with a grant that covers its first destination.
fn ensure_udp(p: &Arc<Process>, slot: usize, grant: &Arc<NetGrant>) -> Result<u32, i64> {
    if let Some(id) = with_state(p, slot, |s| s.id)? {
        return Ok(id);
    }
    wait_ip()?;
    let (id, lport) = net::udp_open(grant, 0).map_err(net_err)?;
    with_state(p, slot, |s| {
        s.id = Some(id);
        s.local_port = lport;
        s.grant = Some(grant.clone());
    })?;
    Ok(id)
}

/// sendto(2) on a datagram socket (`dest` None = the connect()ed peer).
pub fn sendto(p: &Arc<Process>, slot: usize, data: &[u8], dest: Option<([u8; 4], u16)>) -> Result<usize, i64> {
    if ty(p, slot)? != Ty::Dgram {
        // a stream socket ignores the address, like Linux
        return send(p, slot, data, false);
    }
    let Some((ip, port)) = dest.or(peer(p, slot)) else { return Err(EDESTADDRREQ) };
    if data.len() > 1472 {
        return Err(90); // EMSGSIZE: no fragmentation
    }
    if ip == VDNS && port == 53 {
        // kernel-mediated name resolution: one `dns` decision, then the kernel forwards to the real server
        if !crate::perm::resolve_dns(p) {
            return Err(EACCES);
        }
        let grant = net::dns_grant();
        let server = net::dns_ready(CONNECT_TIMEOUT_MS).ok_or(ENETUNREACH)?;
        let id = ensure_udp(p, slot, &grant)?;
        let _ = with_state(p, slot, |s| s.vdns_real = Some(server));
        return net::udp_send(id, &grant, server, 53, data).map_err(net_err);
    }
    let Some(rule) = crate::perm::resolve_net(p, ip, port, "UDP") else { return Err(EACCES) };
    let grant = session_grant(p, &rule, ip, port, Proto::Udp)?;
    let id = ensure_udp(p, slot, &grant)?;
    net::udp_send(id, &grant, ip, port, data).map_err(net_err)
}

/// recvfrom(2): one datagram and its source.
pub fn recvfrom(p: &Arc<Process>, slot: usize, max: usize, dontwait: bool) -> Result<(Vec<u8>, Option<([u8; 4], u16)>), i64> {
    if ty(p, slot)? == Ty::Stream {
        return recv(p, slot, max, dontwait).map(|v| (v, peer(p, slot)));
    }
    let (nb, tmo) = with_state(p, slot, |s| (s.nonblock, s.rcvtimeo_ms))?;
    let nb = nb || dontwait;
    let t0 = crate::time::uptime_ms();
    let mut buf = alloc::vec![0u8; 2048];
    loop {
        let id = with_state(p, slot, |s| s.id)?;
        if let Some(id) = id {
            match net::udp_recv(id, &mut buf) {
                Ok((n, ip, port)) => {
                    let vreal = with_state(p, slot, |s| s.vdns_real)?;
                    let from = if Some(ip) == vreal && port == 53 { VDNS } else { ip };
                    buf.truncate(n.min(max));
                    return Ok((buf, Some((from, port))));
                }
                Err(NetErr::WouldBlock) => {}
                Err(e) => return Err(net_err(e)),
            }
        }
        if nb {
            return Err(EAGAIN);
        }
        if tmo != 0 && crate::time::uptime_ms() - t0 >= tmo {
            return Err(EAGAIN);
        }
        if super::signals::interrupted(p) {
            return Err(super::signals::ERESTART);
        }
        task::sleep_ms(1);
    }
}

// ------------------------------------------------------------- readiness ---

/// (readable, writable) for poll/select/epoll. A listener is readable when a connection waits; a socket whose
/// non-blocking connect finished (or failed) is writable.
pub fn readiness(p: &Arc<Process>, slot: usize) -> (bool, bool) {
    let st = with_state(p, slot, |s| (s.ty, s.id, s.listener, s.connecting, s.so_error));
    let Ok((ty, id, listener, connecting, err)) = st else { return (false, false) };
    if let Some(l) = listener {
        return (net::listen_ready(l), false);
    }
    if connecting.is_some() {
        return match settle_connect(p, slot) {
            Ok(true) | Err(_) => (false, true),
            Ok(false) => (false, false),
        };
    }
    match (ty, id) {
        (Ty::Stream, Some(i)) => (net::tcp_can_recv(i), net::tcp_can_send(i)),
        (Ty::Dgram, Some(i)) => (net::udp_can_recv(i), net::udp_can_send(i)),
        (Ty::Dgram, None) => (false, true),
        (Ty::Stream, None) => (err != 0, err != 0), // a failed connect reports POLLOUT|POLLERR
    }
}

/// Did a failed/never-connected stream socket hang up?
pub fn hangup(p: &Arc<Process>, slot: usize) -> bool {
    with_state(p, slot, |s| s.ty == Ty::Stream && s.id.is_none() && s.listener.is_none() && s.connecting.is_none() && s.so_error != 0).unwrap_or(false)
}

/// Resolve a host name for the Windows layer: numeric addresses need nothing; names need the `dns` decision.
pub fn resolve_host(p: &Arc<Process>, name: &str) -> Result<[u8; 4], i64> {
    if let Some((ip, _)) = crate::perm::parse_dest(&alloc::format!("{}:1", name)) {
        return Ok(ip);
    }
    if !crate::perm::resolve_dns(p) {
        return Err(EACCES);
    }
    net::resolve(name).map_err(|e| match e {
        net::dns::DnsErr::NotFound | net::dns::DnsErr::NoData | net::dns::DnsErr::BadName => 2, // ENOENT -> HOST_NOT_FOUND
        _ => ETIMEDOUT,
    })
}

/// Bytes readable without blocking (FIONREAD): the next datagram's size, or the TCP receive queue.
pub fn pending_bytes(p: &Arc<Process>, slot: usize) -> usize {
    match with_state(p, slot, |s| (s.ty, s.id)) {
        Ok((Ty::Dgram, Some(i))) => net::udp_peek_len(i),
        Ok((Ty::Stream, Some(i))) => net::tcp_recv_queue(i),
        _ => 0,
    }
}
