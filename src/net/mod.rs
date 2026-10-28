//! Networking: air-gapped by default.
//!
//! * The NIC is probed at boot but stays **inert** (device reset, no queues, no DRIVER_OK).
//! * The poll thread brings it up only while at least one live `NetGrant` exists, and resets it
//!   again as soon as the last one expires or is dropped.
//! * Every frame goes through the default-deny [`firewall::Firewall`] (both directions).
//! * Sockets are only reachable through a grant; there are no listening sockets.

pub mod dns;
pub mod firewall;
pub mod grant;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use log::{info, warn};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{dhcpv4, tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};

use crate::drivers::net::{self as nicdrv, Nic, MAX_FRAME};
use crate::sync::IrqMutex;
use firewall::{audit_socket_deny, Firewall, Reason};
pub use grant::{GrantErr, NetGrant, Proto};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetErr {
    Denied,
    NotReady,
    NoNic,
    NoSuchSocket,
    WouldBlock,
    Closed,
    Invalid,
    Timeout,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TcpState {
    Connecting,
    Established,
    Closed,
}

struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    dhcp: SocketHandle,
    ip: Option<[u8; 4]>,
    /// first DNS server (or the gateway) from the DHCP lease
    dns: Option<[u8; 4]>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Tcp,
    Udp,
}

struct SockEntry {
    id: u32,
    handle: SocketHandle,
    grant: Arc<NetGrant>,
    closing: bool,
    kind: Kind,
}

/// A listening TCP port: `backlog` smoltcp sockets in LISTEN state; an established one is handed out by `accept`.
struct Listener {
    id: u32,
    port: u16,
    handles: Vec<SocketHandle>,
    grant: Arc<NetGrant>,
    backlog: usize,
}

struct NetState {
    nic: Option<Nic>,
    fw: Firewall,
    stack: Option<Stack>,
    socks: Vec<SockEntry>,
    listeners: Vec<Listener>,
    next_id: u32,
    next_port: u16,
}

static NET: IrqMutex<NetState> = IrqMutex::new(NetState { nic: None, fw: Firewall::new(), stack: None, socks: Vec::new(), listeners: Vec::new(), next_id: 1, next_port: 49152 });

/// Probe the NIC (leaves it disabled).
pub fn init() {
    match nicdrv::probe_first() {
        Some(Ok(n)) => {
            let m = n.mac();
            info!("net: {} found, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}; NIC left DISABLED (no NetGrant)", n.kind(), m[0], m[1], m[2], m[3], m[4], m[5]);
            NET.lock().nic = Some(n);
        }
        Some(Err(e)) => warn!("net: NIC probe failed: {}", e),
        None => info!("net: no supported NIC present (virtio-net, Intel e1000)"),
    }
}

pub fn has_nic() -> bool {
    NET.lock().nic.is_some()
}

/// Mint a grant and register it with the firewall (trusted kernel path; user consent happens before this call).
pub fn issue_grant(proto: Proto, remote: [u8; 4], prefix: u8, ports: (u16, u16), duration_ms: u64, bytes_max: u64) -> Result<Arc<NetGrant>, GrantErr> {
    let g = NetGrant::new(proto, remote, prefix, ports, duration_ms, bytes_max, crate::time::uptime_ms())?;
    NET.lock().fw.add_grant(&g);
    info!("net: grant #{} issued: {:?} {}.{}.{}.{}/{} ports {}-{} for {} ms, {} bytes", g.id, proto, remote[0], remote[1], remote[2], remote[3], prefix, g.port_lo, g.port_hi, duration_ms, bytes_max);
    Ok(g)
}

/// Mint an any-host grant (see `NetGrant::any`); used for the user's "full access" decision.
pub fn issue_any_grant(proto: Proto, public_only: bool, duration_ms: u64, bytes_max: u64) -> Arc<NetGrant> {
    let g = NetGrant::any(proto, public_only, duration_ms, bytes_max, crate::time::uptime_ms());
    NET.lock().fw.add_grant(&g);
    info!("net: ANY-HOST grant #{} issued: {:?}{} time {} bytes {}", g.id, proto, if public_only { " (internet only)" } else { "" }, if duration_ms == 0 { alloc::string::String::from("unlimited") } else { alloc::format!("{} ms", duration_ms) }, if bytes_max == 0 { alloc::string::String::from("unlimited") } else { alloc::format!("{}", bytes_max) });
    g
}

#[derive(Clone, Copy, Debug)]
pub struct NetStats {
    pub nic_present: bool,
    pub enabled: bool,
    pub ip: Option<[u8; 4]>,
    pub tx_frames: u64,
    pub rx_frames: u64,
    pub fw_allowed: u64,
    pub fw_denied: u64,
    pub device_status: u8,
}

pub fn stats() -> NetStats {
    let s = NET.lock();
    NetStats {
        nic_present: s.nic.is_some(),
        enabled: s.stack.is_some(),
        ip: s.stack.as_ref().and_then(|st| st.ip),
        tx_frames: s.nic.as_ref().map_or(0, |n| n.tx_frames()),
        rx_frames: s.nic.as_ref().map_or(0, |n| n.rx_frames()),
        fw_allowed: s.fw.allowed,
        fw_denied: s.fw.denied,
        device_status: s.nic.as_ref().map_or(0, |n| n.device_status()),
    }
}

// ------------------------------------------------------------- device ---

struct FwDevice<'a> {
    nic: &'a mut Nic,
    fw: &'a mut Firewall,
    now: u64,
}

struct RxTok {
    buf: [u8; MAX_FRAME],
    len: usize,
}
struct TxTok<'a> {
    nic: &'a mut Nic,
    fw: &'a mut Firewall,
    now: u64,
}

impl RxToken for RxTok {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, f: F) -> R {
        f(&mut self.buf[..self.len])
    }
}
impl<'a> TxToken for TxTok<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = [0u8; MAX_FRAME];
        let l = len.min(MAX_FRAME);
        let r = f(&mut buf[..l]);
        if len <= MAX_FRAME && self.fw.outbound(&buf[..l], self.now).allow {
            self.nic.send(&buf[..l]);
        }
        r
    }
}

impl<'a> Device for FwDevice<'a> {
    type RxToken<'b> = RxTok where Self: 'b;
    type TxToken<'b> = TxTok<'b> where Self: 'b;

    fn receive(&mut self, _ts: Instant) -> Option<(RxTok, TxTok<'_>)> {
        if !self.nic.can_send() {
            return None;
        }
        let mut buf = [0u8; MAX_FRAME];
        loop {
            let n = self.nic.recv(&mut buf)?;
            if self.fw.inbound(&buf[..n], self.now).allow {
                return Some((RxTok { buf, len: n }, TxTok { nic: &mut *self.nic, fw: &mut *self.fw, now: self.now }));
            }
        }
    }
    fn transmit(&mut self, _ts: Instant) -> Option<TxTok<'_>> {
        if !self.nic.can_send() {
            return None;
        }
        Some(TxTok { nic: &mut *self.nic, fw: &mut *self.fw, now: self.now })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ethernet;
        c.max_transmission_unit = MAX_FRAME;
        c.max_burst_size = Some(1);
        c
    }
}

// -------------------------------------------------------------- state ---

impl NetState {
    fn enable(&mut self, now: u64) {
        let Some(nic) = self.nic.as_mut() else { return };
        if let Err(e) = nic.start() {
            warn!("net: NIC start failed: {}", e);
            return;
        }
        self.fw.enabled = true;
        self.fw.our_ip = [0; 4];
        self.fw.dhcp_server = [0; 4];
        self.fw.clear_flows();
        let mut cfg = Config::new(HardwareAddress::Ethernet(EthernetAddress(nic.mac())));
        cfg.random_seed = now.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ crate::time::ticks();
        let mut dev = FwDevice { nic, fw: &mut self.fw, now };
        let iface = Interface::new(cfg, &mut dev, Instant::from_millis(now as i64));
        let mut sockets = SocketSet::new(vec![]);
        let dhcp = sockets.add(dhcpv4::Socket::new());
        self.stack = Some(Stack { iface, sockets, dhcp, ip: None, dns: None });
        info!("net: NIC ENABLED (a live NetGrant exists); requesting DHCP");
    }

    fn disable(&mut self) {
        self.stack = None;
        self.socks.clear();
        self.listeners.clear();
        self.fw.enabled = false;
        self.fw.our_ip = [0; 4];
        self.fw.clear_flows();
        if let Some(n) = self.nic.as_mut() {
            n.stop();
        }
        info!("net: NIC DISABLED (no live NetGrant); device reset");
    }

    fn poll(&mut self, now: u64) {
        if self.nic.is_none() {
            return;
        }
        let live = self.fw.has_live_grant(now);
        if live && self.stack.is_none() {
            self.enable(now);
        } else if !live && self.stack.is_some() {
            self.disable();
        }
        let (Some(st), Some(nic)) = (self.stack.as_mut(), self.nic.as_mut()) else { return };
        // Sockets whose grant died are aborted immediately.
        for e in &self.socks {
            if !e.grant.live(now) {
                match e.kind {
                    Kind::Tcp => st.sockets.get_mut::<tcp::Socket>(e.handle).abort(),
                    Kind::Udp => st.sockets.get_mut::<udp::Socket>(e.handle).close(),
                }
            }
        }
        for l in &self.listeners {
            if !l.grant.live(now) {
                for h in &l.handles {
                    st.sockets.get_mut::<tcp::Socket>(*h).abort();
                }
            }
        }
        {
            let mut dev = FwDevice { nic, fw: &mut self.fw, now };
            st.iface.poll(Instant::from_millis(now as i64), &mut dev, &mut st.sockets);
        }
        match st.sockets.get_mut::<dhcpv4::Socket>(st.dhcp).poll() {
            Some(dhcpv4::Event::Configured(c)) => {
                st.iface.update_ip_addrs(|a| {
                    a.clear();
                    let _ = a.push(IpCidr::Ipv4(c.address));
                });
                match c.router {
                    Some(r) => {
                        let _ = st.iface.routes_mut().add_default_ipv4_route(r);
                    }
                    None => {
                        st.iface.routes_mut().remove_default_ipv4_route();
                    }
                }
                let ip = c.address.address().0;
                st.ip = Some(ip);
                st.dns = c.dns_servers.first().map(|d| d.0).or(c.router.map(|r| r.0));
                self.fw.our_ip = ip;
                self.fw.dhcp_server = c.server.address.0;
                info!("net: DHCP lease {}.{}.{}.{}/{} gw {:?}", ip[0], ip[1], ip[2], ip[3], c.address.prefix_len(), c.router.map(|r| r.0));
            }
            Some(dhcpv4::Event::Deconfigured) => {
                st.iface.update_ip_addrs(|a| a.clear());
                st.ip = None;
                st.dns = None;
                self.fw.our_ip = [0; 4];
            }
            None => {}
        }
        // Keep every listener's backlog full (a socket that was reset goes back to LISTEN).
        for l in self.listeners.iter_mut() {
            if !l.grant.live(now) {
                continue;
            }
            for h in &l.handles {
                let s = st.sockets.get_mut::<tcp::Socket>(*h);
                if s.state() == tcp::State::Closed {
                    let _ = s.listen(l.port);
                }
            }
        }
        // Reap fully closed sockets.
        let mut i = 0;
        while i < self.socks.len() {
            let h = self.socks[i].handle;
            let st_closed = match self.socks[i].kind {
                Kind::Tcp => matches!(st.sockets.get::<tcp::Socket>(h).state(), tcp::State::Closed | tcp::State::TimeWait),
                Kind::Udp => true,
            };
            if self.socks[i].closing && st_closed {
                st.sockets.remove(h);
                self.socks.remove(i);
            } else {
                i += 1;
            }
        }
    }
}

/// One polling step (called by the net thread).
pub fn poll() {
    let now = crate::time::uptime_ms();
    NET.lock().poll(now);
}

/// Kernel thread body: poll quickly while the NIC is up, lazily otherwise.
pub fn run() {
    loop {
        poll();
        let up = NET.lock().stack.is_some();
        crate::task::sleep_ms(if up { 1 } else { 10 });
    }
}

/// Block (cooperatively) until the interface has a DHCP lease.
pub fn wait_ready(timeout_ms: u64) -> bool {
    let t0 = crate::time::uptime_ms();
    while crate::time::uptime_ms() - t0 < timeout_ms {
        if stats().ip.is_some() {
            return true;
        }
        crate::task::sleep_ms(5);
    }
    false
}

/// Mint an inbound (server) grant: remote hosts may reach local ports `ports` (TCP + UDP).
pub fn issue_listen_grant(public_only: bool, ports: (u16, u16), duration_ms: u64, bytes_max: u64) -> Arc<NetGrant> {
    let g = NetGrant::listen(public_only, ports, duration_ms, bytes_max, crate::time::uptime_ms());
    NET.lock().fw.add_grant(&g);
    info!("net: LISTEN grant #{} issued: local ports {}-{}{}", g.id, ports.0, ports.1, if public_only { " (internet sources only)" } else { "" });
    g
}

/// The kernel resolver's grant (UDP/53 only). Reused while live so the NIC is not bounced per lookup.
pub fn dns_grant() -> Arc<NetGrant> {
    static G: IrqMutex<Option<Arc<NetGrant>>> = IrqMutex::new(None);
    let now = crate::time::uptime_ms();
    let mut g = G.lock();
    if let Some(x) = g.as_ref() {
        if x.live(now) && x.expires_ms.saturating_sub(now) > 5_000 {
            return x.clone();
        }
    }
    let n = NetGrant::dns(30_000, now);
    NET.lock().fw.add_grant(&n);
    *g = Some(n.clone());
    n
}

/// DNS server from the DHCP lease (None until the NIC is up and leased).
pub fn dns_server() -> Option<[u8; 4]> {
    NET.lock().stack.as_ref().and_then(|s| s.dns)
}

/// Our IPv4 address (None until leased).
pub fn local_ip() -> Option<[u8; 4]> {
    NET.lock().stack.as_ref().and_then(|s| s.ip)
}
// ------------------------------------------------------------ sockets ---

fn alloc_port(s: &mut NetState) -> u16 {
    let p = s.next_port;
    s.next_port = if s.next_port >= 65000 { 49152 } else { s.next_port + 1 };
    p
}

fn check_grant(g: &Arc<NetGrant>, proto: Proto, ip: [u8; 4], port: u16) -> Result<(), NetErr> {
    let now = crate::time::uptime_ms();
    if !g.live(now) || !g.covers(proto as u8, ip, port) {
        audit_socket_deny(g.id, proto, ip, port, Reason::NoGrant);
        return Err(NetErr::Denied);
    }
    Ok(())
}

/// Open a TCP connection to `ip:port`. Allowed only if `g` is live and covers the destination.
pub fn tcp_connect(g: &Arc<NetGrant>, ip: [u8; 4], port: u16) -> Result<u32, NetErr> {
    check_grant(g, Proto::Tcp, ip, port)?;
    let mut s = NET.lock();
    if s.nic.is_none() {
        return Err(NetErr::NoNic);
    }
    let lport = alloc_port(&mut s);
    let id = s.next_id;
    let st = s.stack.as_mut().ok_or(NetErr::NotReady)?;
    if st.ip.is_none() {
        return Err(NetErr::NotReady);
    }
    let mut sock = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; 16384]), tcp::SocketBuffer::new(vec![0u8; 8192]));
    sock.connect(st.iface.context(), (IpAddress::Ipv4(Ipv4Address(ip)), port), lport).map_err(|_| NetErr::Invalid)?;
    let handle = st.sockets.add(sock);
    s.next_id += 1;
    s.socks.push(SockEntry { id, handle, grant: g.clone(), closing: false, kind: Kind::Tcp });
    Ok(id)
}

fn with_sock<R>(id: u32, f: impl FnOnce(&mut tcp::Socket) -> R) -> Result<R, NetErr> {
    let mut s = NET.lock();
    let h = s.socks.iter().find(|e| e.id == id && !e.closing && e.kind == Kind::Tcp).map(|e| e.handle).ok_or(NetErr::NoSuchSocket)?;
    let st = s.stack.as_mut().ok_or(NetErr::Closed)?;
    Ok(f(st.sockets.get_mut::<tcp::Socket>(h)))
}

pub fn tcp_state(id: u32) -> Result<TcpState, NetErr> {
    with_sock(id, |s| match s.state() {
        tcp::State::SynSent | tcp::State::SynReceived => TcpState::Connecting,
        tcp::State::Established | tcp::State::CloseWait | tcp::State::FinWait1 | tcp::State::FinWait2 => TcpState::Established,
        _ => TcpState::Closed,
    })
}

pub fn tcp_send(id: u32, data: &[u8]) -> Result<usize, NetErr> {
    with_sock(id, |s| {
        if !s.may_send() {
            return Err(NetErr::Closed);
        }
        match s.send_slice(data) {
            Ok(0) => Err(NetErr::WouldBlock),
            Ok(n) => Ok(n),
            Err(_) => Err(NetErr::Closed),
        }
    })?
}

/// `Ok(0)` means end of stream.
pub fn tcp_recv(id: u32, out: &mut [u8]) -> Result<usize, NetErr> {
    with_sock(id, |s| {
        if s.can_recv() {
            s.recv_slice(out).map_err(|_| NetErr::Closed)
        } else if !s.may_recv() {
            Ok(0)
        } else {
            Err(NetErr::WouldBlock)
        }
    })?
}

/// Would `tcp_recv` return immediately (data available, or end of stream / error)?
pub fn tcp_can_recv(id: u32) -> bool {
    with_sock(id, |s| s.can_recv() || !s.may_recv()).unwrap_or(true)
}

/// Would `tcp_send` accept at least one byte right now?
pub fn tcp_can_send(id: u32) -> bool {
    with_sock(id, |s| s.can_send()).unwrap_or(false)
}

/// Half-close: send FIN, keep receiving.
pub fn tcp_shutdown_write(id: u32) {
    let _ = with_sock(id, |s| s.close());
}

/// (local ip, local port, remote ip, remote port) of a connection, when known.
pub fn tcp_endpoints(id: u32) -> Option<([u8; 4], u16, [u8; 4], u16)> {
    let ip = local_ip().unwrap_or([0; 4]);
    with_sock(id, |s| {
        let l = s.local_endpoint().map(|e| e.port).unwrap_or(0);
        let (rip, rp) = s.remote_endpoint().map(|e| match e.addr { IpAddress::Ipv4(a) => (a.0, e.port) }).unwrap_or(([0; 4], 0));
        (ip, l, rip, rp)
    })
    .ok()
}

pub fn tcp_close(id: u32) {
    let mut s = NET.lock();
    let Some(h) = s.socks.iter().find(|e| e.id == id && e.kind == Kind::Tcp).map(|e| e.handle) else { return };
    if let Some(st) = s.stack.as_mut() {
        st.sockets.get_mut::<tcp::Socket>(h).close();
    }
    if let Some(e) = s.socks.iter_mut().find(|e| e.id == id) {
        e.closing = true;
    }
}

// ---- listening sockets (servers) ----

/// Start listening on local TCP `port`. `g` must be a live listen grant covering the port.
pub fn tcp_listen(g: &Arc<NetGrant>, port: u16, backlog: usize) -> Result<u32, NetErr> {
    let now = crate::time::uptime_ms();
    if !g.live(now) || !g.listen || !(g.port_lo..=g.port_hi).contains(&port) || port == 0 {
        audit_socket_deny(g.id, Proto::Tcp, [0; 4], port, Reason::NoGrant);
        return Err(NetErr::Denied);
    }
    let mut s = NET.lock();
    if s.nic.is_none() {
        return Err(NetErr::NoNic);
    }
    if s.listeners.iter().any(|l| l.port == port) {
        return Err(NetErr::Invalid); // EADDRINUSE
    }
    let id = s.next_id;
    let st = s.stack.as_mut().ok_or(NetErr::NotReady)?;
    let backlog = backlog.clamp(1, 8);
    let mut handles = Vec::new();
    for _ in 0..backlog {
        let mut sock = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; 16384]), tcp::SocketBuffer::new(vec![0u8; 8192]));
        sock.listen(port).map_err(|_| NetErr::Invalid)?;
        handles.push(st.sockets.add(sock));
    }
    s.next_id += 1;
    s.listeners.push(Listener { id, port, handles, grant: g.clone(), backlog });
    Ok(id)
}

/// Is a connection waiting for `accept`?
pub fn listen_ready(id: u32) -> bool {
    let mut s = NET.lock();
    let s = &mut *s;
    let (Some(l), Some(st)) = (s.listeners.iter().find(|l| l.id == id), s.stack.as_mut()) else { return false };
    l.handles.iter().any(|h| matches!(st.sockets.get::<tcp::Socket>(*h).state(), tcp::State::Established | tcp::State::CloseWait))
}

/// Take an established connection from the listener: `(connection id, peer ip, peer port)`.
pub fn tcp_accept(id: u32) -> Result<([u8; 4], u16, u32), NetErr> {
    let mut s = NET.lock();
    let s = &mut *s;
    let st = s.stack.as_mut().ok_or(NetErr::Closed)?;
    let li = s.listeners.iter().position(|l| l.id == id).ok_or(NetErr::NoSuchSocket)?;
    let l = &mut s.listeners[li];
    let pos = l.handles.iter().position(|h| matches!(st.sockets.get::<tcp::Socket>(*h).state(), tcp::State::Established | tcp::State::CloseWait));
    let Some(pos) = pos else { return Err(NetErr::WouldBlock) };
    let h = l.handles.remove(pos);
    let (peer_ip, peer_port) = st.sockets.get::<tcp::Socket>(h).remote_endpoint().map(|e| match e.addr { IpAddress::Ipv4(a) => (a.0, e.port) }).unwrap_or(([0; 4], 0));
    // refill the backlog
    let mut fresh = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; 16384]), tcp::SocketBuffer::new(vec![0u8; 8192]));
    let _ = fresh.listen(l.port);
    l.handles.push(st.sockets.add(fresh));
    let grant = l.grant.clone();
    let cid = s.next_id;
    s.next_id += 1;
    s.socks.push(SockEntry { id: cid, handle: h, grant, closing: false, kind: Kind::Tcp });
    Ok((peer_ip, peer_port, cid))
}

pub fn listen_close(id: u32) {
    let mut s = NET.lock();
    let s = &mut *s;
    let Some(li) = s.listeners.iter().position(|l| l.id == id) else { return };
    let l = s.listeners.remove(li);
    if let Some(st) = s.stack.as_mut() {
        for h in l.handles {
            let k = st.sockets.get_mut::<tcp::Socket>(h);
            k.abort();
            st.sockets.remove(h);
        }
    }
}

// ---- UDP ----

/// Open a UDP socket. `lport == 0` picks an ephemeral port. `g` covers what it may SEND (or, for a listen grant, which
/// local port it may bind).
pub fn udp_open(g: &Arc<NetGrant>, lport: u16) -> Result<(u32, u16), NetErr> {
    let now = crate::time::uptime_ms();
    if !g.live(now) {
        return Err(NetErr::Denied);
    }
    if lport != 0 && !(g.listen && (g.port_lo..=g.port_hi).contains(&lport)) {
        audit_socket_deny(g.id, Proto::Udp, [0; 4], lport, Reason::NoGrant);
        return Err(NetErr::Denied);
    }
    let mut s = NET.lock();
    if s.nic.is_none() {
        return Err(NetErr::NoNic);
    }
    let port = if lport == 0 { alloc_port(&mut s) } else { lport };
    let id = s.next_id;
    let st = s.stack.as_mut().ok_or(NetErr::NotReady)?;
    let mut sock = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0u8; 32 * 1024]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0u8; 32 * 1024]),
    );
    sock.bind(port).map_err(|_| NetErr::Invalid)?;
    let handle = st.sockets.add(sock);
    s.next_id += 1;
    s.socks.push(SockEntry { id, handle, grant: g.clone(), closing: false, kind: Kind::Udp });
    Ok((id, port))
}

fn with_udp<R>(id: u32, f: impl FnOnce(&mut udp::Socket) -> R) -> Result<R, NetErr> {
    let mut s = NET.lock();
    let h = s.socks.iter().find(|e| e.id == id && !e.closing && e.kind == Kind::Udp).map(|e| e.handle).ok_or(NetErr::NoSuchSocket)?;
    let st = s.stack.as_mut().ok_or(NetErr::Closed)?;
    Ok(f(st.sockets.get_mut::<udp::Socket>(h)))
}

/// Send one datagram. `g` is the grant to check the destination against (it may differ from the socket's own grant,
/// e.g. the kernel resolver). Replies are admitted by the firewall's flow table.
pub fn udp_send(id: u32, g: &Arc<NetGrant>, ip: [u8; 4], port: u16, data: &[u8]) -> Result<usize, NetErr> {
    check_grant(g, Proto::Udp, ip, port)?;
    if data.len() > 1472 {
        return Err(NetErr::Invalid);
    }
    with_udp(id, |s| match s.send_slice(data, (IpAddress::Ipv4(Ipv4Address(ip)), port)) {
        Ok(()) => Ok(data.len()),
        Err(udp::SendError::BufferFull) => Err(NetErr::WouldBlock),
        Err(_) => Err(NetErr::Invalid),
    })?
}

/// Receive one datagram: `(len copied, peer ip, peer port)`; a datagram longer than `out` is truncated.
pub fn udp_recv(id: u32, out: &mut [u8]) -> Result<(usize, [u8; 4], u16), NetErr> {
    with_udp(id, |s| match s.recv_slice(out) {
        Ok((n, meta)) => {
            let (ip, port) = match meta.endpoint.addr { IpAddress::Ipv4(a) => (a.0, meta.endpoint.port) };
            Ok((n, ip, port))
        }
        Err(udp::RecvError::Exhausted) => Err(NetErr::WouldBlock),
        Err(_) => Err(NetErr::Invalid),
    })?
}

/// Length of the next queued datagram (0 if none).
pub fn udp_peek_len(id: u32) -> usize {
    with_udp(id, |s| s.peek().map(|(d, _)| d.len()).unwrap_or(0)).unwrap_or(0)
}
/// Bytes waiting in a TCP receive buffer.
pub fn tcp_recv_queue(id: u32) -> usize {
    with_sock(id, |s| s.recv_queue()).unwrap_or(0)
}
pub fn udp_can_recv(id: u32) -> bool {
    with_udp(id, |s| s.can_recv()).unwrap_or(false)
}
pub fn udp_can_send(id: u32) -> bool {
    with_udp(id, |s| s.can_send()).unwrap_or(false)
}
pub fn udp_close(id: u32) {
    let mut s = NET.lock();
    let Some(h) = s.socks.iter().find(|e| e.id == id && e.kind == Kind::Udp).map(|e| e.handle) else { return };
    if let Some(st) = s.stack.as_mut() {
        st.sockets.get_mut::<udp::Socket>(h).close();
    }
    if let Some(e) = s.socks.iter_mut().find(|e| e.id == id) {
        e.closing = true;
    }
}

// ---- name resolution ----

/// Make sure the NIC is up and leased, holding the resolver grant; returns the DNS server.
pub fn dns_ready(timeout_ms: u64) -> Option<[u8; 4]> {
    let _g = dns_grant();
    let t0 = crate::time::uptime_ms();
    while crate::time::uptime_ms() - t0 < timeout_ms {
        if let Some(d) = dns_server() {
            return Some(d);
        }
        crate::task::sleep_ms(5);
    }
    None
}

/// Resolve `name` to an IPv4 address through the DHCP-provided DNS server (A records, CNAME chains followed).
/// Numeric addresses are returned as-is. Never reaches the network without the caller having been authorised
/// (`perm::resolve_dns`): this function itself holds no policy.
pub fn resolve(name: &str) -> Result<[u8; 4], dns::DnsErr> {
    if let Some((ip, _)) = crate::perm::parse_dest(&alloc::format!("{}:1", name)) {
        return Ok(ip);
    }
    if let Some(ip) = dns::cache_get(name) {
        return Ok(ip);
    }
    if !dns::valid_name(name) {
        return Err(dns::DnsErr::BadName);
    }
    let g = dns_grant();
    let server = dns_ready(15_000).ok_or(dns::DnsErr::NoServer)?;
    let (id, _) = udp_open(&g, 0).map_err(|_| dns::DnsErr::NoServer)?;
    let res = (|| {
        let xid = (crate::time::ticks() as u16) ^ (name.len() as u16).wrapping_mul(0x9E37);
        let q = dns::build_query(name, xid);
        let mut buf = [0u8; 1500];
        for attempt in 0..3u64 {
            udp_send(id, &g, server, 53, &q).map_err(|_| dns::DnsErr::NoServer)?;
            let t0 = crate::time::uptime_ms();
            while crate::time::uptime_ms() - t0 < 1500 + attempt * 1000 {
                match udp_recv(id, &mut buf) {
                    Ok((n, ip, port)) if ip == server && port == 53 => match dns::parse_response(&buf[..n], xid) {
                        r if r != Err(dns::DnsErr::BadResponse) && r.is_err() => {
                            info!("net: dns '{}' -> {:?} (reply {} bytes: {:02x?})", name, r, n, &buf[..n.min(40)]);
                            return r;
                        }
                        Err(dns::DnsErr::BadResponse) => continue, // not ours / garbled: keep waiting
                        r => return r,
                    },
                    Ok(_) => continue,
                    Err(NetErr::WouldBlock) => crate::task::sleep_ms(2),
                    Err(_) => return Err(dns::DnsErr::NoServer),
                }
            }
        }
        Err(dns::DnsErr::Timeout)
    })();
    udp_close(id);
    if let Ok(ip) = res {
        dns::cache_put(name, ip);
    }
    res
}
