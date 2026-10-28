//! Default-deny, stateful, per-frame firewall. Every Ethernet frame in either direction passes
//! through [`Firewall::outbound`] / [`Firewall::inbound`]; nothing moves unless a rule says so.
//!
//! Rules come from live `NetGrant`s (explicit user consent) plus two narrow infrastructure
//! exceptions that exist only while the NIC is enabled: ARP on the local link and the DHCP client
//! exchange. There are no listening sockets: inbound traffic is accepted only as a reply to a flow
//! that an allowed outbound packet created. All parsing treats the frame as hostile input.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use super::grant::{NetGrant, Proto};
use crate::audit::{self, EV_NET_ALLOW, EV_NET_DENY};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dir {
    Out = 0,
    In = 1,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Reason {
    // allow reasons
    Grant = 1,
    Established = 2,
    InfraArp = 3,
    InfraDhcp = 4,
    // deny reasons
    NoGrant = 16,
    Disabled = 17,
    Malformed = 18,
    Unsolicited = 19,
    Budget = 20,
    Spoofed = 21,
    Fragment = 22,
    UnsupportedL3 = 23,
}

#[derive(Clone, Copy, Debug)]
pub struct Decision {
    pub allow: bool,
    pub reason: Reason,
    pub grant: u64,
    pub new_flow: bool,
    pub proto: u8,
    pub remote: [u8; 4],
    pub port: u16,
}

impl Decision {
    fn deny(reason: Reason) -> Decision {
        Decision { allow: false, reason, grant: 0, new_flow: false, proto: 0, remote: [0; 4], port: 0 }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Ip4 {
    pub proto: u8,
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub sport: u16,
    pub dport: u16,
    pub icmp_type: u8,
    pub icmp_id: u16,
    pub tcp_flags: u8,
}

#[derive(Clone, Copy, Debug)]
pub enum Parsed {
    Arp { op: u16, spa: [u8; 4], tpa: [u8; 4] },
    Ip4(Ip4),
}

fn be16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(o)?, *b.get(o.checked_add(1)?)?]))
}

/// Parse an Ethernet frame. Every offset is bounds-checked; fragments and unknown ethertypes are rejected.
pub fn parse(f: &[u8]) -> Result<Parsed, Reason> {
    let ethertype = be16(f, 12).ok_or(Reason::Malformed)?;
    match ethertype {
        0x0806 => {
            if f.len() < 14 + 28 || be16(f, 14) != Some(1) || be16(f, 16) != Some(0x0800) || f[18] != 6 || f[19] != 4 {
                return Err(Reason::Malformed);
            }
            let op = be16(f, 20).ok_or(Reason::Malformed)?;
            Ok(Parsed::Arp { op, spa: [f[28], f[29], f[30], f[31]], tpa: [f[38], f[39], f[40], f[41]] })
        }
        0x0800 => {
            if f.len() < 14 + 20 {
                return Err(Reason::Malformed);
            }
            let ip = &f[14..];
            let ihl = (ip[0] & 0x0F) as usize * 4;
            if ip[0] >> 4 != 4 || ihl < 20 {
                return Err(Reason::Malformed);
            }
            let total = be16(ip, 2).ok_or(Reason::Malformed)? as usize;
            if total < ihl || total > ip.len() {
                return Err(Reason::Malformed);
            }
            if be16(ip, 6).ok_or(Reason::Malformed)? & 0x3FFF != 0 {
                return Err(Reason::Fragment);
            }
            let l4 = &ip[ihl..total];
            let proto = ip[9];
            let mut p = Ip4 { proto, src: [ip[12], ip[13], ip[14], ip[15]], dst: [ip[16], ip[17], ip[18], ip[19]], sport: 0, dport: 0, icmp_type: 0, icmp_id: 0, tcp_flags: 0 };
            match proto {
                6 if l4.len() >= 20 => {
                    p.sport = be16(l4, 0).ok_or(Reason::Malformed)?;
                    p.dport = be16(l4, 2).ok_or(Reason::Malformed)?;
                    p.tcp_flags = l4[13];
                }
                17 if l4.len() >= 8 => {
                    p.sport = be16(l4, 0).ok_or(Reason::Malformed)?;
                    p.dport = be16(l4, 2).ok_or(Reason::Malformed)?;
                }
                1 if l4.len() >= 8 => {
                    p.icmp_type = l4[0];
                    p.icmp_id = be16(l4, 4).ok_or(Reason::Malformed)?;
                }
                6 | 17 | 1 => return Err(Reason::Malformed),
                _ => return Err(Reason::UnsupportedL3),
            }
            Ok(Parsed::Ip4(p))
        }
        _ => Err(Reason::UnsupportedL3),
    }
}

struct Flow {
    proto: u8,
    remote: [u8; 4],
    rport: u16,
    lport: u16,
    grant: u64,
    last_ms: u64,
    /// created by an inbound packet that a listen grant admitted (a server's connection)
    inbound: bool,
}

const MAX_FLOWS: usize = 256;
const FLOW_IDLE_MS: u64 = 900_000;
const DENY_AUDIT_PER_SEC: u32 = 20;

pub struct Firewall {
    grants: Vec<Weak<NetGrant>>,
    flows: Vec<Flow>,
    /// NIC is up (set by the network layer). While false everything is denied.
    pub enabled: bool,
    pub our_ip: [u8; 4],
    pub dhcp_server: [u8; 4],
    pub allowed: u64,
    pub denied: u64,
    win_start: u64,
    win_count: u32,
    pub deny_suppressed: u64,
}

impl Firewall {
    pub const fn new() -> Firewall {
        Firewall {
            grants: Vec::new(),
            flows: Vec::new(),
            enabled: false,
            our_ip: [0; 4],
            dhcp_server: [0; 4],
            allowed: 0,
            denied: 0,
            win_start: 0,
            win_count: 0,
            deny_suppressed: 0,
        }
    }

    pub fn add_grant(&mut self, g: &Arc<NetGrant>) {
        self.grants.retain(|w| w.strong_count() > 0);
        self.grants.push(Arc::downgrade(g));
    }

    pub fn has_live_grant(&mut self, now: u64) -> bool {
        self.grants.retain(|w| w.strong_count() > 0);
        self.grants.iter().any(|w| w.upgrade().map_or(false, |g| g.live(now)))
    }

    pub fn clear_flows(&mut self) {
        self.flows.clear();
    }

    fn find_grant(&self, now: u64, proto: u8, ip: [u8; 4], port: u16) -> Option<Arc<NetGrant>> {
        self.grants.iter().filter_map(|w| w.upgrade()).find(|g| g.live(now) && g.covers(proto, ip, port))
    }

    fn grant_by_id(&self, now: u64, id: u64) -> Option<Arc<NetGrant>> {
        self.grants.iter().filter_map(|w| w.upgrade()).find(|g| g.id == id && g.live(now))
    }

    fn find_listen(&self, now: u64, proto: u8, src: [u8; 4], lport: u16) -> Option<Arc<NetGrant>> {
        self.grants.iter().filter_map(|w| w.upgrade()).find(|g| g.live(now) && g.covers_inbound(proto, src, lport))
    }

    fn touch_flow(&mut self, now: u64, proto: u8, remote: [u8; 4], rport: u16, lport: u16, grant: u64, inbound: bool) -> bool {
        self.flows.retain(|f| now.saturating_sub(f.last_ms) < FLOW_IDLE_MS);
        if let Some(f) = self.flows.iter_mut().find(|f| f.proto == proto && f.remote == remote && f.rport == rport && f.lport == lport) {
            f.last_ms = now;
            return false;
        }
        if self.flows.len() >= MAX_FLOWS {
            self.flows.remove(0);
        }
        self.flows.push(Flow { proto, remote, rport, lport, grant, last_ms: now, inbound });
        true
    }

    /// Decide on a frame the stack wants to transmit.
    pub fn outbound(&mut self, frame: &[u8], now: u64) -> Decision {
        let d = self.outbound_inner(frame, now);
        self.record(Dir::Out, &d, now);
        d
    }

    /// Decide on a frame that arrived from the wire.
    pub fn inbound(&mut self, frame: &[u8], now: u64) -> Decision {
        let d = self.inbound_inner(frame, now);
        self.record(Dir::In, &d, now);
        d
    }

    fn outbound_inner(&mut self, frame: &[u8], now: u64) -> Decision {
        if !self.enabled {
            return Decision::deny(Reason::Disabled);
        }
        let parsed = match parse(frame) {
            Ok(p) => p,
            Err(r) => return Decision::deny(r),
        };
        match parsed {
            Parsed::Arp { op, spa, .. } => {
                if (op != 1 && op != 2) || (spa != self.our_ip && spa != [0; 4]) {
                    return Decision::deny(Reason::Spoofed);
                }
                Decision { allow: true, reason: Reason::InfraArp, grant: 0, new_flow: false, proto: 0, remote: [0; 4], port: 0 }
            }
            Parsed::Ip4(p) => {
                let info = |allow, reason, grant, new_flow| Decision { allow, reason, grant, new_flow, proto: p.proto, remote: p.dst, port: p.dport };
                // DHCP client: 0.0.0.0 or our address -> broadcast (or the known server), port 68 -> 67.
                if p.proto == 17 && p.sport == 68 && p.dport == 67 {
                    let bcast = p.dst == [255; 4];
                    if (p.src == [0; 4] || p.src == self.our_ip) && (bcast || (p.dst == self.dhcp_server && p.dst != [0; 4])) {
                        return info(true, Reason::InfraDhcp, 0, false);
                    }
                    return info(false, Reason::Spoofed, 0, false);
                }
                if self.our_ip == [0; 4] || p.src != self.our_ip {
                    return info(false, Reason::Spoofed, 0, false);
                }
                if p.proto == 1 && p.icmp_type != 8 {
                    return info(false, Reason::NoGrant, 0, false); // only echo requests can be granted
                }
                // replies of a connection a listen grant admitted (we never open flows towards the peer on our own)
                let (rp, lp) = if p.proto == 1 { (0, p.icmp_id) } else { (p.dport, p.sport) };
                if let Some(gid) = self.flows.iter().find(|f| f.inbound && f.proto == p.proto && f.remote == p.dst && f.rport == rp && f.lport == lp).map(|f| f.grant) {
                    let Some(g) = self.grant_by_id(now, gid) else {
                        return info(false, Reason::NoGrant, gid, false);
                    };
                    if !g.charge(frame.len() as u64) {
                        return info(false, Reason::Budget, g.id, false);
                    }
                    if let Some(f) = self.flows.iter_mut().find(|f| f.inbound && f.proto == p.proto && f.remote == p.dst && f.rport == rp && f.lport == lp) {
                        f.last_ms = now;
                    }
                    return info(true, Reason::Established, g.id, false);
                }
                let Some(g) = self.find_grant(now, p.proto, p.dst, p.dport) else {
                    return info(false, Reason::NoGrant, 0, false);
                };
                if !g.charge(frame.len() as u64) {
                    return info(false, Reason::Budget, g.id, false);
                }
                let (rport, lport) = if p.proto == 1 { (0, p.icmp_id) } else { (p.dport, p.sport) };
                let new_flow = self.touch_flow(now, p.proto, p.dst, rport, lport, g.id, false);
                info(true, Reason::Grant, g.id, new_flow)
            }
        }
    }

    fn inbound_inner(&mut self, frame: &[u8], now: u64) -> Decision {
        if !self.enabled {
            return Decision::deny(Reason::Disabled);
        }
        let parsed = match parse(frame) {
            Ok(p) => p,
            Err(r) => return Decision::deny(r),
        };
        match parsed {
            Parsed::Arp { op, tpa, .. } => {
                if (op != 1 && op != 2) || self.our_ip == [0; 4] || tpa != self.our_ip {
                    return Decision::deny(Reason::Unsolicited);
                }
                Decision { allow: true, reason: Reason::InfraArp, grant: 0, new_flow: false, proto: 0, remote: [0; 4], port: 0 }
            }
            Parsed::Ip4(p) => {
                let info = |allow, reason, grant| Decision { allow, reason, grant, new_flow: false, proto: p.proto, remote: p.src, port: p.sport };
                // DHCP server reply (offer/ack): only accepted while enabled; the DHCP client socket validates xid/chaddr.
                if p.proto == 17 && p.sport == 67 && p.dport == 68 {
                    return info(true, Reason::InfraDhcp, 0);
                }
                if p.dst != self.our_ip || self.our_ip == [0; 4] {
                    return info(false, Reason::Unsolicited, 0); // broadcast / multicast / not for us
                }
                let (rport, lport) = if p.proto == 1 {
                    if p.icmp_type != 0 {
                        return info(false, Reason::Unsolicited, 0);
                    }
                    (0, p.icmp_id)
                } else {
                    (p.sport, p.dport)
                };
                let Some(gid) = self.flows.iter().find(|f| f.proto == p.proto && f.remote == p.src && f.rport == rport && f.lport == lport).map(|f| f.grant) else {
                    // no flow yet: only a TCP SYN (no ACK) or a UDP datagram to a port a live listen grant covers can start one
                    let starts = (p.proto == 6 && p.tcp_flags & 0x12 == 0x02) || p.proto == 17;
                    if starts {
                        if let Some(g) = self.find_listen(now, p.proto, p.src, lport) {
                            if !g.charge(frame.len() as u64) {
                                return info(false, Reason::Budget, g.id);
                            }
                            self.touch_flow(now, p.proto, p.src, rport, lport, g.id, true);
                            let mut d = info(true, Reason::Grant, g.id);
                            d.new_flow = true;
                            return d;
                        }
                    }
                    return info(false, Reason::Unsolicited, 0);
                };
                let Some(g) = self.grant_by_id(now, gid) else {
                    return info(false, Reason::NoGrant, gid);
                };
                if !g.charge(frame.len() as u64) {
                    return info(false, Reason::Budget, gid);
                }
                if let Some(f) = self.flows.iter_mut().find(|f| f.proto == p.proto && f.remote == p.src && f.rport == rport && f.lport == lport) {
                    f.last_ms = now;
                }
                info(true, Reason::Established, gid)
            }
        }
    }

    fn record(&mut self, dir: Dir, d: &Decision, now: u64) {
        let sysno = dir as u32 | (d.proto as u32) << 8 | (d.reason as u32) << 16;
        if d.allow {
            self.allowed += 1;
            if d.new_flow {
                audit::log(EV_NET_ALLOW, sysno, d.grant, u32::from_be_bytes(d.remote) as u64, d.port as u64, 0);
            }
        } else {
            self.denied += 1;
            if now.saturating_sub(self.win_start) >= 1000 {
                self.win_start = now;
                self.win_count = 0;
            }
            if self.win_count < DENY_AUDIT_PER_SEC {
                self.win_count += 1;
                audit::log(EV_NET_DENY, sysno, d.grant, u32::from_be_bytes(d.remote) as u64, d.port as u64, -crate::sys::errno::EPERM);
            } else {
                self.deny_suppressed += 1;
            }
        }
    }
}

/// Audit a socket-layer denial (a process asked for something its grant does not cover).
pub fn audit_socket_deny(grant: u64, proto: Proto, ip: [u8; 4], port: u16, reason: Reason) {
    let sysno = 0u32 | (proto as u32) << 8 | (reason as u32) << 16;
    audit::log(EV_NET_DENY, sysno, grant, u32::from_be_bytes(ip) as u64, port as u64, -crate::sys::errno::EPERM);
}
