//! `NetGrant`: the capability object that authorises one narrow slice of network access.
//!
//! A grant names a protocol, a remote IPv4 prefix, a port range, an expiry and a byte budget.
//! Grants are minted only by trusted kernel paths (user consent in the shell / deloxy-de, the
//! updater); a process can hold, narrow-by-dropping and use one, but never create one.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    /// TCP and UDP (used by rule-scoped grants for programs: one budget for everything the program sends)
    All = 0,
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GrantErr {
    BadPrefix,
    ForbiddenRange,
    BadPorts,
    BadDuration,
    BadBudget,
}

pub const MAX_GRANT_MS: u64 = 3_600_000;
pub const MAX_GRANT_BYTES: u64 = 1 << 30;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub struct NetGrant {
    pub id: u64,
    pub proto: Proto,
    pub remote: [u8; 4],
    pub prefix: u8,
    pub port_lo: u16,
    pub port_hi: u16,
    pub expires_ms: u64,
    pub bytes_max: u64,
    /// an any-host grant that also excludes private/LAN ranges ("internet only")
    pub public_only: bool,
    /// an INBOUND grant: allows remote hosts matching `remote/prefix` to reach local ports `port_lo..=port_hi`
    /// (servers). It never authorises outbound connections.
    pub listen: bool,
    used: AtomicU64,
    revoked: AtomicBool,
}

/// this-net, loopback, multicast/broadcast: never grantable
pub fn forbidden(ip: [u8; 4]) -> bool {
    ip[0] == 0 || ip[0] == 127 || ip[0] >= 224
}

/// RFC 1918, link-local and CGNAT ranges
pub fn private(ip: [u8; 4]) -> bool {
    ip[0] == 10 || (ip[0] == 172 && (16..=31).contains(&ip[1])) || (ip[0] == 192 && ip[1] == 168) || (ip[0] == 169 && ip[1] == 254) || (ip[0] == 100 && (64..=127).contains(&ip[1]))
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

impl NetGrant {
    /// Validate and create a grant valid for `duration_ms` from `now_ms`.
    pub fn new(proto: Proto, remote: [u8; 4], prefix: u8, ports: (u16, u16), duration_ms: u64, bytes_max: u64, now_ms: u64) -> Result<Arc<NetGrant>, GrantErr> {
        if !(16..=32).contains(&prefix) {
            return Err(GrantErr::BadPrefix);
        }
        let net = u32::from_be_bytes(remote) & mask(prefix);
        let first = (net >> 24) as u8;
        if first == 0 || first == 127 || first >= 224 {
            return Err(GrantErr::ForbiddenRange); // this-net, loopback, multicast, broadcast
        }
        let (lo, hi) = if proto == Proto::Icmp { (0, 0) } else { ports };
        if proto != Proto::Icmp && (lo == 0 || lo > hi) {
            return Err(GrantErr::BadPorts);
        }
        if duration_ms == 0 || duration_ms > MAX_GRANT_MS {
            return Err(GrantErr::BadDuration);
        }
        if bytes_max == 0 || bytes_max > MAX_GRANT_BYTES {
            return Err(GrantErr::BadBudget);
        }
        Ok(Arc::new(NetGrant {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            proto,
            remote: net.to_be_bytes(),
            prefix,
            port_lo: lo,
            port_hi: hi,
            expires_ms: now_ms.saturating_add(duration_ms),
            bytes_max,
            public_only: false,
            listen: false,
            used: AtomicU64::new(0),
            revoked: AtomicBool::new(false),
        }))
    }

    /// An inbound grant for a server: remote hosts (all, or all but private/LAN with `public_only`) may reach local
    /// ports `lo..=hi` over TCP and UDP. `duration_ms == 0` / `bytes_max == 0` = unlimited.
    pub fn listen(public_only: bool, ports: (u16, u16), duration_ms: u64, bytes_max: u64, now_ms: u64) -> Arc<NetGrant> {
        Arc::new(NetGrant {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            proto: Proto::All,
            remote: [0; 4],
            prefix: 0,
            port_lo: ports.0,
            port_hi: ports.1,
            expires_ms: if duration_ms == 0 { u64::MAX } else { now_ms.saturating_add(duration_ms) },
            bytes_max: if bytes_max == 0 { u64::MAX } else { bytes_max },
            public_only,
            listen: true,
            used: AtomicU64::new(0),
            revoked: AtomicBool::new(false),
        })
    }

    /// The kernel resolver's grant: UDP port 53 to any host (the resolver itself only talks to the DHCP-provided
    /// DNS server). Short-lived and tiny; minted per lookup burst, never handed to a program.
    pub fn dns(duration_ms: u64, now_ms: u64) -> Arc<NetGrant> {
        Arc::new(NetGrant {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            proto: Proto::Udp,
            remote: [0; 4],
            prefix: 0,
            port_lo: 53,
            port_hi: 53,
            expires_ms: now_ms.saturating_add(duration_ms),
            bytes_max: 256 * 1024,
            public_only: false,
            listen: false,
            used: AtomicU64::new(0),
            revoked: AtomicBool::new(false),
        })
    }

    /// An any-host grant for the user's explicit "regular connection" choice: every IPv4 destination except
    /// this-net, loopback, multicast/broadcast (never grantable) and, with `public_only`, private/LAN ranges.
    /// `duration_ms == 0` / `bytes_max == 0` mean unlimited (the fixed ceilings of `new` do not apply).
    pub fn any(proto: Proto, public_only: bool, duration_ms: u64, bytes_max: u64, now_ms: u64) -> Arc<NetGrant> {
        Arc::new(NetGrant {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            proto,
            remote: [0; 4],
            prefix: 0,
            port_lo: 1,
            port_hi: 65535,
            expires_ms: if duration_ms == 0 { u64::MAX } else { now_ms.saturating_add(duration_ms) },
            bytes_max: if bytes_max == 0 { u64::MAX } else { bytes_max },
            public_only,
            listen: false,
            used: AtomicU64::new(0),
            revoked: AtomicBool::new(false),
        })
    }

    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
    }
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }
    pub fn live(&self, now_ms: u64) -> bool {
        !self.revoked.load(Ordering::SeqCst) && now_ms < self.expires_ms && self.used() < self.bytes_max
    }
    fn proto_ok(&self, proto: u8) -> bool {
        proto == self.proto as u8 || (self.proto == Proto::All && (proto == Proto::Tcp as u8 || proto == Proto::Udp as u8))
    }
    /// Does this (inbound) grant admit a packet from `src` to local port `lport`?
    pub fn covers_inbound(&self, proto: u8, src: [u8; 4], lport: u16) -> bool {
        self.listen && self.proto_ok(proto) && !forbidden(src) && !(self.public_only && private(src)) && (self.port_lo..=self.port_hi).contains(&lport)
    }
    pub fn covers(&self, proto: u8, ip: [u8; 4], port: u16) -> bool {
        if self.listen {
            return false; // inbound grants never authorise outbound traffic
        }
        if self.prefix == 0 && (forbidden(ip) || (self.public_only && private(ip))) {
            return false; // any-host grants still never reach loopback/multicast, nor LAN when internet-only
        }
        self.proto_ok(proto)
            && (u32::from_be_bytes(ip) & mask(self.prefix)) == u32::from_be_bytes(self.remote)
            && (proto == Proto::Icmp as u8 || (self.port_lo..=self.port_hi).contains(&port))
    }
    /// Account `n` bytes; false (and no charge) if that would exceed the budget.
    pub fn charge(&self, n: u64) -> bool {
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            match cur.checked_add(n) {
                Some(next) if next <= self.bytes_max => match self.used.compare_exchange(cur, next, Ordering::SeqCst, Ordering::Relaxed) {
                    Ok(_) => return true,
                    Err(v) => cur = v,
                },
                _ => return false,
            }
        }
    }
}
