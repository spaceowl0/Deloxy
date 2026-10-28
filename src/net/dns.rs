//! Minimal DNS stub-resolver pieces: query construction, response parsing (A records, CNAME chains, name
//! compression) and a tiny cache. The response is hostile input: every offset is bounds-checked and compression
//! loops are bounded.

use alloc::string::String;
use alloc::vec::Vec;

use crate::sync::IrqMutex;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DnsErr {
    BadName,
    NoServer,
    Timeout,
    /// NXDOMAIN
    NotFound,
    /// the name exists but has no IPv4 address, or the server failed
    NoData,
    BadResponse,
}

/// Valid host name: 1..=253 bytes, labels 1..=63 of `[A-Za-z0-9-_]`.
pub fn valid_name(n: &str) -> bool {
    let n = n.strip_suffix('.').unwrap_or(n);
    if n.is_empty() || n.len() > 253 {
        return false;
    }
    n.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'))
}

pub fn build_query(name: &str, id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // RD
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QDCOUNT=1
    for label in name.strip_suffix('.').unwrap_or(name).split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    q
}

fn be16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(o)?, *b.get(o.checked_add(1)?)?]))
}

/// Skip a (possibly compressed) name starting at `o`; returns the offset after it.
fn skip_name(b: &[u8], mut o: usize) -> Option<usize> {
    loop {
        let l = *b.get(o)? as usize;
        if l == 0 {
            return o.checked_add(1);
        }
        if l & 0xC0 == 0xC0 {
            b.get(o + 1)?;
            return o.checked_add(2);
        }
        if l & 0xC0 != 0 {
            return None;
        }
        o = o.checked_add(1 + l)?;
    }
}

/// Parse a response to our A query with transaction id `xid`. Returns the first IPv4 address.
pub fn parse_response(b: &[u8], xid: u16) -> Result<[u8; 4], DnsErr> {
    if b.len() < 12 || be16(b, 0) != Some(xid) {
        return Err(DnsErr::BadResponse);
    }
    let flags = be16(b, 2).ok_or(DnsErr::BadResponse)?;
    if flags & 0x8000 == 0 {
        return Err(DnsErr::BadResponse); // not a response
    }
    match flags & 0xF {
        0 => {}
        3 => return Err(DnsErr::NotFound),
        _ => return Err(DnsErr::NoData),
    }
    let qd = be16(b, 4).ok_or(DnsErr::BadResponse)? as usize;
    let an = be16(b, 6).ok_or(DnsErr::BadResponse)? as usize;
    let mut o = 12;
    for _ in 0..qd.min(4) {
        o = skip_name(b, o).ok_or(DnsErr::BadResponse)?.checked_add(4).ok_or(DnsErr::BadResponse)?;
    }
    for _ in 0..an.min(32) {
        o = skip_name(b, o).ok_or(DnsErr::BadResponse)?;
        let ty = be16(b, o).ok_or(DnsErr::BadResponse)?;
        let class = be16(b, o + 2).ok_or(DnsErr::BadResponse)?;
        let rdlen = be16(b, o + 8).ok_or(DnsErr::BadResponse)? as usize;
        let rd = o.checked_add(10).ok_or(DnsErr::BadResponse)?;
        let end = rd.checked_add(rdlen).ok_or(DnsErr::BadResponse)?;
        if end > b.len() {
            return Err(DnsErr::BadResponse);
        }
        if ty == 1 && class == 1 && rdlen == 4 {
            return Ok([b[rd], b[rd + 1], b[rd + 2], b[rd + 3]]);
        }
        o = end; // CNAME and others: the A record for the target follows in the same answer section
    }
    Err(DnsErr::NoData)
}

// ---- cache ----

struct Entry {
    name: String,
    ip: [u8; 4],
    at: u64,
}
static CACHE: IrqMutex<Vec<Entry>> = IrqMutex::new(Vec::new());
const TTL_MS: u64 = 300_000;

pub fn cache_get(name: &str) -> Option<[u8; 4]> {
    let now = crate::time::uptime_ms();
    CACHE.lock().iter().find(|e| e.name.eq_ignore_ascii_case(name) && now.saturating_sub(e.at) < TTL_MS).map(|e| e.ip)
}

pub fn cache_put(name: &str, ip: [u8; 4]) {
    let now = crate::time::uptime_ms();
    let mut c = CACHE.lock();
    c.retain(|e| !e.name.eq_ignore_ascii_case(name) && now.saturating_sub(e.at) < TTL_MS);
    if c.len() >= 64 {
        c.remove(0);
    }
    c.push(Entry { name: String::from(name), ip, at: now });
}

/// Reverse lookup in the cache (for permission prompts: "chat.example.com (1.2.3.4)").
pub fn cache_name_of(ip: [u8; 4]) -> Option<String> {
    let now = crate::time::uptime_ms();
    CACHE.lock().iter().rev().find(|e| e.ip == ip && now.saturating_sub(e.at) < TTL_MS).map(|e| e.name.clone())
}
