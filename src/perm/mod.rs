//! Application permissions for foreign (Linux/Windows) programs.
//!
//! **Files.** A foreign program starts with NO file access. The first time it touches a file (open/opendir/unlink
//! through `abi::vfs`) the kernel resolves its policy: a stored decision for (program name, image hash) is applied;
//! otherwise the user is asked on the console (once / always / no / deny always). A modified binary has a different
//! hash and is asked again.
//!
//! **Network.** Each `connect` is checked against the program's network rules (see `NetRule`): a rule is either for
//! one destination (`ip:port`) or for ANY host ("full access"), with an optional **time limit** and **data cap**
//! (0 = unlimited) and an "internet only" flag that excludes private/LAN ranges. Without a rule the user is asked:
//! `[o]nce [a]lways (this host) [f]ull access [n]o [d]eny always`. Limits apply to the program's whole run (one
//! shared grant per rule), not to each connection.
//!
//! **Name resolution and servers.** Two more scopes use the same rule type: `dns` (look up host names; the kernel's own
//! resolver talks to the DHCP-provided DNS server, a program never gets raw DNS access) and `listen:PORT` (accept
//! incoming TCP connections / UDP datagrams on that local port). A full-access (any-host) rule includes `dns` but never
//! `listen`: running a server is always its own explicit decision. Answers given as "once" are remembered for the run
//! (`ForeignState::net_asked`) so a program is not asked again for every packet.
//!
//! `perms.db` (store, kernel-owned) holds the stored decisions, one per line:
//! `NAME HASH R W` (files) or `NAME HASH R 0 DEST [T<secs>] [K<KiB>] [P]` (network; DEST = `a.b.c.d:port` | `any` | `dns` | `listen:PORT`).
//! Native programs are not subject to this (their authority is exactly the capabilities they were given).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::sync::IrqMutex;
use crate::task::Process;

pub type Dest = Option<([u8; 4], u16)>;

/// A network rule: where, for how long, how much data. `secs`/`kib` of 0 mean unlimited.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NetRule {
    /// `None` = any host
    pub dest: Dest,
    pub secs: u32,
    pub kib: u32,
    /// exclude private/LAN ranges (only meaningful for any-host rules)
    pub public_only: bool,
}

impl NetRule {
    /// Defaults for "always (this host)": 10 minutes, 64 MiB (as before).
    pub fn this_host(ip: [u8; 4], port: u16) -> NetRule {
        NetRule { dest: Some((ip, port)), secs: 600, kib: 64 * 1024, public_only: false }
    }
    /// "Full access": any host, no time or data limit.
    pub fn full() -> NetRule {
        NetRule { dest: None, secs: 0, kib: 0, public_only: false }
    }
    /// Look up host names through the kernel resolver.
    pub fn dns() -> NetRule {
        NetRule { dest: Some(DNS_DEST), secs: 0, kib: 0, public_only: false }
    }
    /// Accept incoming connections / datagrams on local `port` (no limits by default: a server runs for a while).
    pub fn listen(port: u16) -> NetRule {
        NetRule { dest: Some(([0; 4], port)), secs: 0, kib: 0, public_only: false }
    }
    pub fn is_dns(&self) -> bool {
        self.dest == Some(DNS_DEST)
    }
    pub fn is_listen(&self) -> bool {
        matches!(self.dest, Some(([0, 0, 0, 0], p)) if p != 0)
    }
}

/// Scope sentinel for name resolution (0.0.0.0 is never a valid connect destination).
pub const DNS_DEST: ([u8; 4], u16) = ([0; 4], 0);

/// Human-readable scope of a rule (`net 1.2.3.4:80`, `net DNS lookups`, `net LISTEN port 8080`, `net any host`).
pub fn describe(r: &NetRule) -> String {
    match r.dest {
        None => String::from(if r.public_only { "net any (internet)" } else { "net any host" }),
        Some(DNS_DEST) => String::from("net DNS lookups"),
        Some(([0, 0, 0, 0], port)) => alloc::format!("net LISTEN port {}", port),
        Some((ip, port)) => alloc::format!("net {}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port),
    }
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub hash: String,
    pub read: bool,
    pub write: bool,
    /// consumed by the next decision (a one-shot answer)
    pub once: bool,
    /// `Some(rule)`: a network rule (`read` = allowed); `None`: a file rule
    pub net: Option<NetRule>,
}

static POLICY: IrqMutex<Vec<Entry>> = IrqMutex::new(Vec::new());
const DB: &str = "perms.db";

pub fn parse_dest(s: &str) -> Option<([u8; 4], u16)> {
    let (ip, port) = s.rsplit_once(':')?;
    let mut o = [0u8; 4];
    let mut it = ip.split('.');
    for b in o.iter_mut() {
        *b = it.next()?.parse().ok()?;
    }
    if it.next().is_some() {
        return None;
    }
    Some((o, port.parse().ok().filter(|p| *p != 0)?))
}

/// Parse the network part of a stored line: `DEST [T<secs>] [K<KiB>] [P]`; missing limits get the old defaults.
fn parse_rule<'a>(mut it: impl Iterator<Item = &'a str>) -> Option<NetRule> {
    let d = it.next()?;
    let dest = if d == "any" {
        None
    } else if d == "dns" {
        Some(DNS_DEST)
    } else if let Some(p) = d.strip_prefix("listen:") {
        Some(([0; 4], p.parse::<u16>().ok().filter(|p| *p != 0)?))
    } else {
        Some(parse_dest(d)?)
    };
    let special = matches!(dest, None | Some(([0, 0, 0, 0], _)));
    let (mut secs, mut kib, mut public_only) = if !special { (600, 64 * 1024, false) } else { (0, 0, false) };
    for t in it {
        if let Some(v) = t.strip_prefix('T') {
            secs = v.parse().ok()?;
        } else if let Some(v) = t.strip_prefix('K') {
            kib = v.parse().ok()?;
        } else if t == "P" {
            public_only = true;
        }
    }
    Some(NetRule { dest, secs, kib, public_only })
}

pub fn image_hash(data: &[u8]) -> String {
    let h = crate::upd::sha256(data);
    let mut s = String::new();
    for b in &h[..8] {
        s.push_str(&alloc::format!("{:02x}", b));
    }
    s
}

pub fn init() {
    if crate::store::state() != crate::store::State::Ready {
        return;
    }
    let Ok(Ok(bytes)) = crate::store::with(|s| s.read(DB)) else { return };
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let mut v = POLICY.lock();
    for line in text.lines() {
        let mut it = line.split(' ');
        if let (Some(n), Some(h), Some(r), Some(w)) = (it.next(), it.next(), it.next(), it.next()) {
            if crate::store::valid_name(n) && h.len() == 16 {
                let rest: Vec<&str> = it.collect();
                let net = if rest.is_empty() { None } else { parse_rule(rest.into_iter()) };
                v.push(Entry { name: String::from(n), hash: String::from(h), read: r == "1", write: w == "1", once: false, net });
            }
        }
    }
    log::info!("perm: {} stored permission decision(s)", v.len());
}

pub fn fmt_rule(r: &NetRule) -> String {
    let dest = match r.dest {
        Some(DNS_DEST) => String::from("dns"),
        Some(([0, 0, 0, 0], port)) => alloc::format!("listen:{}", port),
        Some((ip, port)) => alloc::format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port),
        None => String::from("any"),
    };
    alloc::format!("{} T{} K{}{}", dest, r.secs, r.kib, if r.public_only { " P" } else { "" })
}

fn save() {
    if crate::store::state() != crate::store::State::Ready {
        return;
    }
    let mut t = String::new();
    for e in POLICY.lock().iter().filter(|e| !e.once) {
        match &e.net {
            None => t.push_str(&alloc::format!("{} {} {} {}\n", e.name, e.hash, e.read as u8, e.write as u8)),
            Some(r) => t.push_str(&alloc::format!("{} {} {} 0 {}\n", e.name, e.hash, e.read as u8, fmt_rule(r))),
        }
    }
    let _ = crate::store::with(|s| s.write(DB, t.as_bytes()));
}

pub fn list() -> Vec<Entry> {
    POLICY.lock().clone()
}

/// Add or replace the file decision for (name, hash).
pub fn set(name: &str, hash: &str, read: bool, write: bool, once: bool) {
    {
        let mut v = POLICY.lock();
        v.retain(|e| !(e.name == name && e.hash == hash && e.once == once && e.net.is_none()));
        v.push(Entry { name: String::from(name), hash: String::from(hash), read, write, once, net: None });
    }
    if !once {
        save();
    }
}

/// Remove the file rule of `name`.
pub fn remove_files(name: &str) -> bool {
    remove_where(|e| e.name == name && e.net.is_none() && !e.once)
}

/// Remove the network rule of `name` for `dest` (`None` = the any-host rule).
pub fn remove_net(name: &str, dest: Dest) -> bool {
    remove_where(|e| e.name == name && e.net.map_or(false, |r| r.dest == dest))
}

/// Remove every stored decision (files and network) of `name`.
pub fn revoke(name: &str) -> bool {
    remove_where(|e| e.name == name)
}

fn remove_where(f: impl Fn(&Entry) -> bool) -> bool {
    let n = {
        let mut v = POLICY.lock();
        let before = v.len();
        v.retain(|e| !f(e));
        before - v.len()
    };
    if n > 0 {
        save();
    }
    n > 0
}

/// Decision for (name, hash): a one-shot entry wins and is consumed; then a stored one.
fn find(name: &str, hash: &str) -> Option<(bool, bool)> {
    let mut v = POLICY.lock();
    if let Some(i) = v.iter().position(|e| e.once && e.net.is_none() && e.name == name && e.hash == hash) {
        let e = v.remove(i);
        return Some((e.read, e.write));
    }
    v.iter().find(|e| !e.once && e.net.is_none() && e.name == name && e.hash == hash).map(|e| (e.read, e.write))
}

/// Prompt on the program's console. Returns the typed key (lower case), or `None` when there is no console.
fn ask_key(p: &Arc<Process>, msg: &str, valid: &[u8]) -> Option<u8> {
    if p.foreign.lock().console == 0 {
        return None;
    }
    let _ = crate::abi::console_write(p, "perm", msg.as_bytes());
    let mut b = [0u8; 1];
    loop {
        if crate::tty::read_input(&mut b) == 0 {
            crate::task::sleep_ms(2);
            continue;
        }
        let k = b[0].to_ascii_lowercase();
        if valid.contains(&k) {
            let _ = crate::abi::console_write(p, "perm", &[b[0], b'\r', b'\n']);
            return Some(k);
        }
    }
}

fn ask(p: &Arc<Process>, name: &str, hash: &str) -> (bool, bool) {
    let msg = alloc::format!(
        "\r\n[permission] {} wants to use files (read system + store files, write store files).\r\nAllow? [o]nce  [a]lways  [n]o  [d]eny always: ",
        name
    );
    let (grant, persist) = match ask_key(p, &msg, b"oyand") {
        Some(b'o') | Some(b'y') => (true, false),
        Some(b'a') => (true, true),
        Some(b'n') => (false, false),
        Some(b'd') => (false, true),
        _ => return (false, false),
    };
    if persist {
        set(name, hash, grant, grant, false);
    }
    log::info!("perm: {} -> files {} ({})", name, if grant { "ALLOWED" } else { "DENIED" }, if persist { "stored" } else { "this run" });
    (grant, grant)
}

/// Add or replace a network rule for (name, hash) with the same destination scope.
pub fn set_net(name: &str, hash: &str, rule: NetRule, allow: bool) {
    {
        let mut v = POLICY.lock();
        v.retain(|e| !(e.name == name && e.hash == hash && e.net.map_or(false, |r| r.dest == rule.dest)));
        v.push(Entry { name: String::from(name), hash: String::from(hash), read: allow, write: false, once: false, net: Some(rule) });
    }
    save();
}

/// Settle one network scope for a program. Order: this run's earlier answers, stored rules (exact scope first, then --
/// when `any_applies` -- the any-host rule), else ask the user. `Some(rule)` = allowed, with the limits to apply.
fn resolve_scope(p: &Arc<Process>, scope: ([u8; 4], u16), any_applies: bool, msg: &str, keys: &[u8], default_rule: NetRule, log_what: &str) -> Option<NetRule> {
    let (name, hash) = {
        let f = p.foreign.lock();
        if let Some((_, r)) = f.net_asked.iter().find(|(d, _)| *d == scope) {
            return *r;
        }
        (f.prog_name.clone(), f.prog_hash.clone())
    };
    {
        let v = POLICY.lock();
        let mine = v.iter().filter(|e| e.name == name && e.hash == hash && !e.once);
        let mut any: Option<&Entry> = None;
        for e in mine {
            match e.net {
                Some(r) if r.dest == Some(scope) => return if e.read { Some(r) } else { None },
                Some(r) if r.dest.is_none() && any_applies => any = Some(e),
                _ => {}
            }
        }
        if let Some(e) = any {
            return if e.read { e.net } else { None };
        }
    }
    let key = ask_key(p, msg, keys)?;
    let res = match key {
        b'o' | b'y' => Some(default_rule),
        b'a' => {
            set_net(&name, &hash, default_rule, true);
            Some(default_rule)
        }
        b'f' => {
            set_net(&name, &hash, NetRule::full(), true);
            Some(NetRule::full())
        }
        b'd' => {
            set_net(&name, &hash, default_rule, false);
            None
        }
        _ => None,
    };
    // a one-shot answer (and a plain "no") is remembered for this run only; stored answers live in the policy
    if matches!(key, b'o' | b'y' | b'n') {
        p.foreign.lock().net_asked.push((scope, res));
    }
    log::info!("perm: {} -> {} {} (key '{}')", name, log_what, if res.is_some() { "ALLOWED" } else { "DENIED" }, key as char);
    res
}

/// May this program talk to `ip:port` (TCP connect or UDP datagram)? Returns the rule to apply (limits + scope).
pub fn resolve_net(p: &Arc<Process>, ip: [u8; 4], port: u16, proto: &str) -> Option<NetRule> {
    let name = p.foreign.lock().prog_name.clone();
    let host = match crate::net::dns::cache_name_of(ip) {
        Some(h) => alloc::format!("{} ({}.{}.{}.{})", h, ip[0], ip[1], ip[2], ip[3]),
        None => alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
    };
    let msg = alloc::format!(
        "\r\n[permission] {} wants to connect to {}:{} ({}).\r\nAllow? [o]nce  [a]lways (this host)  [f]ull access (any host, no limits)  [n]o  [d]eny always: ",
        name, host, port, proto
    );
    resolve_scope(p, (ip, port), true, &msg, b"oyafnd", NetRule::this_host(ip, port), &alloc::format!("{} {}.{}.{}.{}:{}", proto, ip[0], ip[1], ip[2], ip[3], port))
}

/// May this program look up host names? (Full access includes it.)
pub fn resolve_dns(p: &Arc<Process>) -> bool {
    let name = p.foreign.lock().prog_name.clone();
    let msg = alloc::format!(
        "\r\n[permission] {} wants to look up host names (DNS, through the system resolver).\r\nAllow? [o]nce  [a]lways  [f]ull access (any host, no limits)  [n]o  [d]eny always: ",
        name
    );
    resolve_scope(p, DNS_DEST, true, &msg, b"oyafnd", NetRule::dns(), "DNS lookups").is_some()
}

/// May this program accept incoming connections / datagrams on local `port`? Never implied by full access.
pub fn resolve_listen(p: &Arc<Process>, port: u16) -> Option<NetRule> {
    let name = p.foreign.lock().prog_name.clone();
    let msg = alloc::format!(
        "\r\n[permission] {} wants to ACCEPT INCOMING connections on port {} (act as a server).\r\nAllow? [o]nce  [a]lways  [n]o  [d]eny always: ",
        name, port
    );
    resolve_scope(p, ([0; 4], port), false, &msg, b"oyand", NetRule::listen(port), &alloc::format!("listen on port {}", port))
}

/// Called before a foreign program's first file access: settle its file capabilities.
pub fn resolve(p: &Arc<Process>) {
    let (pending, name, hash) = {
        let f = p.foreign.lock();
        (f.fs_pending, f.prog_name.clone(), f.prog_hash.clone())
    };
    if !pending {
        return;
    }
    let (r, w) = find(&name, &hash).unwrap_or_else(|| ask(p, &name, &hash));
    let mut f = p.foreign.lock();
    f.fs_pending = false;
    if !r {
        f.fs_dir = false;
        f.fs_store_read = false;
    }
    if !w {
        f.fs_store_write = false;
    }
}
