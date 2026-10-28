//! `deloxy-upd`: signed, pull-only updater.
//!
//! * Pull-only and user-initiated: nothing here runs on a timer, there is no background polling and no
//!   telemetry. A caller must present a live `NetGrant` for exactly one server; without it the firewall
//!   and the NIC stay shut.
//! * `manifest.json` is authenticated (Ed25519, key compiled into the kernel) BEFORE it is parsed.
//! * Rollback protection: the offered version must be strictly greater than the running kernel version and
//!   than the highest version already staged in this boot.
//! * Artifacts are fetched only after the manifest verifies and are accepted only if size and SHA-256 match.
//! * Staging goes to RAM and, when a `store` disk is mounted, is persisted as `upd.*` files (artifacts, a
//!   `upd.pending` record written last as the commit marker, and `upd.floor`, the persistent anti-rollback
//!   floor). At boot `recover()` re-verifies every persisted artifact against its SHA-256. ACTIVATING a staged
//!   update (booting the new kernel) is NOT implemented: the kernel is loaded by Limine from the boot medium
//!   (an ISO in the alpha), which Deloxy cannot rewrite.

pub mod keys;
pub mod manifest;
#[cfg(feature = "selftest")]
pub mod testvec;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use log::info;
use sha2::{Digest, Sha256};

use crate::net::{self, NetErr, NetGrant, TcpState};
use crate::sync::IrqMutex;
use manifest::{Manifest, Version};

/// Version of the running kernel (keep in sync with the boot banner).
pub const CURRENT_VERSION: Version = [0, 1, 0];

#[derive(Debug, PartialEq, Eq)]
pub enum UpdError {
    Net(NetErr),
    Http(u16),
    BadResponse(&'static str),
    TooLarge,
    BadPath,
    SigFormat(&'static str),
    UnknownKey,
    BadSignature,
    ManifestFormat(&'static str),
    NotNewer { offered: Version, current: Version },
    BelowMinVersion { required: Version, current: Version },
    ArtifactSize(String),
    ArtifactHash(String),
}

#[derive(Clone, Copy)]
pub struct Server {
    pub ip: [u8; 4],
    pub port: u16,
}

pub struct Staged {
    pub version: Version,
    pub files: Vec<(String, Vec<u8>)>,
}

static STAGED: IrqMutex<Option<Staged>> = IrqMutex::new(None);
static HIGHEST_STAGED: IrqMutex<Version> = IrqMutex::new([0, 0, 0]);

pub fn staged_version() -> Option<Version> {
    STAGED.lock().as_ref().map(|s| s.version)
}
pub fn staged_files() -> usize {
    STAGED.lock().as_ref().map_or(0, |s| s.files.len())
}
/// Forget everything staged and the in-RAM replay floor (tests only).
pub fn reset_for_test() {
    *STAGED.lock() = None;
    *HIGHEST_STAGED.lock() = [0, 0, 0];
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

// ----------------------------------------------------------- http ---

const HTTP_TIMEOUT_MS: u64 = 15_000;

fn http_get(g: &Arc<NetGrant>, s: Server, path: &str, max_body: usize) -> Result<Vec<u8>, UpdError> {
    if !manifest::safe_path(path) {
        return Err(UpdError::BadPath);
    }
    let t0 = crate::time::uptime_ms();
    let expired = || crate::time::uptime_ms() - t0 > HTTP_TIMEOUT_MS;
    let id = loop {
        match net::tcp_connect(g, s.ip, s.port) {
            Ok(id) => break id,
            Err(NetErr::NotReady) if !expired() => crate::task::sleep_ms(5),
            Err(e) => return Err(UpdError::Net(e)),
        }
    };
    let res = http_exchange(id, s, path, max_body, &expired);
    net::tcp_close(id);
    res
}

fn http_exchange(id: u32, s: Server, path: &str, max_body: usize, expired: &dyn Fn() -> bool) -> Result<Vec<u8>, UpdError> {
    loop {
        match net::tcp_state(id).map_err(UpdError::Net)? {
            TcpState::Established => break,
            TcpState::Closed => return Err(UpdError::Net(NetErr::Closed)),
            TcpState::Connecting if expired() => return Err(UpdError::Net(NetErr::Timeout)),
            TcpState::Connecting => crate::task::sleep_ms(2),
        }
    }
    let req = format!("GET {} HTTP/1.0\r\nHost: {}.{}.{}.{}\r\nConnection: close\r\nUser-Agent: deloxy-upd/0.1\r\n\r\n", path, s.ip[0], s.ip[1], s.ip[2], s.ip[3]);
    let mut sent = 0;
    while sent < req.len() {
        match net::tcp_send(id, &req.as_bytes()[sent..]) {
            Ok(n) => sent += n,
            Err(NetErr::WouldBlock) if !expired() => crate::task::sleep_ms(1),
            Err(e) => return Err(UpdError::Net(e)),
        }
    }
    let limit = max_body.checked_add(8192).ok_or(UpdError::TooLarge)?;
    let mut resp: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match net::tcp_recv(id, &mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if resp.len() + n > limit {
                    return Err(UpdError::TooLarge);
                }
                resp.extend_from_slice(&chunk[..n]);
            }
            Err(NetErr::WouldBlock) => {
                if expired() {
                    return Err(UpdError::Net(NetErr::Timeout));
                }
                crate::task::sleep_ms(1);
            }
            Err(e) => return Err(UpdError::Net(e)),
        }
    }
    parse_http(&resp, max_body)
}

fn parse_http(resp: &[u8], max_body: usize) -> Result<Vec<u8>, UpdError> {
    let end = resp.windows(4).position(|w| w == b"\r\n\r\n").ok_or(UpdError::BadResponse("no header terminator"))?;
    let head = core::str::from_utf8(&resp[..end]).map_err(|_| UpdError::BadResponse("non-utf8 headers"))?;
    let mut lines = head.split("\r\n");
    let status = lines.next().ok_or(UpdError::BadResponse("empty response"))?;
    let mut parts = status.split(' ');
    if !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(UpdError::BadResponse("not HTTP/1.x"));
    }
    let code: u16 = parts.next().and_then(|c| c.parse().ok()).ok_or(UpdError::BadResponse("bad status"))?;
    if code != 200 {
        return Err(UpdError::Http(code));
    }
    let body = &resp[end + 4..];
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                let n: usize = v.trim().parse().map_err(|_| UpdError::BadResponse("bad content-length"))?;
                if n != body.len() {
                    return Err(UpdError::BadResponse("body does not match content-length (truncated?)"));
                }
            }
        }
    }
    if body.len() > max_body {
        return Err(UpdError::TooLarge);
    }
    Ok(body.to_vec())
}

// ------------------------------------------------------ verification ---

/// Verify `manifest.sig` over the raw manifest bytes. Distinct errors for a malformed signature file,
/// an unknown signing key, and a signature that does not verify (tampered data / forged signature).
pub fn verify_manifest(manifest_bytes: &[u8], sig_file: &[u8]) -> Result<(), UpdError> {
    let text = core::str::from_utf8(sig_file).map_err(|_| UpdError::SigFormat("not utf-8"))?;
    if sig_file.len() > 512 {
        return Err(UpdError::SigFormat("too large"));
    }
    let mut it = text.split('\n');
    if it.next() != Some("deloxy-sig-v1") {
        return Err(UpdError::SigFormat("bad magic"));
    }
    let kid = it.next().and_then(|l| l.strip_prefix("key_id=")).ok_or(UpdError::SigFormat("missing key_id"))?;
    let sig = it.next().and_then(|l| l.strip_prefix("sig=")).ok_or(UpdError::SigFormat("missing sig"))?;
    if it.next() != Some("") || it.next().is_some() {
        return Err(UpdError::SigFormat("trailing data"));
    }
    if kid.len() != 16 || sig.len() != 128 {
        return Err(UpdError::SigFormat("bad field length"));
    }
    let mut key_id = [0u8; 8];
    for i in 0..8 {
        key_id[i] = (manifest::nib(kid.as_bytes()[2 * i]).map_err(UpdError::SigFormat)? << 4) | manifest::nib(kid.as_bytes()[2 * i + 1]).map_err(UpdError::SigFormat)?;
    }
    let mut sig_bytes = [0u8; 64];
    for i in 0..64 {
        sig_bytes[i] = (manifest::nib(sig.as_bytes()[2 * i]).map_err(UpdError::SigFormat)? << 4) | manifest::nib(sig.as_bytes()[2 * i + 1]).map_err(UpdError::SigFormat)?;
    }
    let key = keys::TRUSTED.iter().find(|k| k.key_id == key_id).ok_or(UpdError::UnknownKey)?;
    let pk = ed25519_compact::PublicKey::from_slice(&key.public).map_err(|_| UpdError::BadSignature)?;
    let sg = ed25519_compact::Signature::from_slice(&sig_bytes).map_err(|_| UpdError::BadSignature)?;
    pk.verify(manifest_bytes, &sg).map_err(|_| UpdError::BadSignature)
}

fn newer(a: Version, b: Version) -> bool {
    a > b // lexicographic on [major, minor, patch]
}

/// Policy applied to an AUTHENTICATED manifest.
pub fn check_policy(m: &Manifest, running: Version, highest_staged: Version) -> Result<(), UpdError> {
    let floor = if newer(highest_staged, running) { highest_staged } else { running };
    if !newer(m.version, floor) {
        return Err(UpdError::NotNewer { offered: m.version, current: floor });
    }
    if newer(m.min_version, running) {
        return Err(UpdError::BelowMinVersion { required: m.min_version, current: running });
    }
    Ok(())
}

pub struct UpdateInfo {
    pub manifest: Manifest,
}

/// `upd check`: fetch and authenticate the manifest under `base` (e.g. "/ok") and apply the rollback policy.
pub fn check(g: &Arc<NetGrant>, s: Server, base: &str) -> Result<UpdateInfo, UpdError> {
    let sig = http_get(g, s, &format!("{}/manifest.sig", base), 512)?;
    let body = http_get(g, s, &format!("{}/manifest.json", base), manifest::MAX_MANIFEST)?;
    verify_manifest(&body, &sig)?;
    let m = manifest::parse(&body).map_err(UpdError::ManifestFormat)?;
    check_policy(&m, CURRENT_VERSION, *HIGHEST_STAGED.lock())?;
    info!("upd: update available: {}.{}.{} ({} artifact(s))", m.version[0], m.version[1], m.version[2], m.artifacts.len());
    Ok(UpdateInfo { manifest: m })
}

/// Download every artifact of an authenticated manifest, verify size + SHA-256 and stage them in RAM.
pub fn fetch_and_stage(g: &Arc<NetGrant>, s: Server, base: &str, info: &UpdateInfo) -> Result<(), UpdError> {
    let mut files = Vec::new();
    for a in &info.manifest.artifacts {
        let data = http_get(g, s, &format!("{}{}", base, a.path), a.size as usize)?;
        if data.len() as u64 != a.size {
            return Err(UpdError::ArtifactSize(a.name.clone()));
        }
        if sha256(&data) != a.sha256 {
            return Err(UpdError::ArtifactHash(a.name.clone()));
        }
        files.push((a.name.clone(), data));
    }
    let v = info.manifest.version;
    *STAGED.lock() = Some(Staged { version: v, files });
    *HIGHEST_STAGED.lock() = v;
    info!("upd: staged {}.{}.{} in RAM", v[0], v[1], v[2]);
    Ok(())
}

// ------------------------------------------------------------ persistence ---

fn vstr(v: Version) -> String {
    format!("{}.{}.{}", v[0], v[1], v[2])
}

fn parse_version(s: &str) -> Option<Version> {
    let mut it = s.trim().split('.');
    let v = [it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?.parse().ok()?];
    if it.next().is_some() { None } else { Some(v) }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

#[derive(Debug, PartialEq, Eq)]
pub enum PersistOutcome {
    Saved(usize),
    NoStore,
    Failed(crate::store::StoreErr),
}

/// Write the staged update to the store: old `upd.*` files go first, then artifacts, then the pending record
/// (commit marker), then the floor. Each store write is atomic, so a crash leaves either no `upd.pending`
/// (nothing is considered staged) or a complete, hash-checkable set.
pub fn persist_staged() -> PersistOutcome {
    use crate::store::{self, StoreErr};
    if store::state() != store::State::Ready {
        return PersistOutcome::NoStore;
    }
    let guard = STAGED.lock();
    let Some(st) = guard.as_ref() else { return PersistOutcome::NoStore };
    let tag = vstr(st.version);
    let r: Result<usize, StoreErr> = store::with(|s| {
        let old: Vec<String> = s.list().iter().filter(|e| e.name.starts_with("upd.") && e.name != "upd.floor").map(|e| e.name.clone()).collect();
        for n in old {
            s.delete(&n)?;
        }
        let mut rec = format!("version {}\n", tag);
        for (name, data) in &st.files {
            let fname = format!("upd.{}.{}", tag, name);
            s.write(&fname, data)?;
            rec.push_str(&format!("file {} {} {}\n", fname, data.len(), hex(&sha256(data))));
        }
        s.write("upd.pending", rec.as_bytes())?;
        s.write("upd.floor", tag.as_bytes())?;
        Ok(st.files.len())
    })
    .and_then(|x| x);
    match r {
        Ok(n) => {
            info!("upd: persisted {} artifact(s) of {} to the store", n, tag);
            PersistOutcome::Saved(n)
        }
        Err(e) => PersistOutcome::Failed(e),
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RecoverReport {
    pub floor: Option<Version>,
    /// `(version, verified_ok)` of the pending update record, if one exists.
    pub pending: Option<(String, bool)>,
}

pub fn highest_staged() -> Version {
    *HIGHEST_STAGED.lock()
}

/// Test helper: pretend `files` were downloaded and verified for `version`.
#[cfg(feature = "selftest")]
pub fn stage_for_test(version: Version, files: Vec<(String, Vec<u8>)>) {
    *STAGED.lock() = Some(Staged { version, files });
    *HIGHEST_STAGED.lock() = version;
}

/// Boot-time recovery: load the persistent rollback floor and re-verify a pending update on disk.
pub fn recover() {
    let _ = recover_report();
}

pub fn recover_report() -> RecoverReport {
    use crate::store;
    let mut rep = RecoverReport::default();
    if store::state() != store::State::Ready {
        return rep;
    }
    let floor = store::with(|s| s.read("upd.floor")).ok().and_then(|r| r.ok()).and_then(|b| core::str::from_utf8(&b).ok().and_then(parse_version));
    if let Some(f) = floor {
        rep.floor = Some(f);
        *HIGHEST_STAGED.lock() = f;
        info!("upd: persistent rollback floor {}", vstr(f));
    }
    let pending = store::with(|s| s.read("upd.pending")).ok().and_then(|r| r.ok());
    let Some(rec) = pending else { return rep };
    let text = String::from_utf8_lossy(&rec).into_owned();
    let mut ok = true;
    let mut n = 0;
    let mut ver = String::new();
    for line in text.lines() {
        let mut p = line.split(' ');
        match p.next() {
            Some("version") => ver = String::from(p.next().unwrap_or("?")),
            Some("file") => {
                let (Some(name), Some(size), Some(h)) = (p.next(), p.next(), p.next()) else { ok = false; continue };
                let good = store::with(|s| s.read(name)).ok().and_then(|r| r.ok()).map_or(false, |d| format!("{}", d.len()) == size && hex(&sha256(&d)) == h);
                ok &= good;
                n += 1;
            }
            _ => ok = false,
        }
    }
    rep.pending = Some((ver.clone(), ok && n > 0));
    if ok && n > 0 {
        info!("upd: pending update {} verified on disk ({} artifact(s)); activation needs a writable boot medium (not implemented)", ver, n);
    } else {
        log::warn!("upd: pending update record is damaged or incomplete; ignoring it");
    }
    rep
}
