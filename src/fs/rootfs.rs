//! Read-only hierarchical root filesystem: a USTAR archive handed over by Limine as the *second* boot module.
//!
//! Unlike the flat initramfs (`fs`), this tree has real directories and symlinks and holds data trees (a Python
//! stdlib, `/usr/share/misc/magic.mgc`, ...). It is parsed once, strictly (checksums, bounds, names validated:
//! no empty / `.` / `..` components, no NUL), file data stays in the module (`&'static [u8]`, never copied).
//! Missing parent directories are created implicitly. `/bin`, `/sbin`, `/lib`, `/lib64` are aliases of `/usr/...`
//! (usr-merge) unless the archive provides them itself.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Once;

#[derive(Clone)]
pub enum Node {
    File { data: &'static [u8] },
    Dir,
    Link(String),
}

static TREE: Once<BTreeMap<String, Node>> = Once::new();

pub const MAX_NODES: usize = 40_000;

#[derive(Debug, PartialEq, Eq)]
pub enum RootfsError {
    BadChecksum,
    Truncated,
    BadName,
    BadSize,
    TooMany,
}

fn octal(field: &[u8]) -> Option<u64> {
    let mut v: u64 = 0;
    let mut seen = false;
    for &c in field {
        match c {
            b'0'..=b'7' => {
                v = v.checked_mul(8)?.checked_add((c - b'0') as u64)?;
                seen = true;
            }
            0 | b' ' => {
                if seen {
                    break;
                }
            }
            _ => return None,
        }
    }
    Some(v)
}

fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// Canonical form of an archive path: components joined by '/', no leading slash. None if any component is bad.
fn clean_name(raw: &[u8]) -> Option<String> {
    let s = core::str::from_utf8(raw).ok()?;
    let mut parts: Vec<&str> = Vec::new();
    for c in s.split('/') {
        match c {
            "" | "." => continue,
            ".." => return None,
            _ if c.bytes().any(|b| b < 0x20 || b == 0x7f) => return None,
            _ => parts.push(c),
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("/"))
}

fn add_parents(tree: &mut BTreeMap<String, Node>, path: &str) {
    let mut end = 0;
    while let Some(i) = path[end..].find('/') {
        end += i;
        tree.entry(String::from(&path[..end])).or_insert(Node::Dir);
        end += 1;
    }
}

pub fn parse(tar: &'static [u8]) -> Result<BTreeMap<String, Node>, RootfsError> {
    let mut tree: BTreeMap<String, Node> = BTreeMap::new();
    let mut off = 0usize;
    loop {
        let Some(end) = off.checked_add(512) else { return Err(RootfsError::Truncated) };
        if end > tar.len() {
            if off == tar.len() {
                break;
            }
            return Err(RootfsError::Truncated);
        }
        let h = &tar[off..end];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let stored = octal(&h[148..156]).ok_or(RootfsError::BadChecksum)?;
        let sum: u64 = h.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { 0x20 } else { b as u64 }).sum();
        if sum != stored {
            return Err(RootfsError::BadChecksum);
        }
        let size = octal(&h[124..136]).ok_or(RootfsError::BadSize)?;
        let typ = h[156];
        let data_start = end;
        let data_end = data_start.checked_add(usize::try_from(size).map_err(|_| RootfsError::BadSize)?).ok_or(RootfsError::BadSize)?;
        if data_end > tar.len() {
            return Err(RootfsError::Truncated);
        }
        // name = prefix + '/' + name (USTAR)
        let mut full: Vec<u8> = Vec::new();
        if &h[257..262] == b"ustar" && h[345] != 0 {
            full.extend_from_slice(cstr(&h[345..500]));
            full.push(b'/');
        }
        full.extend_from_slice(cstr(&h[..100]));
        match typ {
            b'0' | 0 | b'5' | b'2' => {
                let Some(name) = clean_name(&full) else { return Err(RootfsError::BadName) };
                if tree.len() >= MAX_NODES {
                    return Err(RootfsError::TooMany);
                }
                add_parents(&mut tree, &name);
                let node = match typ {
                    b'5' => Node::Dir,
                    b'2' => {
                        let t = cstr(&h[157..257]);
                        if t.is_empty() || core::str::from_utf8(t).is_err() {
                            return Err(RootfsError::BadName);
                        }
                        Node::Link(String::from(core::str::from_utf8(t).unwrap()))
                    }
                    _ => Node::File { data: &tar[data_start..data_end] },
                };
                // a directory entry never replaces something that already holds children/data
                if !(matches!(node, Node::Dir) && tree.contains_key(&name)) {
                    tree.insert(name, node);
                }
            }
            _ => {} // pax headers, hard links, devices...: ignored
        }
        let padded = (data_end - data_start).checked_add(511).ok_or(RootfsError::BadSize)? & !511;
        off = data_start.checked_add(padded).ok_or(RootfsError::BadSize)?;
    }
    Ok(tree)
}

pub fn install(tar: &'static [u8]) -> Result<usize, RootfsError> {
    let t = parse(tar)?;
    let n = t.len();
    TREE.call_once(|| t);
    Ok(n)
}

pub fn installed() -> bool {
    TREE.get().is_some()
}

/// Collapse `.`/`..`/empty components of an absolute-or-relative path (relative to the root); `..` above the root stays at the root.
pub fn canon(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(c),
        }
    }
    parts.join("/")
}

/// Resolve `path` (canonical, no leading slash; "" = the root) following symlinks. Returns the canonical resolved path and node.
pub fn lookup(path: &str) -> Option<(String, Node)> {
    let tree = TREE.get()?;
    let mut cur: Vec<String> = Vec::new();
    let mut rest: Vec<String> = path.split('/').filter(|c| !c.is_empty()).map(String::from).collect();
    rest.reverse();
    let mut hops = 0;
    // usr-merge aliases for the first component
    let mut first = true;
    while let Some(c) = rest.pop() {
        if c == "." {
            continue;
        }
        if c == ".." {
            cur.pop();
            continue;
        }
        let mut name = c;
        if first && cur.is_empty() && matches!(name.as_str(), "bin" | "sbin" | "lib" | "lib64") && !tree.contains_key(name.as_str()) {
            cur.push(String::from("usr"));
        }
        first = false;
        cur.push(name.clone());
        let joined = cur.join("/");
        match tree.get(&joined) {
            None => return None,
            Some(Node::Link(t)) => {
                hops += 1;
                if hops > 16 {
                    return None;
                }
                cur.pop();
                if t.starts_with('/') {
                    cur.clear();
                    first = true;
                }
                // splice the link target in front of the remaining components
                let tparts: Vec<String> = t.split('/').filter(|c| !c.is_empty()).map(String::from).collect();
                for p in tparts.into_iter().rev() {
                    rest.push(p);
                }
                name.clear();
            }
            Some(_) => {}
        }
    }
    let joined = cur.join("/");
    if joined.is_empty() {
        return Some((joined, Node::Dir));
    }
    tree.get(&joined).cloned().map(|n| (joined, n))
}

/// Children of a directory: (name, is_dir). `dir` is canonical and already symlink-resolved.
pub fn list(dir: &str) -> Vec<(String, bool)> {
    let Some(tree) = TREE.get() else { return Vec::new() };
    let prefix = if dir.is_empty() { String::new() } else { alloc::format!("{}/", dir) };
    let mut out: Vec<(String, bool)> = Vec::new();
    for (k, v) in tree.range(prefix.clone()..) {
        if !k.starts_with(&prefix) {
            break;
        }
        let rel = &k[prefix.len()..];
        if rel.is_empty() || rel.contains('/') {
            continue;
        }
        out.push((String::from(rel), matches!(v, Node::Dir)));
    }
    out
}

/// Target of a symlink (for readlink), without following it.
pub fn readlink(path: &str) -> Option<String> {
    let tree = TREE.get()?;
    match tree.get(path)? {
        Node::Link(t) => Some(t.clone()),
        _ => None,
    }
}
