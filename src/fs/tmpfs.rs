//! Volatile `/tmp`: an in-memory tree of files and directories, bounded (files, bytes, depth, name length).
//! Gone at reboot. Access is gated by the same file permissions as the persistent store (see `abi::vfs`).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use crate::sync::IrqMutex;

pub const MAX_FILES: usize = 1024;
pub const MAX_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_NAME: usize = 255;

struct Tmp {
    files: BTreeMap<String, Vec<u8>>,
    dirs: BTreeSet<String>,
    bytes: usize,
}

static TMP: IrqMutex<Tmp> = IrqMutex::new(Tmp { files: BTreeMap::new(), dirs: BTreeSet::new(), bytes: 0 });

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TmpErr {
    NotFound,
    Exists,
    NoSpace,
    NotDir,
    IsDir,
    NotEmpty,
    BadName,
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(p, _)| p)
}

fn valid(path: &str) -> bool {
    path.len() <= 4096 && path.split('/').all(|c| !c.is_empty() && c.len() <= MAX_NAME && c != "." && c != ".." && !c.bytes().any(|b| b == 0))
}

fn dir_exists(t: &Tmp, d: &str) -> bool {
    d == "tmp" || t.dirs.contains(d)
}

pub fn is_dir(path: &str) -> bool {
    dir_exists(&TMP.lock(), path)
}
pub fn exists(path: &str) -> bool {
    let t = TMP.lock();
    dir_exists(&t, path) || t.files.contains_key(path)
}
pub fn read(path: &str) -> Option<Vec<u8>> {
    TMP.lock().files.get(path).cloned()
}

/// Create or replace a file (the parent directory must exist).
pub fn write(path: &str, data: &[u8]) -> Result<(), TmpErr> {
    if !valid(path) || !path.starts_with("tmp/") {
        return Err(TmpErr::BadName);
    }
    let mut t = TMP.lock();
    if t.dirs.contains(path) {
        return Err(TmpErr::IsDir);
    }
    if !dir_exists(&t, parent(path)) {
        return Err(TmpErr::NotFound);
    }
    let old = t.files.get(path).map_or(0, |v| v.len());
    if t.bytes - old + data.len() > MAX_BYTES || (old == 0 && !t.files.contains_key(path) && t.files.len() >= MAX_FILES) {
        return Err(TmpErr::NoSpace);
    }
    t.bytes = t.bytes - old + data.len();
    t.files.insert(String::from(path), data.to_vec());
    Ok(())
}

/// Create an empty file if it does not exist (open(O_CREAT)).
pub fn create(path: &str) -> Result<(), TmpErr> {
    if exists(path) && !is_dir(path) {
        return Ok(());
    }
    write(path, &[])
}

pub fn remove(path: &str) -> Result<(), TmpErr> {
    let mut t = TMP.lock();
    match t.files.remove(path) {
        Some(v) => {
            t.bytes -= v.len();
            Ok(())
        }
        None if dir_exists(&t, path) => Err(TmpErr::IsDir),
        None => Err(TmpErr::NotFound),
    }
}

pub fn mkdir(path: &str) -> Result<(), TmpErr> {
    if !valid(path) || !path.starts_with("tmp/") {
        return Err(TmpErr::BadName);
    }
    let mut t = TMP.lock();
    if dir_exists(&t, path) || t.files.contains_key(path) {
        return Err(TmpErr::Exists);
    }
    if !dir_exists(&t, parent(path)) {
        return Err(TmpErr::NotFound);
    }
    if t.dirs.len() >= MAX_FILES {
        return Err(TmpErr::NoSpace);
    }
    t.dirs.insert(String::from(path));
    Ok(())
}

pub fn rmdir(path: &str) -> Result<(), TmpErr> {
    let mut t = TMP.lock();
    if !t.dirs.contains(path) {
        return Err(if t.files.contains_key(path) { TmpErr::NotDir } else { TmpErr::NotFound });
    }
    let prefix = alloc::format!("{}/", path);
    if t.files.keys().any(|k| k.starts_with(&prefix)) || t.dirs.iter().any(|d| d.starts_with(&prefix)) {
        return Err(TmpErr::NotEmpty);
    }
    t.dirs.remove(path);
    Ok(())
}

/// rename within /tmp (files and empty-or-not directories: children move with the directory).
pub fn rename(from: &str, to: &str) -> Result<(), TmpErr> {
    if !valid(to) || !to.starts_with("tmp/") {
        return Err(TmpErr::BadName);
    }
    let mut t = TMP.lock();
    if !dir_exists(&t, parent(to)) {
        return Err(TmpErr::NotFound);
    }
    if let Some(v) = t.files.remove(from) {
        if let Some(old) = t.files.insert(String::from(to), v) {
            t.bytes -= old.len();
        }
        return Ok(());
    }
    if t.dirs.contains(from) {
        if to.starts_with(&alloc::format!("{}/", from)) {
            return Err(TmpErr::BadName);
        }
        let prefix = alloc::format!("{}/", from);
        let moved_files: Vec<String> = t.files.keys().filter(|k| k.starts_with(&prefix)).cloned().collect();
        let moved_dirs: Vec<String> = t.dirs.iter().filter(|d| d.starts_with(&prefix)).cloned().collect();
        t.dirs.remove(from);
        t.dirs.insert(String::from(to));
        for d in moved_dirs {
            t.dirs.remove(&d);
            t.dirs.insert(alloc::format!("{}/{}", to, &d[prefix.len()..]));
        }
        for f in moved_files {
            let v = t.files.remove(&f).unwrap();
            t.files.insert(alloc::format!("{}/{}", to, &f[prefix.len()..]), v);
        }
        return Ok(());
    }
    Err(TmpErr::NotFound)
}

/// Children of a directory: (name, is_dir).
pub fn list(dir: &str) -> Vec<(String, bool)> {
    let t = TMP.lock();
    let prefix = alloc::format!("{}/", dir);
    let mut out: Vec<(String, bool)> = Vec::new();
    for k in t.files.keys() {
        if let Some(rel) = k.strip_prefix(&prefix) {
            if !rel.contains('/') {
                out.push((String::from(rel), false));
            }
        }
    }
    for d in t.dirs.iter() {
        if let Some(rel) = d.strip_prefix(&prefix) {
            if !rel.contains('/') {
                out.push((String::from(rel), true));
            }
        }
    }
    out
}

pub fn used_bytes() -> usize {
    TMP.lock().bytes
}
