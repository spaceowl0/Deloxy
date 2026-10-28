//! Read-only initramfs: a USTAR archive handed over by Limine as a boot module.
//!
//! There is no global path namespace. A process can only open files through a `Dir` capability, and a
//! file is reachable only as a `File` capability (READ, EXEC). The archive is parsed once, strictly:
//! every size/offset is checked, names must be flat (no '/', no ".."), duplicates are rejected.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Once;

pub mod rootfs;
pub mod tmpfs;

pub struct RamFile {
    pub name: String,
    pub data: &'static [u8],
}

pub struct RamDir {
    pub files: Vec<Arc<RamFile>>,
}

static ROOT: Once<Arc<RamDir>> = Once::new();

#[derive(Debug, PartialEq, Eq)]
pub enum TarError {
    BadChecksum,
    Truncated,
    BadName,
    Duplicate,
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
    if seen { Some(v) } else { Some(0) }
}

pub const MAX_FILES: usize = 128;

/// Parse a USTAR archive that lives for `'static`. Only regular files are kept.
pub fn parse_tar(tar: &'static [u8]) -> Result<RamDir, TarError> {
    let files = scan(tar)?.into_iter().map(|(name, r)| Arc::new(RamFile { name, data: &tar[r] })).collect();
    Ok(RamDir { files })
}

/// Validate an archive and return `(name, data range)` for every regular file (no lifetime requirement).
pub fn scan(tar: &[u8]) -> Result<Vec<(String, core::ops::Range<usize>)>, TarError> {
    let mut files: Vec<(String, core::ops::Range<usize>)> = Vec::new();
    let mut off = 0usize;
    loop {
        let Some(end) = off.checked_add(512) else { return Err(TarError::Truncated) };
        if end > tar.len() {
            // Archives may simply end without the two zero blocks.
            if off == tar.len() {
                break;
            }
            return Err(TarError::Truncated);
        }
        let h = &tar[off..end];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let stored = octal(&h[148..156]).ok_or(TarError::BadChecksum)?;
        let sum: u64 = h.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { 0x20 } else { b as u64 }).sum();
        if sum != stored {
            return Err(TarError::BadChecksum);
        }
        let size = octal(&h[124..136]).ok_or(TarError::BadSize)?;
        let typ = h[156];
        let nlen = h[..100].iter().position(|&b| b == 0).unwrap_or(100);
        let mut name = &h[..nlen];
        if name.starts_with(b"./") {
            name = &name[2..];
        }
        let data_start = end;
        let data_end = data_start.checked_add(usize::try_from(size).map_err(|_| TarError::BadSize)?).ok_or(TarError::BadSize)?;
        if data_end > tar.len() {
            return Err(TarError::Truncated);
        }
        if typ == b'0' || typ == 0 {
            let ok = !name.is_empty() && name != b"." && name != b".." && name.iter().all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b'+'));
            if !ok {
                return Err(TarError::BadName);
            }
            let name = core::str::from_utf8(name).map_err(|_| TarError::BadName)?;
            if files.iter().any(|f| f.0 == name) {
                return Err(TarError::Duplicate);
            }
            if files.len() >= MAX_FILES {
                return Err(TarError::TooMany);
            }
            files.push((String::from(name), data_start..data_end));
        }
        let padded = (data_end - data_start).checked_add(511).ok_or(TarError::BadSize)? & !511;
        off = data_start.checked_add(padded).ok_or(TarError::BadSize)?;
    }
    Ok(files)
}

/// Install the root directory from the boot module (called once from `kmain`).
pub fn install(tar: &'static [u8]) -> Result<usize, TarError> {
    let d = parse_tar(tar)?;
    let n = d.files.len();
    ROOT.call_once(|| Arc::new(d));
    Ok(n)
}

/// The root directory object. Only trusted kernel code (init) may hand it out as a capability.
pub fn root() -> Option<Arc<RamDir>> {
    ROOT.get().cloned()
}

impl RamDir {
    pub fn lookup(&self, name: &str) -> Option<Arc<RamFile>> {
        self.files.iter().find(|f| f.name == name).cloned()
    }
}
