//! PE32+ (x86-64) console/GUI executable parser. Imports are resolved against the
//! built-in Win32 shim table at load time: an unknown import is a load error naming
//! `dll!function` (nothing half-runs). Relocations (DIR64) are applied only when the
//! preferred ImageBase can't be used.

use alloc::string::String;
use alloc::vec::Vec;

use super::{ExecError, Patch, Plan, Segment, PERM_R, PERM_W, PERM_X};
use crate::abi::{nt, AbiKind};
use crate::mm::layout::{is_user_range, PAGE_SIZE};
use crate::task::USER_MMAP_BASE;

const FALLBACK_BASE: u64 = 0x0000_0001_4000_0000;

fn rd<const N: usize>(d: &[u8], off: usize) -> Result<[u8; N], ExecError> {
    let end = off.checked_add(N).ok_or(ExecError::Truncated)?;
    d.get(off..end).ok_or(ExecError::Truncated)?.try_into().map_err(|_| ExecError::Truncated)
}
fn u16_at(d: &[u8], o: usize) -> Result<u16, ExecError> {
    Ok(u16::from_le_bytes(rd(d, o)?))
}
fn u32_at(d: &[u8], o: usize) -> Result<u32, ExecError> {
    Ok(u32::from_le_bytes(rd(d, o)?))
}
fn u64_at(d: &[u8], o: usize) -> Result<u64, ExecError> {
    Ok(u64::from_le_bytes(rd(d, o)?))
}

struct Section {
    va: u32,
    vsize: u32,
    raw_off: u32,
    raw_size: u32,
    chars: u32,
}

/// Translate an RVA to a file offset (headers or section raw data), requiring `len` readable bytes.
fn rva_to_off(secs: &[Section], headers: u32, rva: u32, len: usize) -> Result<usize, ExecError> {
    // callers pass `rva` already computed with checked arithmetic (see `rva_add`)
    if rva < headers && (rva as usize).checked_add(len).map_or(false, |e| e <= headers as usize) {
        return Ok(rva as usize);
    }
    for s in secs {
        if rva >= s.va {
            let rel = (rva - s.va) as u64;
            if rel + len as u64 <= s.raw_size as u64 {
                return Ok(s.raw_off as usize + rel as usize);
            }
        }
    }
    Err(ExecError::Format("RVA outside file-backed data"))
}

/// Checked RVA arithmetic (RVAs come straight from the file).
fn rva_add(a: u32, b: u32) -> Result<u32, ExecError> {
    a.checked_add(b).ok_or(ExecError::Format("RVA overflow"))
}

fn cstr(d: &[u8], off: usize, max: usize) -> Result<String, ExecError> {
    let tail = d.get(off..).ok_or(ExecError::Truncated)?;
    let n = tail.iter().take(max).position(|&b| b == 0).ok_or(ExecError::Format("unterminated string"))?;
    let s = core::str::from_utf8(&tail[..n]).map_err(|_| ExecError::Format("non-ASCII name"))?;
    Ok(String::from(s))
}

pub fn plan(d: &[u8]) -> Result<Plan, ExecError> {
    let pe_off = u32_at(d, 0x3C)? as usize;
    if rd::<4>(d, pe_off)? != *b"PE\0\0" {
        return Err(ExecError::Format("missing PE signature"));
    }
    if u16_at(d, pe_off + 4)? != 0x8664 {
        return Err(ExecError::Unsupported("not an x86-64 PE"));
    }
    let nsec = u16_at(d, pe_off + 6)? as usize;
    let opt_size = u16_at(d, pe_off + 20)? as usize;
    let chars = u16_at(d, pe_off + 22)?;
    if chars & 0x2000 != 0 {
        return Err(ExecError::Unsupported("DLL"));
    }
    if chars & 0x0002 == 0 {
        return Err(ExecError::Format("not an executable image"));
    }
    if nsec == 0 || nsec > 96 {
        return Err(ExecError::Format("bad section count"));
    }
    let opt = pe_off + 24;
    if u16_at(d, opt)? != 0x20B {
        return Err(ExecError::Unsupported("not PE32+"));
    }
    let entry_rva = u32_at(d, opt + 16)? as u64;
    let pref_base = u64_at(d, opt + 24)?;
    let sec_align = u32_at(d, opt + 32)?;
    let size_of_image = u32_at(d, opt + 56)? as u64;
    let size_of_headers = u32_at(d, opt + 60)?;
    let subsystem = u16_at(d, opt + 68)?;
    let nrva = u32_at(d, opt + 108)? as usize;
    if sec_align < PAGE_SIZE as u32 || sec_align % PAGE_SIZE as u32 != 0 {
        return Err(ExecError::Unsupported("SectionAlignment below page size"));
    }
    if subsystem != 2 && subsystem != 3 {
        return Err(ExecError::Unsupported("subsystem (need console or GUI)"));
    }
    if size_of_image == 0 || size_of_image > super::MAX_IMAGE_PAGES * PAGE_SIZE {
        return Err(ExecError::TooLarge);
    }
    if size_of_headers == 0 || size_of_headers as usize > d.len() || size_of_headers as u64 > size_of_image {
        return Err(ExecError::Format("bad SizeOfHeaders"));
    }
    let dir = |i: usize| -> Result<(u32, u32), ExecError> {
        if i >= nrva.min(16) {
            return Ok((0, 0));
        }
        Ok((u32_at(d, opt + 112 + i * 8)?, u32_at(d, opt + 116 + i * 8)?))
    };
    let (tls_rva, _tls_size) = dir(9)?;
    if dir(13)?.0 != 0 {
        return Err(ExecError::Unsupported("delay-load imports"));
    }
    if dir(14)?.0 != 0 {
        return Err(ExecError::Unsupported(".NET image"));
    }

    // section table
    let sec_tab = opt.checked_add(opt_size).ok_or(ExecError::Truncated)?;
    let mut secs: Vec<Section> = Vec::new();
    for i in 0..nsec {
        let o = sec_tab.checked_add(i * 40).ok_or(ExecError::Truncated)?;
        secs.push(Section {
            vsize: u32_at(d, o + 8)?,
            va: u32_at(d, o + 12)?,
            raw_size: u32_at(d, o + 16)?,
            raw_off: u32_at(d, o + 20)?,
            chars: u32_at(d, o + 36)?,
        });
    }

    // base address
    let base_ok = pref_base >= 0x1_0000
        && pref_base % 0x1_0000 == 0
        && is_user_range(pref_base, size_of_image)
        && pref_base + size_of_image < USER_MMAP_BASE;
    let base = if base_ok { pref_base } else { FALLBACK_BASE };

    let mut segments: Vec<Segment> = Vec::new();
    segments.push(Segment { va: base, file_off: 0, file_len: size_of_headers as usize, mem_len: size_of_headers as u64, perms: PERM_R });
    for s in &secs {
        let mem = if s.vsize != 0 { s.vsize } else { s.raw_size } as u64;
        if mem == 0 {
            continue;
        }
        if s.va % sec_align != 0 || (s.va as u64) + mem > size_of_image {
            return Err(ExecError::Format("section outside image"));
        }
        let file_len = core::cmp::min(s.raw_size as u64, mem) as usize;
        let mut perms = 0u8;
        if s.chars & 0x4000_0000 != 0 {
            perms |= PERM_R;
        }
        if s.chars & 0x8000_0000 != 0 {
            perms |= PERM_W;
        }
        if s.chars & 0x2000_0000 != 0 {
            perms |= PERM_X;
        }
        if perms == 0 {
            perms = PERM_R;
        }
        segments.push(Segment { va: base + s.va as u64, file_off: s.raw_off as usize, file_len, mem_len: mem, perms });
    }

    let mut patches: Vec<Patch> = Vec::new();

    // imports -> thunk addresses in the shim page
    let (imp_rva, imp_size) = dir(1)?;
    if imp_rva != 0 && imp_size != 0 {
        for k in 0..64usize {
            let desc = rva_to_off(&secs, size_of_headers, rva_add(imp_rva, (k as u32) * 20)?, 20)?;
            let oft = u32_at(d, desc)?;
            let name_rva = u32_at(d, desc + 12)?;
            let first = u32_at(d, desc + 16)?;
            if oft == 0 && name_rva == 0 && first == 0 {
                break;
            }
            let dll = cstr(d, rva_to_off(&secs, size_of_headers, name_rva, 1)?, 64)?;
            let lookup_rva = if oft != 0 { oft } else { first };
            for t in 0..1024u32 {
                let off = rva_to_off(&secs, size_of_headers, rva_add(lookup_rva, t * 8)?, 8)?;
                let thunk = u64_at(d, off)?;
                if thunk == 0 {
                    break;
                }
                if thunk >> 63 != 0 {
                    return Err(ExecError::Unsupported("import by ordinal"));
                }
                let name = cstr(d, rva_to_off(&secs, size_of_headers, rva_add((thunk & 0x7FFF_FFFF) as u32, 2)?, 1)?, 128)?;
                match nt::resolve(&dll, &name) {
                    Some(addr) => patches.push(Patch::Set { va: base + first as u64 + t as u64 * 8, val: addr }),
                    None => return Err(ExecError::UnresolvedImport { dll, name }),
                }
            }
        }
    }

    // base relocations (only needed when we couldn't use ImageBase)
    if base != pref_base {
        let (rel_rva, rel_size) = dir(5)?;
        if rel_rva == 0 || rel_size == 0 {
            return Err(ExecError::Unsupported("image needs relocation but has no .reloc"));
        }
        let delta = base.wrapping_sub(pref_base);
        let mut pos = 0u32;
        let mut count = 0u32;
        while pos.checked_add(8).map_or(false, |e| e <= rel_size) {
            let blk = rva_to_off(&secs, size_of_headers, rva_add(rel_rva, pos)?, 8)?;
            let page = u32_at(d, blk)?;
            let bsize = u32_at(d, blk + 4)?;
            if bsize < 8 || pos.checked_add(bsize).map_or(true, |e| e > rel_size) || bsize % 2 != 0 {
                return Err(ExecError::Format("bad relocation block"));
            }
            for e in 0..(bsize - 8) / 2 {
                let ent = u16_at(d, rva_to_off(&secs, size_of_headers, rva_add(rva_add(rel_rva, pos)?, 8 + e * 2)?, 2)?)?;
                match ent >> 12 {
                    0 => {}
                    10 => patches.push(Patch::Add { va: base + page as u64 + (ent & 0xFFF) as u64, delta }),
                    _ => return Err(ExecError::Unsupported("relocation type (only DIR64)")),
                }
                count += 1;
                if count > 1 << 20 {
                    return Err(ExecError::TooLarge);
                }
            }
            pos += bsize;
        }
    }

    // TLS directory: static TLS template; callbacks are ignored (documented limit)
    let tls = if tls_rva != 0 {
        let o = rva_to_off(&secs, size_of_headers, tls_rva, 40)?;
        let (start, end, index) = (u64_at(d, o)?, u64_at(d, o + 8)?, u64_at(d, o + 16)?);
        let zero = u32_at(d, o + 32)?;
        let adj = |va: u64| va.wrapping_sub(pref_base).wrapping_add(base);
        if end < start || end - start > 1 << 20 || zero > 1 << 20 {
            return Err(ExecError::Unsupported("TLS template too large"));
        }
        Some((adj(start), adj(end), zero, adj(index)))
    } else {
        None
    };
    Ok(Plan {
        abi: AbiKind::Nt,
        entry: base.checked_add(entry_rva).ok_or(ExecError::BadRange)?,
        segments,
        patches,
        image_base: base,
        phdr_va: 0,
        phnum: 0,
        phent: 0,
        tls,
        interp: None,
        main_entry: 0,
        at_base: 0,
    })
}
