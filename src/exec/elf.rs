//! ELF64 (x86-64, little endian) parser: ET_EXEC, static-PIE (RELATIVE relocations only) and dynamically linked
//! programs (PT_INTERP: the interpreter is mapped next to the program and does all relocation, see `exec::build`).
//! All reads are bounds-checked.

use alloc::string::String;
use alloc::vec::Vec;

use super::{ExecError, Patch, Plan, Segment, PERM_R, PERM_W, PERM_X};
use crate::abi::AbiKind;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;

const DT_NULL: u64 = 0;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;

/// Load bias for ET_DYN images.
const PIE_BASE: u64 = 0x0000_0000_0040_0000;

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

/// A PT_NOTE with owner "Deloxy" marks a native Deloxy-ABI program (no loader flags needed).
fn has_deloxy_note(d: &[u8], off: usize, len: usize) -> bool {
    if len > 4096 {
        return false;
    }
    let Some(end) = off.checked_add(len) else { return false };
    let Some(note) = d.get(off..end) else { return false };
    let mut pos = 0usize;
    for _ in 0..16 {
        if pos + 12 > note.len() {
            return false;
        }
        let namesz = u32::from_le_bytes(note[pos..pos + 4].try_into().unwrap()) as usize;
        let descsz = u32::from_le_bytes(note[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let name_off = pos + 12;
        let Some(name_end) = name_off.checked_add(namesz) else { return false };
        if name_end > note.len() {
            return false;
        }
        if &note[name_off..name_end] == b"Deloxy\0" {
            return true;
        }
        let advance = (12usize)
            .checked_add((namesz + 3) & !3)
            .and_then(|v| v.checked_add((descsz + 3) & !3));
        match advance {
            Some(a) if a > 0 => pos += a,
            _ => return false,
        }
    }
    false
}

pub fn plan(d: &[u8]) -> Result<Plan, ExecError> {
    if d.len() < 64 {
        return Err(ExecError::Truncated);
    }
    if d[4] != 2 || d[5] != 1 || d[6] != 1 {
        return Err(ExecError::Unsupported("not ELF64 little-endian v1"));
    }
    let e_type = u16_at(d, 16)?;
    if u16_at(d, 18)? != 62 {
        return Err(ExecError::Unsupported("not an x86-64 binary"));
    }
    let bias = match e_type {
        2 => 0,
        3 => PIE_BASE,
        _ => return Err(ExecError::Unsupported("ELF type (need ET_EXEC or ET_DYN)")),
    };
    let entry = u64_at(d, 24)?.checked_add(bias).ok_or(ExecError::BadRange)?;
    let phoff = usize::try_from(u64_at(d, 32)?).map_err(|_| ExecError::Truncated)?;
    let phentsize = u16_at(d, 54)?;
    let phnum = u16_at(d, 56)?;
    if phentsize != 56 {
        return Err(ExecError::Format("unexpected program header size"));
    }
    if phnum == 0 || phnum > 32 {
        return Err(ExecError::Format("bad program header count"));
    }
    let table_len = (phnum as usize) * 56;
    match phoff.checked_add(table_len) {
        Some(e) if e <= d.len() => {}
        _ => return Err(ExecError::Truncated),
    }

    let mut segments: Vec<Segment> = Vec::new();
    let mut native = false;
    let mut dynamic: Option<(usize, usize)> = None;
    let mut interp: Option<String> = None;
    for i in 0..phnum as usize {
        let ph = phoff + i * 56;
        let p_type = u32_at(d, ph)?;
        let flags = u32_at(d, ph + 4)?;
        let offset = u64_at(d, ph + 8)?;
        let vaddr = u64_at(d, ph + 16)?;
        let filesz = u64_at(d, ph + 32)?;
        let memsz = u64_at(d, ph + 40)?;
        match p_type {
            PT_LOAD => {
                if memsz == 0 {
                    continue;
                }
                if filesz > memsz {
                    return Err(ExecError::Format("p_filesz > p_memsz"));
                }
                let off = usize::try_from(offset).map_err(|_| ExecError::Truncated)?;
                let flen = usize::try_from(filesz).map_err(|_| ExecError::Truncated)?;
                match off.checked_add(flen) {
                    Some(e) if e <= d.len() => {}
                    _ => return Err(ExecError::Truncated),
                }
                let va = vaddr.checked_add(bias).ok_or(ExecError::BadRange)?;
                let mut perms = 0u8;
                if flags & 4 != 0 {
                    perms |= PERM_R;
                }
                if flags & 2 != 0 {
                    perms |= PERM_W;
                }
                if flags & 1 != 0 {
                    perms |= PERM_X;
                }
                segments.push(Segment { va, file_off: off, file_len: flen, mem_len: memsz, perms });
            }
            PT_INTERP => {
                let off = usize::try_from(offset).map_err(|_| ExecError::Truncated)?;
                let len = usize::try_from(filesz).map_err(|_| ExecError::Truncated)?;
                if len < 2 || len > 256 {
                    return Err(ExecError::Format("bad PT_INTERP"));
                }
                let raw = d.get(off..off.checked_add(len).ok_or(ExecError::Truncated)?).ok_or(ExecError::Truncated)?;
                let s = raw.split(|b| *b == 0).next().unwrap_or(&[]);
                interp = Some(String::from_utf8_lossy(s).into_owned());
            }
            PT_DYNAMIC => {
                let off = usize::try_from(offset).map_err(|_| ExecError::Truncated)?;
                let len = usize::try_from(filesz).map_err(|_| ExecError::Truncated)?;
                dynamic = Some((off, len));
            }
            PT_NOTE => {
                if let (Ok(off), Ok(len)) = (usize::try_from(offset), usize::try_from(filesz)) {
                    if has_deloxy_note(d, off, len) {
                        native = true;
                    }
                }
            }
            _ => {}
        }
    }

    // AT_PHDR: virtual address of the program header table inside a loaded segment.
    let mut phdr_va = 0u64;
    for s in &segments {
        let so = s.file_off as u64;
        if (phoff as u64) >= so && (phoff as u64) < so.saturating_add(s.file_len as u64) {
            if let Some(v) = s.va.checked_add(phoff as u64 - so) {
                phdr_va = v;
            }
        }
    }

    let mut patches: Vec<Patch> = Vec::new();
    if e_type == 3 && interp.is_none() {
        // static-PIE: we apply the RELATIVE relocations ourselves; with an interpreter, ld.so does all of it
        if let Some((doff, dlen)) = dynamic {
            let dend = doff.checked_add(dlen).ok_or(ExecError::Truncated)?;
            if dend > d.len() {
                return Err(ExecError::Truncated);
            }
            let (mut rela, mut relasz, mut relaent) = (0u64, 0u64, 24u64);
            for k in 0..(dlen / 16).min(512) {
                let tag = u64_at(d, doff + k * 16)?;
                let val = u64_at(d, doff + k * 16 + 8)?;
                match tag {
                    DT_NULL => break,
                    DT_RELA => rela = val,
                    DT_RELASZ => relasz = val,
                    DT_RELAENT => relaent = val,
                    _ => {}
                }
            }
            if relasz > 0 {
                if relaent != 24 || relasz / 24 > 65536 {
                    return Err(ExecError::Format("bad relocation table"));
                }
                // translate the table's virtual address to a file offset through the segments
                let rela_va = rela.checked_add(bias).ok_or(ExecError::BadRange)?;
                let mut base_off = None;
                for s in &segments {
                    if rela_va >= s.va && rela_va < s.va.saturating_add(s.file_len as u64) {
                        base_off = Some(s.file_off + (rela_va - s.va) as usize);
                    }
                }
                let base_off = base_off.ok_or(ExecError::Format("relocation table not in file data"))?;
                for r in 0..(relasz / 24) as usize {
                    let o = base_off + r * 24;
                    let r_off = u64_at(d, o)?;
                    let info = u64_at(d, o + 8)?;
                    let addend = u64_at(d, o + 16)?;
                    match info & 0xFFFF_FFFF {
                        0 => {}
                        8 => patches.push(Patch::Set {
                            va: r_off.checked_add(bias).ok_or(ExecError::BadRange)?,
                            val: addend.wrapping_add(bias),
                        }),
                        _ => return Err(ExecError::Unsupported("relocation type (only R_X86_64_RELATIVE)")),
                    }
                }
            }
        }
    }

    Ok(Plan {
        abi: if native { AbiKind::Native } else { AbiKind::Linux },
        entry,
        segments,
        patches,
        image_base: bias,
        phdr_va,
        phnum,
        phent: 56,
        tls: None,
        interp,
        main_entry: 0,
        at_base: 0,
    })
}

/// Plan the dynamic linker (an ET_DYN shared object) at `bias`: its loadable segments (file offsets relative to `d`) and
/// entry point. It relocates itself at startup, so no patches are needed.
pub fn plan_interp(d: &[u8], bias: u64) -> Result<(Vec<Segment>, u64), ExecError> {
    if d.len() < 64 || &d[..4] != b"\x7fELF" || d[4] != 2 || d[5] != 1 {
        return Err(ExecError::Format("interpreter is not an ELF64 image"));
    }
    if u16_at(d, 16)? != 3 || u16_at(d, 18)? != 62 {
        return Err(ExecError::Format("interpreter is not an x86-64 shared object"));
    }
    let entry = u64_at(d, 24)?.checked_add(bias).ok_or(ExecError::BadRange)?;
    let phoff = usize::try_from(u64_at(d, 32)?).map_err(|_| ExecError::Truncated)?;
    let phnum = u16_at(d, 56)? as usize;
    if u16_at(d, 54)? != 56 || phnum == 0 || phnum > 32 {
        return Err(ExecError::Format("bad interpreter program headers"));
    }
    let mut segments = Vec::new();
    for i in 0..phnum {
        let ph = phoff + i * 56;
        if u32_at(d, ph)? != PT_LOAD {
            continue;
        }
        let flags = u32_at(d, ph + 4)?;
        let offset = usize::try_from(u64_at(d, ph + 8)?).map_err(|_| ExecError::Truncated)?;
        let vaddr = u64_at(d, ph + 16)?;
        let filesz = usize::try_from(u64_at(d, ph + 32)?).map_err(|_| ExecError::Truncated)?;
        let memsz = u64_at(d, ph + 40)?;
        if memsz == 0 {
            continue;
        }
        if (filesz as u64) > memsz || offset.checked_add(filesz).map_or(true, |e| e > d.len()) {
            return Err(ExecError::Truncated);
        }
        let mut perms = 0u8;
        if flags & 4 != 0 { perms |= PERM_R; }
        if flags & 2 != 0 { perms |= PERM_W; }
        if flags & 1 != 0 { perms |= PERM_X; }
        segments.push(Segment { va: vaddr.checked_add(bias).ok_or(ExecError::BadRange)?, file_off: offset, file_len: filesz, mem_len: memsz, perms });
    }
    Ok((segments, entry))
}
