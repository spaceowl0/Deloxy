//! Windows DLL support at run time: finding DLL files, `LoadLibrary`, `GetProcAddress`, `FreeLibrary`.
//!
//! A DLL is planned by `pe::DllCtx` (own base, relocations, imports bound to the shim table or to other DLLs),
//! mapped like an executable segment set, and its `DllMain(hinst, DLL_PROCESS_ATTACH, 0)` is run by *user mode*
//! code: the syscall that loaded it returns into the continuation stub (`nt::CONT_VA`), which walks a list of
//! `{entry, hinst, reason}` records and then returns to the caller with the LoadLibrary result (NULL when a
//! DllMain returned FALSE). Static imports use the same list through `nt::START_VA` before the entry point.
//! Limits: no thread attach/detach notifications, no DLL TLS, DLL_PROCESS_DETACH only through FreeLibrary
//! (not at process exit), dependencies stay loaded after their dependent is freed, pages of a freed DLL stay
//! mapped (a later LoadLibrary of the same file reuses them in place).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

use x86_64::VirtAddr;

use super::pe::{self, DllCtx, DllPlan, ImportRef, Module};
use super::{page_of, write_user, ExecError, Patch, PERM_W, PERM_X};
use crate::abi::nt;
use crate::mm::layout::PAGE_SIZE;
use crate::mm::vmm::VmFlags;
use crate::task::Process;

pub const ERROR_MOD_NOT_FOUND: u32 = 126;
pub const ERROR_PROC_NOT_FOUND: u32 = 127;
pub const ERROR_BAD_EXE_FORMAT: u32 = 193;
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub const ERROR_INVALID_HANDLE: u32 = 6;

/// Handle returned for the built-in system DLLs (kernel32, msvcrt, ...).
pub const SYSTEM_HMODULE: u64 = 0x0000_7FF0_0000_0000;

/// DLL bytes by lower-case name without extension: the boot image first, then the root of the persistent store.
pub fn find_dll_bytes(name: &str) -> Option<Vec<u8>> {
    let want = alloc::format!("{}.dll", name);
    if let Some(root) = crate::fs::root() {
        if let Some(f) = root.files.iter().find(|f| f.name.eq_ignore_ascii_case(&want)) {
            return Some(f.data.to_vec());
        }
    }
    if crate::store::state() == crate::store::State::Ready {
        if let Ok(Some(b)) = crate::store::with(|s| {
            let n = s.list().into_iter().find(|e| e.name.eq_ignore_ascii_case(&want))?.name;
            s.read(&n).ok()
        }) {
            return Some(b);
        }
    }
    None
}

fn err_code(e: &ExecError) -> u32 {
    match e {
        ExecError::UnresolvedImport { .. } => ERROR_PROC_NOT_FOUND,
        ExecError::OutOfMemory | ExecError::TooLarge => ERROR_NOT_ENOUGH_MEMORY,
        _ => ERROR_BAD_EXE_FORMAT,
    }
}

/// Map one planned DLL into a running process. `existing` = its pages are still mapped from an earlier load
/// (the image is rewritten in place).
fn map_dll_plan(p: &Arc<Process>, dp: &DllPlan, existing: bool) -> Result<(), ExecError> {
    let oom = |_| ExecError::OutOfMemory;
    let mut pages: BTreeMap<u64, u8> = BTreeMap::new();
    for s in &dp.segments {
        let mut pg = page_of(s.va);
        let last = page_of(s.va + s.mem_len - 1);
        while pg <= last {
            *pages.entry(pg).or_insert(0) |= s.perms;
            pg += PAGE_SIZE;
        }
    }
    if existing {
        let mut g = p.space.lock();
        let sp = g.as_mut().ok_or(ExecError::OutOfMemory)?;
        for &pg in pages.keys() {
            sp.protect(VirtAddr::new(pg), VmFlags::USER | VmFlags::WRITE).map_err(|_| ExecError::OutOfMemory)?;
        }
        drop(g);
        let zero = alloc::vec![0u8; PAGE_SIZE as usize];
        for &pg in pages.keys() {
            write_user(p, pg, &zero)?;
        }
    } else {
        let (mut start, mut len, mut prev) = (0u64, 0usize, 0u64);
        for &pg in pages.keys() {
            if len > 0 && pg == prev + PAGE_SIZE {
                len += 1;
            } else {
                if len > 0 {
                    p.map_region(start, len, VmFlags::WRITE | VmFlags::USER).map_err(oom)?;
                }
                start = pg;
                len = 1;
            }
            prev = pg;
        }
        if len > 0 {
            p.map_region(start, len, VmFlags::WRITE | VmFlags::USER).map_err(oom)?;
        }
    }
    for s in &dp.segments {
        if s.file_len > 0 {
            write_user(p, s.va, &dp.bytes[s.file_off..s.file_off + s.file_len])?;
        }
    }
    for patch in &dp.patches {
        match *patch {
            Patch::Set { va, val } => write_user(p, va, &val.to_le_bytes())?,
            Patch::Add { va, delta } => {
                let cur = super::read_user_u64(p, va)?;
                write_user(p, va, &cur.wrapping_add(delta).to_le_bytes())?;
            }
        }
    }
    let mut g = p.space.lock();
    let sp = g.as_mut().ok_or(ExecError::OutOfMemory)?;
    for (&pg, &perms) in pages.iter() {
        let mut f = VmFlags::USER;
        if perms & PERM_W != 0 {
            f = f | VmFlags::WRITE;
        }
        if perms & PERM_X != 0 {
            f = f | VmFlags::EXEC;
        }
        sp.protect(VirtAddr::new(pg), f).map_err(|_| ExecError::OutOfMemory)?;
    }
    Ok(())
}

/// Queue `(entry, hinst, reason)` records and ask `nt::syscall` to continue through the user-mode stub.
fn queue_calls(p: &Arc<Process>, calls: &[(u64, u64, u32)]) -> Result<(), ExecError> {
    if calls.is_empty() {
        return Ok(());
    }
    let mut buf: Vec<u8> = Vec::new();
    for &(entry, hinst, reason) in calls.iter().take(40) {
        buf.extend_from_slice(&entry.to_le_bytes());
        buf.extend_from_slice(&hinst.to_le_bytes());
        buf.extend_from_slice(&(reason as u64).to_le_bytes());
    }
    buf.extend_from_slice(&[0u8; 8]);
    write_user(p, nt::LIST_VA, &buf)?;
    p.foreign.lock().pending_init = true;
    Ok(())
}

fn exe_range(p: &Process) -> (u64, u64) {
    let g = p.foreign.lock();
    (g.image_base, g.brk_base_hint.max(g.image_base + 0x1_0000))
}

/// `LoadLibrary(path)`: HMODULE or a Win32 error code.
pub fn load_library(p: &Arc<Process>, path: &str) -> Result<u64, u32> {
    let name = pe::norm_name(path);
    if name.is_empty() {
        return Err(ERROR_MOD_NOT_FOUND);
    }
    if nt::is_system_dll(&name) {
        return Ok(SYSTEM_HMODULE);
    }
    let (known, mut reserved, next, dormant) = {
        let mut g = p.foreign.lock();
        if let Some(m) = g.modules.iter_mut().find(|m| m.name == name && m.attached) {
            m.refs += 1;
            return Ok(m.base);
        }
        let dormant = g.modules.iter().position(|m| m.name == name && !m.attached).map(|i| g.modules.remove(i));
        let reserved: Vec<(u64, u64)> = g.modules.iter().map(|m| (m.base, m.base + ((m.size + 0xFFFF) & !0xFFFF))).collect();
        (g.modules.clone(), reserved, g.dll_next, dormant)
    };
    let (es, ee) = exe_range(p);
    reserved.push((es, ee));
    if let Some(d) = &dormant {
        // its old range is ours again
        let _ = d;
    }
    // bytes: a bare name comes from the boot image / store root (no permission needed, like a static import);
    // an explicit path is opened through the VFS (its permission rules apply)
    let bytes = {
        let norm = path.replace('\\', "/");
        let norm = norm.strip_prefix("C:/").or_else(|| norm.strip_prefix("c:/")).unwrap_or(&norm);
        let mut b: Option<Vec<u8>> = if norm.contains('/') { None } else { find_dll_bytes(&name) };
        if b.is_none() && norm.contains('/') {
            if let Ok(f) = crate::abi::vfs::open(p, norm, false, false, false, false) {
                if !f.is_dir() {
                    b = Some(f.bytes().to_vec());
                }
            }
        }
        b.or_else(|| find_dll_bytes(&name)).ok_or(ERROR_MOD_NOT_FOUND)?
    };
    let finder = |n: &str| find_dll_bytes(n);
    let mut ctx = DllCtx::new(&finder, known, reserved, next);
    let forced = dormant.as_ref().map(|d| d.base);
    if let Some(d) = &dormant {
        // keep the dormant range out of `reserved` so the forced base is acceptable
        let _ = d;
    }
    let root = match ctx.load_bytes(&name, bytes, forced) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("LoadLibrary({}): {}", path, e);
            if let Some(d) = dormant {
                p.foreign.lock().modules.push(d);
            }
            return Err(err_code(&e));
        }
    };
    let _ = root;
    for (i, dp) in ctx.mods.iter().enumerate() {
        let reuse = forced.is_some() && dp.module.name == name;
        if let Err(e) = map_dll_plan(p, dp, reuse) {
            log::warn!("LoadLibrary({}): mapping failed: {}", path, e);
            let _ = i;
            return Err(err_code(&e));
        }
    }
    let calls: Vec<(u64, u64, u32)> = ctx.init_order.iter().filter_map(|&i| { let m = &ctx.mods[i].module; (m.entry != 0).then_some((m.entry, m.base, 1u32)) }).collect();
    let base = ctx.mods.iter().find(|m| m.module.name == name).map(|m| m.module.base).ok_or(ERROR_BAD_EXE_FORMAT)?;
    {
        let mut g = p.foreign.lock();
        for dp in ctx.mods.iter() {
            let mut m = dp.module.clone();
            m.refs = 1;
            m.attached = true;
            g.modules.push(m);
        }
        g.dll_next = g.dll_next.max(ctx.next_base);
    }
    if queue_calls(p, &calls).is_err() {
        return Err(ERROR_NOT_ENOUGH_MEMORY);
    }
    Ok(base)
}

/// `FreeLibrary(h)`: false for an unknown handle.
pub fn free_library(p: &Arc<Process>, h: u64) -> bool {
    if h == SYSTEM_HMODULE {
        return true;
    }
    let call = {
        let mut g = p.foreign.lock();
        let Some(m) = g.modules.iter_mut().find(|m| m.base == h && m.attached) else { return false };
        if m.refs > 1 {
            m.refs -= 1;
            return true;
        }
        m.refs = 0;
        m.attached = false;
        (m.entry != 0).then_some((m.entry, m.base, 0u32))
    };
    if let Some(c) = call {
        let _ = queue_calls(p, &[c]);
    }
    true
}

/// `GetModuleHandle(name)`: loaded DLLs and system DLLs; None when unknown.
pub fn module_handle(p: &Arc<Process>, name: &str) -> Option<u64> {
    let n = pe::norm_name(name);
    if let Some(m) = p.foreign.lock().modules.iter().find(|m| m.name == n && m.attached) {
        return Some(m.base);
    }
    if nt::is_system_dll(&n) {
        return Some(SYSTEM_HMODULE);
    }
    None
}

/// Name of the loaded module with handle `h` (for GetModuleFileName).
pub fn module_name(p: &Arc<Process>, h: u64) -> Option<String> {
    p.foreign.lock().modules.iter().find(|m| m.base == h && m.attached).map(|m| alloc::format!("{}.dll", m.name))
}

/// `GetProcAddress` into a loaded DLL: `Some(None)` = it is one of ours but the export is missing.
pub fn proc_address(p: &Arc<Process>, h: u64, imp: ImportRef) -> Option<Option<u64>> {
    let (known, name) = {
        let g = p.foreign.lock();
        let m = g.modules.iter().find(|m| m.base == h && m.attached)?;
        (g.modules.clone(), m.name.clone())
    };
    let none = |_: &str| None;
    let mut ctx = DllCtx::new(&none, known, Vec::new(), 0);
    Some(ctx.export_of_known(&name, imp))
}
