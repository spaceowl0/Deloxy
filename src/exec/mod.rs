//! Binary loading (`deloxy-wltd`): ELF64 and PE32+ images into isolated user address spaces.
//!
//! Pipeline: parse (pure, bounds-checked) -> `Plan` -> `validate` -> map pages ->
//! copy segments -> apply patches (relocations / imports) -> set final permissions
//! (strict W^X) -> build the ABI-specific initial stack -> start a thread.
//! Every failure is an `ExecError`; malformed input must never fault the kernel.

pub mod elf;
pub mod pe;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use x86_64::VirtAddr;

use crate::abi::{AbiKind, nt};
use crate::cap::{CapObject, Rights};
use crate::mm::layout::{is_user_range, PAGE_SIZE};
use crate::mm::vmm::VmFlags;
use crate::task::{self, Process, USER_STACK_TOP};

pub const PERM_R: u8 = 1;
pub const PERM_W: u8 = 2;
pub const PERM_X: u8 = 4;

/// Upper bound on the memory image of one program (8 MiB) - checked before any allocation.
pub const MAX_IMAGE_PAGES: u64 = 2048;
pub const EXEC_STACK_PAGES: usize = 64; // 256 KiB

#[derive(Debug)]
pub enum ExecError {
    BadMagic,
    Truncated,
    Format(&'static str),
    Unsupported(&'static str),
    TooLarge,
    Overlap,
    BadRange,
    OutOfMemory,
    UnresolvedImport { dll: String, name: String },
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ExecError::BadMagic => write!(f, "not an ELF or PE image"),
            ExecError::Truncated => write!(f, "truncated image"),
            ExecError::Format(m) => write!(f, "malformed image: {}", m),
            ExecError::Unsupported(m) => write!(f, "unsupported: {}", m),
            ExecError::TooLarge => write!(f, "image too large"),
            ExecError::Overlap => write!(f, "overlapping segments"),
            ExecError::BadRange => write!(f, "address outside the user range"),
            ExecError::OutOfMemory => write!(f, "out of memory"),
            ExecError::UnresolvedImport { dll, name } => write!(f, "unimplemented: {}!{}", dll, name),
        }
    }
}

pub struct Segment {
    pub va: u64,
    pub file_off: usize,
    pub file_len: usize,
    pub mem_len: u64,
    pub perms: u8,
}

pub enum Patch {
    Set { va: u64, val: u64 },
    Add { va: u64, delta: u64 },
}

pub struct Plan {
    pub abi: AbiKind,
    pub entry: u64,
    pub segments: Vec<Segment>,
    pub patches: Vec<Patch>,
    pub image_base: u64,
    pub phdr_va: u64,
    pub phnum: u16,
    pub phent: u16,
    /// PE thread-local storage template: (raw data VA, raw data end VA, zero-fill size, VA of the TLS index variable).
    pub tls: Option<(u64, u64, u32, u64)>,
    /// PT_INTERP path of a dynamically linked ELF (None for static programs and PE images)
    pub interp: Option<String>,
    /// AT_ENTRY for dynamic programs (the program's own entry; `entry` is then the interpreter's)
    pub main_entry: u64,
    /// AT_BASE: load address of the interpreter
    pub at_base: u64,
}

/// Where the dynamic linker is mapped (between the program and the mmap area).
pub const INTERP_BASE: u64 = 0x0000_1000_0000_0000;

pub struct SpawnOpts<'a> {
    pub args: &'a [&'a str],
    /// Grant the process a Console capability (its stdout/stderr).
    pub console: bool,
    /// Extra capabilities installed before the first instruction (native ABI: first five handles go
    /// into the info page at `USER_INFO_BASE`, followed by the NUL-separated args).
    pub caps: &'a [(CapObject, Rights)],
    /// Capabilities installed only for foreign ABIs (Linux/NT): file access etc. Native programs never see them.
    pub foreign_caps: &'a [(CapObject, Rights)],
}

fn page_of(v: u64) -> u64 {
    v & !(PAGE_SIZE - 1)
}

/// Structural checks shared by all formats; runs before anything is allocated.
fn validate(plan: &Plan, data_len: usize) -> Result<(), ExecError> {
    if plan.segments.is_empty() {
        return Err(ExecError::Format("no loadable segments"));
    }
    let mut total_pages = 0u64;
    for s in &plan.segments {
        if s.mem_len == 0 || !is_user_range(s.va, s.mem_len) {
            return Err(ExecError::BadRange);
        }
        if s.file_len as u64 > s.mem_len {
            return Err(ExecError::Format("file size exceeds memory size"));
        }
        match s.file_off.checked_add(s.file_len) {
            Some(e) if e <= data_len => {}
            _ => return Err(ExecError::Truncated),
        }
        if s.perms & PERM_W != 0 && s.perms & PERM_X != 0 {
            return Err(ExecError::Unsupported("segment is both writable and executable (W^X)"));
        }
        let first = page_of(s.va);
        let last = page_of(s.va + s.mem_len - 1);
        total_pages += (last - first) / PAGE_SIZE + 1;
        if total_pages > MAX_IMAGE_PAGES {
            return Err(ExecError::TooLarge);
        }
    }
    // byte-range overlap (sorted copy of (start, end))
    let mut ranges: Vec<(u64, u64)> = plan.segments.iter().map(|s| (s.va, s.va + s.mem_len)).collect();
    ranges.sort_unstable();
    for w in ranges.windows(2) {
        if w[0].1 > w[1].0 {
            return Err(ExecError::Overlap);
        }
    }
    let entry_ok = plan
        .segments
        .iter()
        .any(|s| s.perms & PERM_X != 0 && plan.entry >= s.va && plan.entry < s.va + s.mem_len);
    if !entry_ok {
        return Err(ExecError::Format("entry point is not in an executable segment"));
    }
    Ok(())
}

pub fn write_user(p: &Process, va: u64, bytes: &[u8]) -> Result<(), ExecError> {
    let mut g = p.space.lock();
    let sp = g.as_mut().ok_or(ExecError::OutOfMemory)?;
    let mut done = 0usize;
    while done < bytes.len() {
        let v = va.checked_add(done as u64).ok_or(ExecError::BadRange)?;
        let off = (v & (PAGE_SIZE - 1)) as usize;
        let n = core::cmp::min(bytes.len() - done, PAGE_SIZE as usize - off);
        let va_t = VirtAddr::try_new(v).map_err(|_| ExecError::BadRange)?;
        let pa = sp.translate(va_t).ok_or(ExecError::BadRange)?;
        // SAFETY: `pa` is a frame owned by this (not yet running) process, reachable via the HHDM; `n` stays within the page.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr().add(done), crate::mm::vmm::phys_to_virt(pa), n) };
        done += n;
    }
    Ok(())
}

fn read_user_u64(p: &Process, va: u64) -> Result<u64, ExecError> {
    let mut g = p.space.lock();
    let sp = g.as_mut().ok_or(ExecError::OutOfMemory)?;
    let mut buf = [0u8; 8];
    for (i, b) in buf.iter_mut().enumerate() {
        let v = va.checked_add(i as u64).ok_or(ExecError::BadRange)?;
        let va_t = VirtAddr::try_new(v).map_err(|_| ExecError::BadRange)?;
        let pa = sp.translate(va_t).ok_or(ExecError::BadRange)?;
        // SAFETY: translated, mapped frame.
        *b = unsafe { *crate::mm::vmm::phys_to_virt(pa) };
    }
    Ok(u64::from_le_bytes(buf))
}

pub struct Built {
    pub proc: Arc<Process>,
    pub rip: u64,
    pub rsp: u64,
    pub arg0: u64,
    pub gs: u64,
}

/// Parse + map + prepare a process image. Does not start a thread (the fuzz test uses this alone).
/// Parse the image and, for a dynamically linked ELF, append the interpreter. Returns the plan and (if an
/// interpreter was added) the combined byte buffer the segments' file offsets refer to.
fn prepare_plan(data: &[u8]) -> Result<(Plan, Option<Vec<u8>>), ExecError> {
    let mut plan = if data.len() >= 4 && &data[..4] == b"\x7fELF" {
        elf::plan(data)?
    } else if data.len() >= 2 && &data[..2] == b"MZ" {
        pe::plan(data)?
    } else {
        return Err(ExecError::BadMagic);
    };
    let main_len = data.len();
    let mut combined: Option<Vec<u8>> = None;
    if let Some(path) = plan.interp.clone() {
        // dynamic program: map the interpreter (ld.so) next to it; ld.so loads the libraries and relocates everything
        let f = crate::abi::vfs::system_lib(&path).ok_or(ExecError::Unsupported("dynamic linker not found in the image"))?;
        let ibytes: &[u8] = f.data;
        let (mut isegs, ientry) = elf::plan_interp(ibytes, INTERP_BASE)?;
        for sg in isegs.iter_mut() {
            sg.file_off += main_len;
        }
        let mut c = Vec::with_capacity(main_len + ibytes.len());
        c.extend_from_slice(data);
        c.extend_from_slice(ibytes);
        plan.main_entry = plan.entry;
        plan.entry = ientry;
        plan.at_base = INTERP_BASE;
        plan.segments.extend(isegs);
        combined = Some(c);
    }
    validate(&plan, combined.as_ref().map_or(data.len(), |c| c.len()))?;
    Ok((plan, combined))
}

/// Parse + map + prepare a process image. Does not start a thread (the fuzz test uses this alone).
pub fn build(name: &str, data: &[u8], opts: &SpawnOpts) -> Result<Built, ExecError> {
    let (plan, combined) = prepare_plan(data)?;
    let main_len = data.len();
    let all: &[u8] = combined.as_deref().unwrap_or(data);
    let proc = task::create_process(name).ok_or(ExecError::OutOfMemory)?;
    build_into(proc, name, all, main_len, plan, opts)
}

/// Environment for the next `build_into` (execve passes the caller's envp this way; None = the default).
static EXEC_ENV: crate::sync::IrqMutex<Option<Vec<String>>> = crate::sync::IrqMutex::new(None);

/// Everything execve needs to resume the caller in the new image.
pub struct Replaced {
    pub rip: u64,
    pub rsp: u64,
    pub arg0: u64,
    pub gs: u64,
}

/// execve: replace the image of `p` (whose only thread is the caller). Everything that can fail on the file or format
/// is checked *before* the old image is destroyed; after that only out-of-memory can fail (the caller then kills the
/// process, like Linux does).
pub fn exec_replace(p: &Arc<Process>, name: &str, data: &[u8], args: &[&str], env: Vec<String>) -> Result<Replaced, (ExecError, bool)> {
    let (plan, combined) = prepare_plan(data).map_err(|e| (e, false))?;
    if plan.abi == AbiKind::Native {
        return Err((ExecError::Unsupported("native programs cannot be exec'd"), false));
    }
    let main_len = data.len();
    let all: &[u8] = combined.as_deref().unwrap_or(data);
    p.wipe_user_mappings();
    p.foreign.lock().reset_for_exec();
    *EXEC_ENV.lock() = if env.is_empty() { None } else { Some(env) };
    let opts = SpawnOpts { args, console: false, caps: &[], foreign_caps: &[] };
    let r = build_into(p.clone(), name, all, main_len, plan, &opts);
    *EXEC_ENV.lock() = None;
    match r {
        Ok(b) => Ok(Replaced { rip: b.rip, rsp: b.rsp, arg0: b.arg0, gs: b.gs }),
        Err(e) => Err((e, true)),
    }
}

fn build_into(proc: Arc<Process>, name: &str, data: &[u8], main_len: usize, plan: Plan, opts: &SpawnOpts) -> Result<Built, ExecError> {
    proc.set_abi(plan.abi);


    // Page permissions: union of every segment touching the page.
    let mut pages: BTreeMap<u64, u8> = BTreeMap::new();
    for s in &plan.segments {
        let mut pg = page_of(s.va);
        let last = page_of(s.va + s.mem_len - 1);
        while pg <= last {
            *pages.entry(pg).or_insert(0) |= s.perms;
            pg += PAGE_SIZE;
        }
    }
    // Map contiguous runs RW first (so we can fill them), tighten afterwards.
    let mut run_start = 0u64;
    let mut run_len = 0usize;
    let mut prev = 0u64;
    let mut flush = |start: u64, len: usize| -> Result<(), ExecError> {
        if len > 0 {
            proc.map_region(start, len, VmFlags::WRITE | VmFlags::USER).map_err(|_| ExecError::OutOfMemory)?;
        }
        Ok(())
    };
    for &pg in pages.keys() {
        if run_len > 0 && pg == prev + PAGE_SIZE {
            run_len += 1;
        } else {
            flush(run_start, run_len)?;
            run_start = pg;
            run_len = 1;
        }
        prev = pg;
    }
    flush(run_start, run_len)?;

    for s in &plan.segments {
        if s.file_len > 0 {
            write_user(&proc, s.va, &data[s.file_off..s.file_off + s.file_len])?;
        }
    }
    for patch in &plan.patches {
        match *patch {
            Patch::Set { va, val } => write_user(&proc, va, &val.to_le_bytes())?,
            Patch::Add { va, delta } => {
                let cur = read_user_u64(&proc, va)?;
                write_user(&proc, va, &cur.wrapping_add(delta).to_le_bytes())?;
            }
        }
    }
    {
        let mut g = proc.space.lock();
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
    }

    // brk starts after the highest loaded byte.
    let image_end = plan.segments.iter().map(|s| s.va + s.mem_len).max().unwrap_or(0);
    let brk_base = (image_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    {
        let mut f = proc.foreign.lock();
        f.image_base = plan.image_base;
        f.brk_base = brk_base;
        f.brk = brk_base;
        f.brk_mapped = brk_base;
    }

    // Console capability = the process's stdout/stderr.
    if opts.console {
        let h = proc.caps.lock().insert(CapObject::Console, Rights::WRITE).map_err(|_| ExecError::OutOfMemory)?;
        proc.foreign.lock().console = h;
    }

    let stack_base = USER_STACK_TOP - EXEC_STACK_PAGES as u64 * PAGE_SIZE;
    proc.map_region(stack_base, EXEC_STACK_PAGES, VmFlags::WRITE | VmFlags::USER)
        .map_err(|_| ExecError::OutOfMemory)?;

    let mut handles = [0u64; task::INFO_HANDLES];
    let all_caps = opts.caps.iter().chain(if plan.abi == AbiKind::Native { [].iter() } else { opts.foreign_caps.iter() });
    for (i, (obj, r)) in all_caps.enumerate() {
        let h = proc.caps.lock().insert(obj.clone(), *r).map_err(|_| ExecError::OutOfMemory)?;
        {
            let mut f = proc.foreign.lock();
            match obj {
                CapObject::Dir(_) if r.contains(Rights::READ) => f.fs_dir = true,
                CapObject::Store => {
                    f.fs_store_read |= r.contains(Rights::READ);
                    f.fs_store_write |= r.contains(Rights::WRITE);
                }
                _ => {}
            }
        }
        if i < handles.len() {
            handles[i] = h;
        }
    }
    if plan.abi != AbiKind::Native {
        proc.mem_limit_pages.store(task::FOREIGN_MEM_LIMIT_PAGES, core::sync::atomic::Ordering::Relaxed);
    }
    if plan.abi != AbiKind::Native {
        // identity used by the permission system (files and network decisions are keyed by name + image hash)
        let mut f = proc.foreign.lock();
        f.prog_name = String::from(name);
        f.prog_hash = crate::perm::image_hash(&data[..main_len]);
        if f.fs_dir || f.fs_store_read || f.fs_store_write {
            f.fs_pending = true;
        }
    }
    let (rsp, arg0, gs) = match plan.abi {
        AbiKind::Native => {
            // Info page: [role, n, side, handle0..handle4, args_len] (u64 words), args bytes from offset 128.
            let mut page = alloc::vec![0u8; 128];
            page[24..24 + 8 * handles.len()].copy_from_slice(unsafe_words(&handles).as_slice());
            let mut args_blob: Vec<u8> = Vec::new();
            for a in opts.args {
                args_blob.extend_from_slice(a.as_bytes());
                args_blob.push(0);
            }
            args_blob.truncate(1024);
            page[64..72].copy_from_slice(&(args_blob.len() as u64).to_le_bytes());
            page.extend_from_slice(&args_blob);
            proc.map_region(task::USER_INFO_BASE, 1, VmFlags::WRITE | VmFlags::USER).map_err(|_| ExecError::OutOfMemory)?;
            write_user(&proc, task::USER_INFO_BASE, &page)?;
            proc.space.lock().as_mut().ok_or(ExecError::OutOfMemory)?
                .protect(VirtAddr::new(task::USER_INFO_BASE), VmFlags::USER).map_err(|_| ExecError::OutOfMemory)?;
            (USER_STACK_TOP - 8, task::USER_INFO_BASE, 0)
        }
        AbiKind::Linux => (build_linux_stack(&proc, &plan, opts.args)?, 0, 0),
        AbiKind::Nt => {
            let (rsp, teb) = nt::setup_process(&proc, &plan, opts.args)?;
            (rsp, 0, teb)
        }
    };
    Ok(Built { proc, rip: plan.entry, rsp, arg0, gs })
}

fn unsafe_words(h: &[u64]) -> Vec<u8> {
    let mut v = Vec::with_capacity(h.len() * 8);
    for w in h {
        v.extend_from_slice(&w.to_le_bytes());
    }
    v
}

/// Build + start. Returns the new process.
pub fn spawn(name: &str, data: &[u8], opts: &SpawnOpts) -> Result<Arc<Process>, ExecError> {
    let b = build(name, data, opts)?;
    crate::audit_log!(crate::audit::EV_PROC_SPAWN, 0, 0, b.proc.pid, b.proc.abi() as u8, 0);
    task::spawn_user_thread_ex(&b.proc, name, b.rip, b.rsp, b.arg0, b.gs).ok_or(ExecError::OutOfMemory)?;
    Ok(b.proc)
}

// ------------------------------------------------------ Linux stack ---------

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_FLAGS: u64 = 8;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;

/// System V x86-64 initial process stack: argc, argv[], NULL, envp[], NULL, auxv[].
fn build_linux_stack(p: &Arc<Process>, plan: &Plan, args: &[&str]) -> Result<u64, ExecError> {
    const DEFAULT_ENV: [&str; 3] = ["PATH=/bin", "HOME=/", "TERM=dumb"];
    let custom: Option<Vec<String>> = EXEC_ENV.lock().take();
    let env_strs: Vec<&str> = match &custom {
        Some(v) => v.iter().map(|s| s.as_str()).collect(),
        None => DEFAULT_ENV.to_vec(),
    };
    let stack_base = USER_STACK_TOP - EXEC_STACK_PAGES as u64 * PAGE_SIZE;
    let mut cur = USER_STACK_TOP;
    let mut addrs: Vec<u64> = Vec::new();
    for s in args.iter().chain(env_strs.iter()) {
        let len = s.len() as u64 + 1;
        cur = cur.checked_sub(len).ok_or(ExecError::BadRange)?;
        let mut bytes: Vec<u8> = Vec::from(s.as_bytes());
        bytes.push(0);
        write_user(p, cur, &bytes)?;
        addrs.push(cur);
    }
    cur = cur.checked_sub(16).ok_or(ExecError::BadRange)?;
    let random_va = cur;
    let mut rnd = [0u8; 16];
    {
        let mut f = p.foreign.lock();
        rnd[..8].copy_from_slice(&f.next_random().to_le_bytes());
        rnd[8..].copy_from_slice(&f.next_random().to_le_bytes());
    }
    write_user(p, random_va, &rnd)?;
    cur &= !0xF;

    let argc = args.len();
    let execfn = addrs.first().copied().unwrap_or(0);
    let auxv: [(u64, u64); 14] = [
        (AT_PHDR, plan.phdr_va),
        (AT_PHENT, plan.phent as u64),
        (AT_PHNUM, plan.phnum as u64),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_BASE, plan.at_base),
        (AT_FLAGS, 0),
        (AT_ENTRY, if plan.main_entry != 0 { plan.main_entry } else { plan.entry }),
        (AT_UID, 1000),
        (AT_EUID, 1000),
        (AT_GID, 1000),
        (AT_EGID, 1000),
        (AT_CLKTCK, 100),
        (AT_SECURE, 0),
        (AT_RANDOM, random_va),
    ];
    let mut words: Vec<u64> = Vec::new();
    words.push(argc as u64);
    for a in &addrs[..argc] {
        words.push(*a);
    }
    words.push(0);
    for a in &addrs[argc..] {
        words.push(*a);
    }
    words.push(0);
    for (k, v) in auxv.iter() {
        words.push(*k);
        words.push(*v);
    }
    words.push(AT_EXECFN);
    words.push(execfn);
    words.push(AT_NULL);
    words.push(0);
    let rsp = cur.checked_sub(words.len() as u64 * 8).ok_or(ExecError::BadRange)? & !0xF;
    if rsp < stack_base {
        return Err(ExecError::TooLarge);
    }
    let mut bytes: Vec<u8> = Vec::with_capacity(words.len() * 8);
    for w in &words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    write_user(p, rsp, &bytes)?;
    Ok(rsp)
}
