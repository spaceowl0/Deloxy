//! PE32+ (x86-64) console/GUI executable and DLL parser. Imports are resolved against the built-in Win32 shim
//! table (kernel32, msvcrt, ws2_32...) or against DLL files shipped next to the program: a DLL is planned at its
//! own base (preferred ImageBase when free, else relocated), its imports are bound recursively, forwarded exports
//! and import-by-ordinal are followed. An unknown import is a load error naming `dll!function` (nothing half-runs).
//! Relocations (DIR64) are applied only when the preferred ImageBase can't be used.

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


/// First address handed out to DLLs that cannot use their preferred base.
pub const DLL_REGION: u64 = 0x0000_0002_0000_0000;
const DLL_LIMIT: u64 = 0x0000_7000_0000_0000;
const MAX_DLLS: usize = 16;
const MAX_EXPORTS: usize = 8192;

#[derive(Clone, Debug)]
pub enum ExpTarget {
    Rva(u32),
    /// "DLL.Function" or "DLL.#ordinal"
    Forward(String),
}

#[derive(Clone, Debug)]
pub struct Export {
    pub ordinal: u32,
    pub name: Option<String>,
    pub target: ExpTarget,
}

/// A loaded (or planned) DLL: what the per-process module list remembers.
#[derive(Clone, Debug)]
pub struct Module {
    /// lower-case file name without ".dll"
    pub name: String,
    pub base: u64,
    pub size: u64,
    /// DllMain (0 = none)
    pub entry: u64,
    pub exports: Vec<Export>,
    /// LoadLibrary reference count (static imports count as one)
    pub refs: u32,
    /// DllMain(DLL_PROCESS_ATTACH) has run and DETACH has not
    pub attached: bool,
}

/// A DLL image planned in this session; segment file offsets refer to `bytes`.
pub struct DllPlan {
    pub module: Module,
    pub bytes: Vec<u8>,
    pub segments: Vec<Segment>,
    pub patches: Vec<Patch>,
}

#[derive(Clone, Copy)]
pub enum ImportRef<'a> {
    Name(&'a str),
    Ordinal(u32),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ModRef {
    Known(usize),
    New(usize),
}

/// Lower-case base name without directory and without ".dll".
pub fn norm_name(n: &str) -> String {
    let base = n.rsplit(|c| c == '/' || c == '\\').next().unwrap_or(n);
    let mut l = String::from(base).to_ascii_lowercase();
    if l.ends_with(".dll") {
        l.truncate(l.len() - 4);
    }
    l
}

/// Planning context shared by the static (exec time) and dynamic (LoadLibrary) loaders.
pub struct DllCtx<'a> {
    /// modules already loaded in the process (empty at exec time)
    pub known: Vec<Module>,
    /// modules planned in this session, in discovery order
    pub mods: Vec<DllPlan>,
    /// indices into `mods` in initialisation order (dependencies first)
    pub init_order: Vec<usize>,
    pub reserved: Vec<(u64, u64)>,
    pub next_base: u64,
    finder: &'a dyn Fn(&str) -> Option<Vec<u8>>,
    depth: usize,
}

impl<'a> DllCtx<'a> {
    pub fn new(finder: &'a dyn Fn(&str) -> Option<Vec<u8>>, known: Vec<Module>, reserved: Vec<(u64, u64)>, next_base: u64) -> DllCtx<'a> {
        DllCtx { known, mods: Vec::new(), init_order: Vec::new(), reserved, next_base: next_base.max(DLL_REGION), finder, depth: 0 }
    }

    fn find(&self, name: &str) -> Option<ModRef> {
        if let Some(i) = self.mods.iter().position(|m| m.module.name == name) {
            return Some(ModRef::New(i));
        }
        self.known.iter().position(|m| m.name == name && m.attached).map(ModRef::Known)
    }

    fn module(&self, m: ModRef) -> &Module {
        match m {
            ModRef::Known(i) => &self.known[i],
            ModRef::New(i) => &self.mods[i].module,
        }
    }

    pub fn module_ref(&self, name: &str) -> Option<ModRef> {
        self.find(&norm_name(name))
    }

    /// Export `imp` of the already loaded module `name` (None when missing).
    pub fn export_of_known(&mut self, name: &str, imp: ImportRef) -> Option<u64> {
        let m = self.module_ref(name)?;
        self.resolve_export(m, imp, 0)
    }

    fn overlaps(&self, b: u64, len: u64) -> bool {
        self.reserved.iter().any(|&(s, e)| b < e && b + len > s)
    }

    fn choose_base(&mut self, pref: u64, size: u64, forced: Option<u64>) -> Result<u64, ExecError> {
        let len = (size + 0xFFFF) & !0xFFFF;
        let fits = |c: &DllCtx, b: u64| b >= 0x1_0000 && b % 0x1_0000 == 0 && is_user_range(b, len) && b + len < DLL_LIMIT && b + len < USER_MMAP_BASE && !c.overlaps(b, len);
        let base = if let Some(f) = forced {
            if !fits(self, f) {
                return Err(ExecError::BadRange);
            }
            f
        } else if fits(self, pref) {
            pref
        } else {
            let mut b = self.next_base;
            while !fits(self, b) {
                b = b.checked_add(0x1_0000).ok_or(ExecError::BadRange)?;
                if b > DLL_LIMIT {
                    return Err(ExecError::OutOfMemory);
                }
            }
            self.next_base = b + len;
            b
        };
        self.reserved.push((base, base + len));
        Ok(base)
    }

    /// Find (or plan, recursively) the DLL called `dll`.
    pub fn load(&mut self, dll: &str) -> Result<ModRef, ExecError> {
        let name = norm_name(dll);
        if let Some(m) = self.find(&name) {
            return Ok(m);
        }
        let bytes = (self.finder)(&name).ok_or_else(|| ExecError::UnresolvedImport { dll: alloc::format!("{}.dll", name), name: String::from("(file not found)") })?;
        self.load_bytes(&name, bytes, None)
    }

    /// Plan a DLL from its bytes (`forced` = reload at a fixed base).
    pub fn load_bytes(&mut self, name: &str, bytes: Vec<u8>, forced: Option<u64>) -> Result<ModRef, ExecError> {
        if self.depth >= 8 || self.mods.len() >= MAX_DLLS {
            return Err(ExecError::Unsupported("too many or too deeply nested DLLs"));
        }
        self.depth += 1;
        let r = plan_image(&bytes, Mode::Dll { name: String::from(name), forced }, self);
        self.depth -= 1;
        let img = r?;
        let idx = img.idx.ok_or(ExecError::Format("internal: DLL not registered"))?;
        self.mods[idx].bytes = bytes;
        Ok(ModRef::New(idx))
    }

    /// Bind one import: the Win32 shim first, then DLL files.
    pub fn bind(&mut self, dll: &str, imp: ImportRef) -> Result<u64, ExecError> {
        if let ImportRef::Name(n) = imp {
            if let Some(a) = nt::resolve(dll, n) {
                return Ok(a);
            }
        }
        let unresolved = || ExecError::UnresolvedImport {
            dll: String::from(dll),
            name: match imp {
                ImportRef::Name(n) => String::from(n),
                ImportRef::Ordinal(o) => alloc::format!("#{}", o),
            },
        };
        if nt::is_system_dll(dll) {
            return Err(unresolved());
        }
        let m = match self.load(dll) {
            Ok(m) => m,
            Err(ExecError::UnresolvedImport { .. }) => return Err(unresolved()),
            Err(e) => return Err(e),
        };
        self.resolve_export(m, imp, 0).ok_or_else(unresolved)
    }

    /// Address of an export of `m` (forwarders followed).
    pub fn resolve_export(&mut self, m: ModRef, imp: ImportRef, hops: usize) -> Option<u64> {
        let (base, target) = {
            let md = self.module(m);
            let e = match imp {
                ImportRef::Name(n) => md.exports.iter().find(|e| e.name.as_deref() == Some(n)),
                ImportRef::Ordinal(o) => md.exports.iter().find(|e| e.ordinal == o),
            }?;
            (md.base, e.target.clone())
        };
        match target {
            ExpTarget::Rva(r) => Some(base + r as u64),
            ExpTarget::Forward(s) => {
                if hops > 8 {
                    return None;
                }
                let (d, f) = s.split_once('.')?;
                let dll = alloc::format!("{}.dll", d);
                let ord = f.strip_prefix('#').and_then(|o| o.parse::<u32>().ok());
                if nt::is_system_dll(&dll) {
                    return if ord.is_some() { None } else { nt::resolve(&dll, f) };
                }
                let m2 = self.load(&dll).ok()?;
                match ord {
                    Some(o) => self.resolve_export(m2, ImportRef::Ordinal(o), hops + 1),
                    None => self.resolve_export(m2, ImportRef::Name(f), hops + 1),
                }
            }
        }
    }
}

#[derive(Clone)]
pub enum Mode {
    Exe,
    Dll { name: String, forced: Option<u64> },
}

struct Image {
    entry: u64,
    base: u64,
    segments: Vec<Segment>,
    patches: Vec<Patch>,
    tls: Option<(u64, u64, u32, u64)>,
    idx: Option<usize>,
}

fn parse_exports(d: &[u8], secs: &[Section], headers: u32, rva: u32, size: u32) -> Result<Vec<Export>, ExecError> {
    if rva == 0 || size < 40 {
        return Ok(Vec::new());
    }
    let o = rva_to_off(secs, headers, rva, 40)?;
    let ord_base = u32_at(d, o + 16)?;
    let nfunc = u32_at(d, o + 20)? as usize;
    let nnames = u32_at(d, o + 24)? as usize;
    let (funcs, names, ords) = (u32_at(d, o + 28)?, u32_at(d, o + 32)?, u32_at(d, o + 36)?);
    if nfunc > MAX_EXPORTS || nnames > MAX_EXPORTS {
        return Err(ExecError::Unsupported("too many exports"));
    }
    let end = rva.checked_add(size).ok_or(ExecError::Format("RVA overflow"))?;
    let mut out: Vec<Export> = Vec::with_capacity(nfunc);
    for i in 0..nfunc {
        let f = u32_at(d, rva_to_off(secs, headers, rva_add(funcs, i as u32 * 4)?, 4)?)?;
        if f == 0 {
            continue;
        }
        let target = if f >= rva && f < end { ExpTarget::Forward(cstr(d, rva_to_off(secs, headers, f, 1)?, 200)?) } else { ExpTarget::Rva(f) };
        out.push(Export { ordinal: ord_base.wrapping_add(i as u32), name: None, target });
    }
    for i in 0..nnames {
        let nrva = u32_at(d, rva_to_off(secs, headers, rva_add(names, i as u32 * 4)?, 4)?)?;
        let idx = u16_at(d, rva_to_off(secs, headers, rva_add(ords, i as u32 * 2)?, 2)?)? as u32;
        let name = cstr(d, rva_to_off(secs, headers, nrva, 1)?, 200)?;
        let ordinal = ord_base.wrapping_add(idx);
        if let Some(e) = out.iter_mut().find(|e| e.ordinal == ordinal) {
            e.name = Some(name);
        }
    }
    Ok(out)
}

/// Executable entry: parse `d` and every DLL it imports (found through `finder`) into one `Plan`.
pub fn plan(d: &[u8], finder: &dyn Fn(&str) -> Option<Vec<u8>>) -> Result<Plan, ExecError> {
    let mut ctx = DllCtx::new(finder, Vec::new(), Vec::new(), DLL_REGION);
    let img = plan_image(d, Mode::Exe, &mut ctx)?;
    let mut patches = img.patches;
    let mut extra: Vec<Segment> = Vec::new();
    let mut blobs: Vec<Vec<u8>> = Vec::new();
    let mut off = d.len();
    for dp in ctx.mods.iter_mut() {
        blobs.push(dp.bytes.clone());
        for sg in &dp.segments {
            extra.push(Segment { va: sg.va, file_off: sg.file_off + off, file_len: sg.file_len, mem_len: sg.mem_len, perms: sg.perms });
        }
        for pt in &dp.patches {
            patches.push(match pt {
                Patch::Set { va, val } => Patch::Set { va: *va, val: *val },
                Patch::Add { va, delta } => Patch::Add { va: *va, delta: *delta },
            });
        }
        off += dp.bytes.len();
        dp.module.attached = true;
    }
    let dll_init: Vec<(u64, u64)> = ctx.init_order.iter().filter(|&&i| ctx.mods[i].module.entry != 0).map(|&i| (ctx.mods[i].module.base, ctx.mods[i].module.entry)).collect();
    let modules: Vec<Module> = ctx.mods.iter().map(|m| m.module.clone()).collect();
    Ok(Plan {
        abi: AbiKind::Nt,
        entry: img.entry,
        segments: img.segments,
        patches,
        image_base: img.base,
        phdr_va: 0,
        phnum: 0,
        phent: 0,
        tls: img.tls,
        interp: None,
        main_entry: 0,
        at_base: 0,
        extra_segments: extra,
        dll_bytes: if blobs.is_empty() { None } else { Some(blobs) },
        modules,
        dll_init,
    })
}

fn plan_image(d: &[u8], mode: Mode, ctx: &mut DllCtx) -> Result<Image, ExecError> {
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
    let is_dll = chars & 0x2000 != 0;
    match mode {
        Mode::Exe if is_dll => return Err(ExecError::Unsupported("DLL")),
        Mode::Dll { .. } if !is_dll => return Err(ExecError::Format("not a DLL")),
        _ => {}
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
    if !is_dll && subsystem != 2 && subsystem != 3 {
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
    let base = match &mode {
        Mode::Exe => {
            let base_ok = pref_base >= 0x1_0000 && pref_base % 0x1_0000 == 0 && is_user_range(pref_base, size_of_image) && pref_base + size_of_image < USER_MMAP_BASE;
            let b = if base_ok { pref_base } else { FALLBACK_BASE };
            ctx.reserved.push((b, b + ((size_of_image + 0xFFFF) & !0xFFFF)));
            b
        }
        Mode::Dll { forced, .. } => ctx.choose_base(pref_base, size_of_image, *forced)?,
    };

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

    // a DLL is registered (with its exports) before its imports are bound, so import cycles resolve
    let idx = if let Mode::Dll { name, .. } = &mode {
        let (exp_rva, exp_size) = dir(0)?;
        let exports = parse_exports(d, &secs, size_of_headers, exp_rva, exp_size)?;
        let entry = if entry_rva != 0 { base.checked_add(entry_rva).ok_or(ExecError::BadRange)? } else { 0 };
        ctx.mods.push(DllPlan { module: Module { name: name.clone(), base, size: size_of_image, entry, exports, refs: 1, attached: false }, bytes: Vec::new(), segments: Vec::new(), patches: Vec::new() });
        Some(ctx.mods.len() - 1)
    } else {
        None
    };

    // imports -> shim thunks or DLL exports
    let (imp_rva, imp_size) = dir(1)?;
    if imp_rva != 0 && imp_size != 0 {
        for k in 0..128usize {
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
                let addr = if thunk >> 63 != 0 {
                    ctx.bind(&dll, ImportRef::Ordinal((thunk & 0xFFFF) as u32))?
                } else {
                    let name = cstr(d, rva_to_off(&secs, size_of_headers, rva_add((thunk & 0x7FFF_FFFF) as u32, 2)?, 1)?, 128)?;
                    ctx.bind(&dll, ImportRef::Name(&name))?
                };
                patches.push(Patch::Set { va: base + first as u64 + t as u64 * 8, val: addr });
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
    let tls = if tls_rva != 0 && !is_dll {
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
    if let Some(i) = idx {
        // a DLL: keep its pieces in the context; dependencies (already pushed) initialise before it
        ctx.mods[i].segments = core::mem::take(&mut segments);
        ctx.mods[i].patches = core::mem::take(&mut patches);
        ctx.init_order.push(i);
    }
    Ok(Image { entry: base.checked_add(entry_rva).ok_or(ExecError::BadRange)?, base, segments, patches, tls, idx })
}
