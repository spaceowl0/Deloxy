//! More of the Windows userland: what MSVC-built programs need to start (FLS, pointer encoding, SList, startup info,
//! version/system info), wide-character (`...W`) variants, locale/ctype stubs, Local/Global memory, console queries,
//! common C string/wide/time functions. Integer/pointer-only: the shim ABI carries no floating-point arguments.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::msvcrt::read_cstr;
use super::nt::{heap_alloc, heap_free, heap_realloc, set_err};
use crate::sys::uaccess::{copy_from_user, copy_to_user};
use crate::task::Process;

type A = [u64; 4];

fn put(p: &Arc<Process>, va: u64, b: &[u8]) {
    let _ = copy_to_user(p, va, b);
}
fn put32(p: &Arc<Process>, va: u64, v: u32) {
    put(p, va, &v.to_le_bytes());
}
fn put64(p: &Arc<Process>, va: u64, v: u64) {
    put(p, va, &v.to_le_bytes());
}
fn zero_n(p: &Arc<Process>, va: u64, n: usize) {
    put(p, va, &alloc::vec![0u8; n]);
}
fn get64(p: &Arc<Process>, va: u64) -> u64 {
    let mut b = [0u8; 8];
    let _ = copy_from_user(p, &mut b, va);
    u64::from_le_bytes(b)
}

pub fn zero(_: &Arc<Process>, _: A) -> u64 { 0 }
pub fn one(_: &Arc<Process>, _: A) -> u64 { 1 }
pub fn ret_first(_: &Arc<Process>, a: A) -> u64 { a[0] }

// ------------------------------------------------------------ wide helpers ---

/// UTF-16 string at `va` (NUL-terminated, at most `max` units).
pub fn read_wstr(p: &Arc<Process>, va: u64, max: usize) -> Vec<u16> {
    let mut v = Vec::new();
    let mut b = [0u8; 2];
    while v.len() < max && copy_from_user(p, &mut b, va + 2 * v.len() as u64).is_ok() {
        let c = u16::from_le_bytes(b);
        if c == 0 {
            break;
        }
        v.push(c);
    }
    v
}
fn to_utf8(w: &[u16]) -> String {
    String::from_utf16_lossy(w)
}
/// Per-process 8 KiB scratch (two 4 KiB halves) in user memory for wide->narrow conversion of arguments.
fn scratch(p: &Arc<Process>, half: u64) -> u64 {
    let mut f = p.foreign.lock();
    if f.wscratch == 0 {
        drop(f);
        let va = heap_alloc(p, [0, 8, 8192, 0]);
        p.foreign.lock().wscratch = va;
        return va + half * 4096;
    }
    f.wscratch + half * 4096
}
/// Convert the wide string at `wptr` to a NUL-terminated UTF-8 string in scratch half `half`; returns its address.
fn narrow(p: &Arc<Process>, wptr: u64, half: u64) -> u64 {
    if wptr == 0 {
        return 0;
    }
    let s = to_utf8(&read_wstr(p, wptr, 1000));
    let va = scratch(p, half);
    let mut b = s.into_bytes();
    b.truncate(4000);
    b.push(0);
    put(p, va, &b);
    va
}
fn write_wide(p: &Arc<Process>, va: u64, s: &str, cap_units: usize) -> usize {
    let mut w: Vec<u16> = s.encode_utf16().collect();
    w.truncate(cap_units.saturating_sub(1));
    let n = w.len();
    w.push(0);
    let mut b = Vec::with_capacity(w.len() * 2);
    for u in &w {
        b.extend_from_slice(&u.to_le_bytes());
    }
    put(p, va, &b);
    n
}

// ------------------------------------------------------------ startup / system ---

pub fn get_startup_info(p: &Arc<Process>, a: A) -> u64 {
    zero_n(p, a[0], 104);
    put32(p, a[0], 104);
    0
}
pub fn is_processor_feature_present(_: &Arc<Process>, a: A) -> u64 {
    matches!(a[0], 6 | 10 | 13) as u64 // PF_FLOATING_POINT_EMULATED=1 is *not* set; SSE2/SSE3/FP precise
}
pub fn get_system_info(p: &Arc<Process>, a: A) -> u64 {
    let mut b = [0u8; 48];
    b[0..2].copy_from_slice(&9u16.to_le_bytes()); // AMD64
    b[4..8].copy_from_slice(&4096u32.to_le_bytes());
    b[8..16].copy_from_slice(&0x10000u64.to_le_bytes());
    b[16..24].copy_from_slice(&0x7FFF_FFFE_FFFFu64.to_le_bytes());
    b[24..32].copy_from_slice(&1u64.to_le_bytes());
    b[32..36].copy_from_slice(&1u32.to_le_bytes());
    b[36..40].copy_from_slice(&8664u32.to_le_bytes());
    b[40..44].copy_from_slice(&65536u32.to_le_bytes());
    b[44..46].copy_from_slice(&6u16.to_le_bytes());
    put(p, a[0], &b);
    0
}
pub fn get_version(_: &Arc<Process>, _: A) -> u64 {
    0x4A65_000A // Windows 10.0 build 19045
}
pub fn get_version_ex(p: &Arc<Process>, a: A) -> u64 {
    let mut sz = [0u8; 4];
    let _ = copy_from_user(p, &mut sz, a[0]);
    if u32::from_le_bytes(sz) < 20 {
        return 0;
    }
    put32(p, a[0] + 4, 10);
    put32(p, a[0] + 8, 0);
    put32(p, a[0] + 12, 19045);
    put32(p, a[0] + 16, 2);
    1
}
pub fn get_computer_name(p: &Arc<Process>, a: A) -> u64 {
    put(p, a[0], b"DELOXY\0");
    put32(p, a[1], 6);
    1
}
pub fn get_user_name(p: &Arc<Process>, a: A) -> u64 {
    put(p, a[0], b"user\0");
    put32(p, a[1], 5);
    1
}
pub fn lcid(_: &Arc<Process>, _: A) -> u64 { 0x409 }
pub fn codepage(_: &Arc<Process>, _: A) -> u64 { 65001 }
pub fn get_cp_info(p: &Arc<Process>, a: A) -> u64 {
    zero_n(p, a[1], 20);
    put32(p, a[1], if a[0] == 65001 { 4 } else { 1 });
    put(p, a[1] + 4, &[b'?', 0]);
    1
}
pub fn get_console_screen_buffer_info(p: &Arc<Process>, a: A) -> u64 {
    let mut b = [0u8; 22];
    b[0..2].copy_from_slice(&80u16.to_le_bytes());
    b[2..4].copy_from_slice(&25u16.to_le_bytes());
    b[8..10].copy_from_slice(&7u16.to_le_bytes());
    b[14..16].copy_from_slice(&79u16.to_le_bytes());
    b[16..18].copy_from_slice(&24u16.to_le_bytes());
    b[18..20].copy_from_slice(&80u16.to_le_bytes());
    b[20..22].copy_from_slice(&25u16.to_le_bytes());
    put(p, a[1], &b);
    1
}
pub fn get_affinity_mask(p: &Arc<Process>, a: A) -> u64 {
    put64(p, a[1], 1);
    put64(p, a[2], 1);
    1
}
pub fn duplicate_handle(p: &Arc<Process>, a: A) -> u64 {
    let out = super::msvcrt::stack_arg(p, 3);
    if out != 0 {
        put64(p, out, a[1]);
    }
    1
}
pub fn get_proc_address(p: &Arc<Process>, a: A) -> u64 {
    use crate::exec::pe::ImportRef;
    let by_ordinal = a[1] < 0x10000;
    let name = if by_ordinal { String::new() } else { String::from_utf8_lossy(&read_cstr(p, a[1], 256)).into_owned() };
    // a DLL loaded from a file: its own export table (forwarders followed)
    let imp = if by_ordinal { ImportRef::Ordinal(a[1] as u32) } else { ImportRef::Name(&name) };
    match crate::exec::dll::proc_address(p, a[0], imp) {
        Some(Some(addr)) => return addr,
        Some(None) => {
            set_err(p, crate::exec::dll::ERROR_PROC_NOT_FOUND);
            return 0;
        }
        None => {}
    }
    if by_ordinal {
        set_err(p, crate::exec::dll::ERROR_PROC_NOT_FOUND);
        return 0;
    }
    for dll in ["msvcrt", "kernel32", "ws2_32"] {
        if let Some(addr) = super::nt::resolve(dll, &name) {
            return addr;
        }
    }
    set_err(p, crate::exec::dll::ERROR_PROC_NOT_FOUND);
    0
}
pub fn get_module_handle_w(p: &Arc<Process>, a: A) -> u64 {
    if a[0] == 0 {
        return p.foreign.lock().image_base;
    }
    match crate::exec::dll::module_handle(p, &to_utf8(&read_wstr(p, a[0], 260))) {
        Some(h) => h,
        None => {
            set_err(p, crate::exec::dll::ERROR_MOD_NOT_FOUND);
            0
        }
    }
}
pub fn get_module_handle_a(p: &Arc<Process>, a: A) -> u64 {
    if a[0] == 0 {
        return p.foreign.lock().image_base;
    }
    match crate::exec::dll::module_handle(p, &String::from_utf8_lossy(&read_cstr(p, a[0], 260))) {
        Some(h) => h,
        None => {
            set_err(p, crate::exec::dll::ERROR_MOD_NOT_FOUND);
            0
        }
    }
}
pub fn get_module_handle_ex_w(p: &Arc<Process>, a: A) -> u64 {
    let h = get_module_handle_w(p, [a[1], 0, 0, 0]);
    if a[2] != 0 {
        put64(p, a[2], h);
    }
    (h != 0) as u64
}
fn load_library_path(p: &Arc<Process>, path: &str) -> u64 {
    match crate::exec::dll::load_library(p, path) {
        Ok(h) => h,
        Err(code) => {
            set_err(p, code);
            0
        }
    }
}
pub fn load_library_a(p: &Arc<Process>, a: A) -> u64 {
    if a[0] == 0 {
        set_err(p, 87);
        return 0;
    }
    load_library_path(p, &String::from_utf8_lossy(&read_cstr(p, a[0], 260)))
}
pub fn load_library_w(p: &Arc<Process>, a: A) -> u64 {
    if a[0] == 0 {
        set_err(p, 87);
        return 0;
    }
    load_library_path(p, &to_utf8(&read_wstr(p, a[0], 260)))
}
// ------------------------------------------------------------ VirtualQuery / VirtualProtect ---

fn prot_of(f: crate::mm::vmm::VmFlags) -> u32 {
    if f.contains(crate::mm::vmm::VmFlags::EXEC) {
        if f.contains(crate::mm::vmm::VmFlags::WRITE) { 0x40 } else { 0x20 }
    } else if f.contains(crate::mm::vmm::VmFlags::WRITE) {
        0x04
    } else {
        0x02
    }
}

fn in_image(p: &Arc<Process>, va: u64) -> bool {
    let g = p.foreign.lock();
    (va >= g.image_base && va < g.brk_base_hint) || g.modules.iter().any(|m| va >= m.base && va < m.base + m.size)
}

/// VirtualQuery(addr, MEMORY_BASIC_INFORMATION*, len): the run of pages around `addr` that share one protection.
pub fn virtual_query(p: &Arc<Process>, a: A) -> u64 {
    const PAGE: u64 = 4096;
    if a[2] < 48 {
        set_err(p, 24); // ERROR_BAD_LENGTH
        return 0;
    }
    let page = a[0] & !(PAGE - 1);
    let first = { p.space.lock().as_mut().and_then(|sp| sp.query(x86_64::VirtAddr::new(page)).map(|q| q.1)) };
    let mut rec = [0u8; 48];
    match first {
        None => {
            rec[0..8].copy_from_slice(&page.to_le_bytes());
            rec[24..32].copy_from_slice(&PAGE.to_le_bytes());
            rec[32..36].copy_from_slice(&0x10000u32.to_le_bytes()); // MEM_FREE
            rec[36..40].copy_from_slice(&1u32.to_le_bytes()); // PAGE_NOACCESS
        }
        Some(f) => {
            let prot = prot_of(f);
            let mut start = page;
            let mut end = page + PAGE;
            let same = |pg: u64| p.space.lock().as_mut().and_then(|sp| sp.query(x86_64::VirtAddr::new(pg)).map(|q| prot_of(q.1))) == Some(prot);
            while end - page < 1024 * PAGE && same(end) {
                end += PAGE;
            }
            while page - start < 1024 * PAGE && start > 0 && same(start - PAGE) {
                start -= PAGE;
            }
            let ty: u32 = if in_image(p, page) { 0x0100_0000 } else { 0x0002_0000 };
            rec[0..8].copy_from_slice(&start.to_le_bytes());
            rec[8..16].copy_from_slice(&start.to_le_bytes());
            rec[16..20].copy_from_slice(&prot.to_le_bytes());
            rec[24..32].copy_from_slice(&(end - start).to_le_bytes());
            rec[32..36].copy_from_slice(&0x1000u32.to_le_bytes()); // MEM_COMMIT
            rec[36..40].copy_from_slice(&prot.to_le_bytes());
            rec[40..44].copy_from_slice(&ty.to_le_bytes());
        }
    }
    let _ = copy_to_user(p, a[1], &rec);
    48
}

/// VirtualProtect(addr, size, newProtect, *oldProtect). W^X: PAGE_EXECUTE_READWRITE is honoured only for pages that
/// are already executable image code (self-patching such as MinGW's pseudo-relocations); elsewhere it means RW.
pub fn virtual_protect(p: &Arc<Process>, a: A) -> u64 {
    use crate::mm::vmm::VmFlags;
    const PAGE: u64 = 4096;
    let (addr, size, new) = (a[0], a[1].max(1), a[2] as u32);
    let first = addr & !(PAGE - 1);
    let last = (addr + size - 1) & !(PAGE - 1);
    if (last - first) / PAGE > 4096 {
        set_err(p, 87);
        return 0;
    }
    let mut old = 0u32;
    let mut pg = first;
    while pg <= last {
        let cur = { p.space.lock().as_mut().and_then(|sp| sp.query(x86_64::VirtAddr::new(pg)).map(|q| q.1)) };
        let Some(cur) = cur else {
            set_err(p, 487); // ERROR_INVALID_ADDRESS
            return 0;
        };
        if pg == first {
            old = prot_of(cur);
        }
        let want = match new & 0xFF {
            0x01 | 0x02 => VmFlags::USER,
            0x04 | 0x08 => VmFlags::USER | VmFlags::WRITE,
            0x10 | 0x20 | 0x80 => VmFlags::USER | VmFlags::EXEC,
            0x40 => {
                if cur.contains(VmFlags::EXEC) && in_image(p, pg) {
                    VmFlags::USER | VmFlags::WRITE | VmFlags::EXEC
                } else {
                    VmFlags::USER | VmFlags::WRITE
                }
            }
            _ => {
                set_err(p, 87);
                return 0;
            }
        };
        // never turn data pages executable
        let want = if want.contains(VmFlags::EXEC) && !cur.contains(VmFlags::EXEC) && !in_image(p, pg) {
            if want.contains(VmFlags::WRITE) { VmFlags::USER | VmFlags::WRITE } else { VmFlags::USER }
        } else {
            want
        };
        if p.space.lock().as_mut().map_or(true, |sp| sp.protect(x86_64::VirtAddr::new(pg), want).is_err()) {
            set_err(p, 5);
            return 0;
        }
        pg += PAGE;
    }
    if a[3] != 0 {
        let _ = copy_to_user(p, a[3], &old.to_le_bytes());
    }
    1
}

pub fn free_library(p: &Arc<Process>, a: A) -> u64 {
    if crate::exec::dll::free_library(p, a[0]) {
        1
    } else {
        set_err(p, crate::exec::dll::ERROR_INVALID_HANDLE);
        0
    }
}

// ------------------------------------------------------------ exceptions / SList ---

pub fn raise_exception(p: &Arc<Process>, a: A) -> u64 {
    log::warn!("win: RaiseException({:#x}) - unhandled, terminating", a[0]);
    super::nt::exit_process(p, [0xE06D7363, 0, 0, 0])
}
pub fn rtl_capture_context(p: &Arc<Process>, a: A) -> u64 {
    zero_n(p, a[0], 0x4D0);
    0
}
pub fn init_slist(p: &Arc<Process>, a: A) -> u64 {
    zero_n(p, a[0], 16);
    0
}
/// Singly linked list head: first u64 is the top entry; each entry's first u64 is its next pointer.
pub fn slist_push(p: &Arc<Process>, a: A) -> u64 {
    let top = get64(p, a[0]);
    put64(p, a[1], top);
    put64(p, a[0], a[1]);
    top
}
pub fn slist_pop(p: &Arc<Process>, a: A) -> u64 {
    let top = get64(p, a[0]);
    if top != 0 {
        let next = get64(p, top);
        put64(p, a[0], next);
    }
    top
}
pub fn slist_flush(p: &Arc<Process>, a: A) -> u64 {
    let top = get64(p, a[0]);
    put64(p, a[0], 0);
    top
}
pub fn interlocked_and(p: &Arc<Process>, a: A) -> u64 {
    let mut b = [0u8; 4];
    let _ = copy_from_user(p, &mut b, a[0]);
    let old = u32::from_le_bytes(b);
    put32(p, a[0], old & a[1] as u32);
    old as u64
}
pub fn interlocked_or(p: &Arc<Process>, a: A) -> u64 {
    let mut b = [0u8; 4];
    let _ = copy_from_user(p, &mut b, a[0]);
    let old = u32::from_le_bytes(b);
    put32(p, a[0], old | a[1] as u32);
    old as u64
}

// ------------------------------------------------------------ memory ---

pub fn local_alloc(p: &Arc<Process>, a: A) -> u64 {
    heap_alloc(p, [0, if a[0] & 0x40 != 0 { 8 } else { 0 }, a[1], 0])
}
pub fn local_free(p: &Arc<Process>, a: A) -> u64 {
    heap_free(p, a[0]);
    0
}
pub fn local_realloc(p: &Arc<Process>, a: A) -> u64 {
    heap_realloc(p, [0, 0, a[0], a[1]])
}

// ------------------------------------------------------------ wide kernel32 ---

pub fn get_command_line_w(p: &Arc<Process>, _: A) -> u64 {
    if let Some(v) = p.foreign.lock().cmdline_w {
        return v;
    }
    let cva = p.foreign.lock().cmdline_va;
    let cmd = String::from_utf8_lossy(&read_cstr(p, cva, 8192)).into_owned();
    let va = heap_alloc(p, [0, 8, (cmd.len() as u64 + 1) * 2, 0]);
    write_wide(p, va, &cmd, cmd.len() + 1);
    p.foreign.lock().cmdline_w = Some(va);
    va
}
pub fn get_environment_strings_w(p: &Arc<Process>, _: A) -> u64 {
    heap_alloc(p, [0, 8, 8, 0]) // an empty block: just the double NUL
}
pub fn get_environment_variable_w(p: &Arc<Process>, _: A) -> u64 {
    set_err(p, 203);
    0
}
pub fn write_console_w(p: &Arc<Process>, a: A) -> u64 {
    let s = to_utf8(&read_wstr(p, a[1], a[2] as usize));
    let va = scratch(p, 1);
    let mut b = s.into_bytes();
    b.truncate(4000);
    let n = b.len();
    put(p, va, &b);
    super::win32::write_file(p, [a[0], va, n as u64, a[3]])
}
pub fn create_file_w(p: &Arc<Process>, a: A) -> u64 {
    super::win32::create_file(p, [narrow(p, a[0], 0), a[1], a[2], a[3]])
}
pub fn get_file_attributes_w(p: &Arc<Process>, a: A) -> u64 {
    super::win32::get_file_attributes(p, [narrow(p, a[0], 0), 0, 0, 0])
}
pub fn delete_file_w(p: &Arc<Process>, a: A) -> u64 {
    super::win32::delete_file(p, [narrow(p, a[0], 0), 0, 0, 0])
}
pub fn create_directory_w(p: &Arc<Process>, a: A) -> u64 {
    super::win32::create_directory(p, [narrow(p, a[0], 0), 0, 0, 0])
}
pub fn remove_directory_w(p: &Arc<Process>, a: A) -> u64 {
    super::win32::remove_directory(p, [narrow(p, a[0], 0), 0, 0, 0])
}
pub fn move_file_w(p: &Arc<Process>, a: A) -> u64 {
    super::win32::move_file(p, [narrow(p, a[0], 0), narrow(p, a[1], 1), 0, 0])
}
pub fn get_module_file_name_w(p: &Arc<Process>, a: A) -> u64 {
    let tmp = scratch(p, 1);
    let n = super::win32::get_module_file_name(p, [a[0], tmp, 260, 0]);
    let s = String::from_utf8_lossy(&read_cstr(p, tmp, 260)).into_owned();
    let _ = n;
    write_wide(p, a[1], &s, a[2] as usize) as u64
}
pub fn get_full_path_name_a(p: &Arc<Process>, a: A) -> u64 {
    let s = read_cstr(p, a[0], 1024);
    if (a[1] as usize) <= s.len() {
        return s.len() as u64 + 1;
    }
    let mut b = s.clone();
    b.push(0);
    put(p, a[2], &b);
    if a[3] != 0 {
        put64(p, a[3], 0);
    }
    s.len() as u64
}
pub fn get_file_size_ex(p: &Arc<Process>, a: A) -> u64 {
    let lo = super::win32::get_file_size(p, [a[0], 0, 0, 0]) as u32;
    if lo == 0xFFFF_FFFF {
        return 0;
    }
    put64(p, a[1], lo as u64);
    1
}
pub fn set_file_pointer_ex(p: &Arc<Process>, a: A) -> u64 {
    let r = super::win32::set_file_pointer(p, [a[0], a[1] & 0xFFFF_FFFF, 0, a[3]]);
    if r == 0xFFFF_FFFF {
        return 0;
    }
    if a[2] != 0 {
        put64(p, a[2], r);
    }
    1
}

// ------------------------------------------------------------ ctype / locale (wide) ---

pub fn get_string_type_w(p: &Arc<Process>, a: A) -> u64 {
    let n = if a[2] as i32 == -1 { read_wstr(p, a[1], 1 << 16).len() + 1 } else { (a[2] as usize).min(1 << 16) };
    let w = {
        let mut v = Vec::with_capacity(n);
        let mut b = [0u8; 2];
        for i in 0..n {
            if copy_from_user(p, &mut b, a[1] + 2 * i as u64).is_err() {
                return 0;
            }
            v.push(u16::from_le_bytes(b));
        }
        v
    };
    let mut out = Vec::with_capacity(n * 2);
    for c in w {
        let ch = char::from_u32(c as u32).unwrap_or('\0');
        let mut f = 0u16;
        if ch.is_uppercase() { f |= 1 | 0x100; }
        if ch.is_lowercase() { f |= 2 | 0x100; }
        if ch.is_alphabetic() { f |= 0x100; }
        if ch.is_ascii_digit() { f |= 4; }
        if ch.is_whitespace() { f |= 8; }
        if ch.is_ascii_punctuation() { f |= 0x10; }
        if ch.is_control() { f |= 0x20; }
        if ch == ' ' || ch == '\t' { f |= 0x40; }
        if ch.is_ascii_hexdigit() { f |= 0x80; }
        out.extend_from_slice(&f.to_le_bytes());
    }
    put(p, a[3], &out);
    1
}
/// LCMapStringW(locale, flags, src, cchSrc, dst, cchDst): lower/upper case (ASCII + Unicode simple mapping).
pub fn lc_map_string_w(p: &Arc<Process>, a: A) -> u64 {
    let cch = super::msvcrt::stack_arg(p, 4) as i32;
    let dst = super::msvcrt::stack_arg(p, 4 + 0); // 5th argument
    let _ = (dst, cch);
    let src_cch = a[3] as i32;
    let src = read_wstr(p, a[2], if src_cch < 0 { 1 << 16 } else { src_cch as usize });
    let n = src.len() + if src_cch < 0 { 1 } else { 0 };
    let cap = super::msvcrt::stack_arg(p, 5) as i32;
    let dstp = super::msvcrt::stack_arg(p, 4);
    if cap == 0 {
        return n as u64;
    }
    if (cap as usize) < n {
        set_err(p, 122);
        return 0;
    }
    let mut out = Vec::new();
    for c in src.iter() {
        let ch = char::from_u32(*c as u32).unwrap_or('\0');
        let m = if a[1] & 0x200 != 0 { ch.to_uppercase().next().unwrap_or(ch) } else if a[1] & 0x100 != 0 { ch.to_lowercase().next().unwrap_or(ch) } else { ch };
        out.extend_from_slice(&(m as u32 as u16).to_le_bytes());
    }
    if src_cch < 0 {
        out.extend_from_slice(&[0, 0]);
    }
    put(p, dstp, &out);
    n as u64
}

// ------------------------------------------------------------ C runtime extras ---

fn cstr_at(p: &Arc<Process>, va: u64) -> Vec<u8> {
    read_cstr(p, va, 16 << 20)
}
pub fn strncat(p: &Arc<Process>, a: A) -> u64 {
    let d = cstr_at(p, a[0]);
    let s = read_cstr(p, a[1], a[2] as usize);
    let mut b = s;
    b.push(0);
    put(p, a[0] + d.len() as u64, &b);
    a[0]
}
pub fn strpbrk(p: &Arc<Process>, a: A) -> u64 {
    let s = cstr_at(p, a[0]);
    let set = read_cstr(p, a[1], 256);
    s.iter().position(|c| set.contains(c)).map_or(0, |i| a[0] + i as u64)
}
pub fn strtok(p: &Arc<Process>, a: A) -> u64 {
    let start = if a[0] != 0 { a[0] } else { p.foreign.lock().strtok_save };
    if start == 0 {
        return 0;
    }
    let delim = read_cstr(p, a[1], 256);
    let s = cstr_at(p, start);
    let Some(b) = s.iter().position(|c| !delim.contains(c)) else {
        p.foreign.lock().strtok_save = 0;
        return 0;
    };
    let rest = &s[b..];
    let e = rest.iter().position(|c| delim.contains(c)).unwrap_or(rest.len());
    let tok = start + b as u64;
    if e < rest.len() {
        put(p, tok + e as u64, &[0]);
        p.foreign.lock().strtok_save = tok + e as u64 + 1;
    } else {
        p.foreign.lock().strtok_save = 0;
    }
    tok
}
pub fn strlwr(p: &Arc<Process>, a: A) -> u64 {
    let mut s = cstr_at(p, a[0]);
    s.make_ascii_lowercase();
    put(p, a[0], &s);
    a[0]
}
pub fn strupr(p: &Arc<Process>, a: A) -> u64 {
    let mut s = cstr_at(p, a[0]);
    s.make_ascii_uppercase();
    put(p, a[0], &s);
    a[0]
}
pub fn labs(_: &Arc<Process>, a: A) -> u64 {
    (a[0] as i64).unsigned_abs()
}
pub fn lstrcmpi(p: &Arc<Process>, a: A) -> u64 {
    let (x, y) = (cstr_at(p, a[0]).to_ascii_lowercase(), cstr_at(p, a[1]).to_ascii_lowercase());
    match x.cmp(&y) { core::cmp::Ordering::Less => u64::MAX, core::cmp::Ordering::Equal => 0, _ => 1 }
}
/// itoa family: (value, buf, radix)
fn itoa_impl(p: &Arc<Process>, v: i128, buf: u64, radix: u32) -> u64 {
    let radix = radix.clamp(2, 36) as i128;
    let neg = v < 0 && radix == 10;
    let mut u = if neg { -v } else { v } as u128;
    let mut d = Vec::new();
    if u == 0 {
        d.push(b'0');
    }
    while u > 0 {
        d.push(b"0123456789abcdefghijklmnopqrstuvwxyz"[(u % radix as u128) as usize]);
        u /= radix as u128;
    }
    if neg {
        d.push(b'-');
    }
    d.reverse();
    d.push(0);
    put(p, buf, &d);
    buf
}
pub fn itoa(p: &Arc<Process>, a: A) -> u64 {
    itoa_impl(p, a[0] as u32 as i32 as i128, a[1], a[2] as u32)
}
pub fn ultoa(p: &Arc<Process>, a: A) -> u64 {
    itoa_impl(p, a[0] as u32 as i128, a[1], a[2] as u32)
}
pub fn i64toa(p: &Arc<Process>, a: A) -> u64 {
    itoa_impl(p, a[0] as i64 as i128, a[1], a[2] as u32)
}
pub fn ui64toa(p: &Arc<Process>, a: A) -> u64 {
    itoa_impl(p, a[0] as i128, a[1], a[2] as u32)
}
pub fn getpid(p: &Arc<Process>, _: A) -> u64 {
    p.pid as u64
}

// wide string functions
fn wcmp(x: &[u16], y: &[u16], fold: bool) -> u64 {
    let f = |c: u16| if fold { char::from_u32(c as u32).and_then(|c| c.to_lowercase().next()).map_or(c, |c| c as u32 as u16) } else { c };
    for (i, a) in x.iter().enumerate() {
        match y.get(i) {
            None => return 1,
            Some(b) if f(*a) != f(*b) => return if f(*a) < f(*b) { u64::MAX } else { 1 },
            _ => {}
        }
    }
    if y.len() > x.len() { u64::MAX } else { 0 }
}
pub fn wcscmp(p: &Arc<Process>, a: A) -> u64 {
    wcmp(&read_wstr(p, a[0], 1 << 20), &read_wstr(p, a[1], 1 << 20), false)
}
pub fn wcsicmp(p: &Arc<Process>, a: A) -> u64 {
    wcmp(&read_wstr(p, a[0], 1 << 20), &read_wstr(p, a[1], 1 << 20), true)
}
pub fn wcsncmp(p: &Arc<Process>, a: A) -> u64 {
    let n = a[2] as usize;
    let (x, y) = (read_wstr(p, a[0], n), read_wstr(p, a[1], n));
    wcmp(&x, &y, false)
}
fn put_wide_units(p: &Arc<Process>, va: u64, w: &[u16], term: bool) {
    let mut b = Vec::with_capacity(w.len() * 2 + 2);
    for u in w {
        b.extend_from_slice(&u.to_le_bytes());
    }
    if term {
        b.extend_from_slice(&[0, 0]);
    }
    put(p, va, &b);
}
pub fn wcscpy(p: &Arc<Process>, a: A) -> u64 {
    put_wide_units(p, a[0], &read_wstr(p, a[1], 1 << 20), true);
    a[0]
}
pub fn wcsncpy(p: &Arc<Process>, a: A) -> u64 {
    let n = a[2] as usize;
    let mut s = read_wstr(p, a[1], n);
    s.resize(n, 0);
    put_wide_units(p, a[0], &s, false);
    a[0]
}
pub fn wcscat(p: &Arc<Process>, a: A) -> u64 {
    let d = read_wstr(p, a[0], 1 << 20);
    put_wide_units(p, a[0] + 2 * d.len() as u64, &read_wstr(p, a[1], 1 << 20), true);
    a[0]
}
pub fn wcschr(p: &Arc<Process>, a: A) -> u64 {
    let s = read_wstr(p, a[0], 1 << 20);
    if a[1] as u16 == 0 {
        return a[0] + 2 * s.len() as u64;
    }
    s.iter().position(|c| *c == a[1] as u16).map_or(0, |i| a[0] + 2 * i as u64)
}
pub fn wcsrchr(p: &Arc<Process>, a: A) -> u64 {
    let s = read_wstr(p, a[0], 1 << 20);
    s.iter().rposition(|c| *c == a[1] as u16).map_or(0, |i| a[0] + 2 * i as u64)
}
pub fn wcsstr(p: &Arc<Process>, a: A) -> u64 {
    let h = read_wstr(p, a[0], 1 << 20);
    let n = read_wstr(p, a[1], 1 << 16);
    if n.is_empty() {
        return a[0];
    }
    h.windows(n.len()).position(|w| w == &n[..]).map_or(0, |i| a[0] + 2 * i as u64)
}
pub fn towlower(_: &Arc<Process>, a: A) -> u64 {
    char::from_u32(a[0] as u32).and_then(|c| c.to_lowercase().next()).map_or(a[0], |c| c as u64)
}
pub fn towupper(_: &Arc<Process>, a: A) -> u64 {
    char::from_u32(a[0] as u32).and_then(|c| c.to_uppercase().next()).map_or(a[0], |c| c as u64)
}
pub fn iswalpha(_: &Arc<Process>, a: A) -> u64 {
    char::from_u32(a[0] as u32).map_or(false, |c| c.is_alphabetic()) as u64
}
pub fn iswdigit(_: &Arc<Process>, a: A) -> u64 {
    char::from_u32(a[0] as u32).map_or(false, |c| c.is_ascii_digit()) as u64
}
pub fn iswspace(_: &Arc<Process>, a: A) -> u64 {
    char::from_u32(a[0] as u32).map_or(false, |c| c.is_whitespace()) as u64
}
pub fn isgraph(_: &Arc<Process>, a: A) -> u64 {
    (a[0] as u32 > 0x20 && (a[0] as u32) < 0x7F) as u64
}
pub fn isascii(_: &Arc<Process>, a: A) -> u64 {
    ((a[0] as u32) < 0x80) as u64
}

// ------------------------------------------------------------ time ---

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}
/// struct tm (9 ints) for a time_t, written to a per-process static buffer.
fn tm_for(p: &Arc<Process>, t: i64) -> u64 {
    let days = t.div_euclid(86400);
    let rem = t.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let yday = days - days_from_civil(y, 1, 1);
    let wday = (days + 4).rem_euclid(7);
    let buf = {
        let existing = p.foreign.lock().tm_buf;
        if existing != 0 { existing } else {
            let v = heap_alloc(p, [0, 8, 64, 0]);
            p.foreign.lock().tm_buf = v;
            v
        }
    };
    let f = [(rem % 60) as i32, ((rem / 60) % 60) as i32, (rem / 3600) as i32, d as i32, m as i32 - 1, (y - 1900) as i32, wday as i32, yday as i32, 0];
    let mut b = Vec::new();
    for v in f {
        b.extend_from_slice(&v.to_le_bytes());
    }
    put(p, buf, &b);
    buf
}
pub fn gmtime(p: &Arc<Process>, a: A) -> u64 {
    tm_for(p, get64(p, a[0]) as i64)
}
pub fn mktime(p: &Arc<Process>, a: A) -> u64 {
    let mut b = [0u8; 24];
    let _ = copy_from_user(p, &mut b, a[0]);
    let g = |i: usize| i32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap()) as i64;
    let (mut y, mut mon) = (g(5) + 1900, g(4));
    y += mon.div_euclid(12);
    mon = mon.rem_euclid(12);
    let days = days_from_civil(y, mon as u32 + 1, 1) + g(3) - 1;
    (days * 86400 + g(2) * 3600 + g(1) * 60 + g(0)) as u64
}
pub fn strftime(p: &Arc<Process>, a: A) -> u64 {
    let fmt = String::from_utf8_lossy(&read_cstr(p, a[2], 256)).into_owned();
    let mut b = [0u8; 36];
    let _ = copy_from_user(p, &mut b, a[3]);
    let g = |i: usize| i32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
    const MON: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const DAY: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let mut out = String::new();
    let mut it = fmt.chars();
    while let Some(c) = it.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('Y') => out += &alloc::format!("{}", g(5) + 1900),
            Some('y') => out += &alloc::format!("{:02}", (g(5) + 1900) % 100),
            Some('m') => out += &alloc::format!("{:02}", g(4) + 1),
            Some('d') => out += &alloc::format!("{:02}", g(3)),
            Some('H') => out += &alloc::format!("{:02}", g(2)),
            Some('M') => out += &alloc::format!("{:02}", g(1)),
            Some('S') => out += &alloc::format!("{:02}", g(0)),
            Some('b') => out += MON[(g(4).rem_euclid(12)) as usize],
            Some('a') => out += DAY[(g(6).rem_euclid(7)) as usize],
            Some('j') => out += &alloc::format!("{:03}", g(7) + 1),
            Some('F') => out += &alloc::format!("{}-{:02}-{:02}", g(5) + 1900, g(4) + 1, g(3)),
            Some('T') => out += &alloc::format!("{:02}:{:02}:{:02}", g(2), g(1), g(0)),
            Some('%') => out.push('%'),
            Some(o) => { out.push('%'); out.push(o); }
            None => break,
        }
    }
    if out.len() + 1 > a[1] as usize {
        return 0;
    }
    let mut ob = out.clone().into_bytes();
    ob.push(0);
    put(p, a[0], &ob);
    out.len() as u64
}
pub fn wcslen_(p: &Arc<Process>, a: A) -> u64 {
    read_wstr(p, a[0], 1 << 20).len() as u64
}

/// _aligned_malloc(size, align): blocks are 16-byte aligned already; larger alignments over-allocate (never recycled).
pub fn aligned_malloc(p: &Arc<Process>, a: A) -> u64 {
    let align = a[1].max(16);
    if align == 16 {
        return heap_alloc(p, [0, 0, a[0], 0]);
    }
    if !align.is_power_of_two() {
        return 0;
    }
    let raw = heap_alloc(p, [0, 0, a[0] + align, 0]);
    if raw == 0 { 0 } else { (raw + align - 1) & !(align - 1) }
}
pub fn aligned_free(p: &Arc<Process>, a: A) -> u64 {
    heap_free(p, a[0]); // ignored when it is not the start of a block
    0
}

// ------------------------------------------------------------ randomness ---

fn fill_user(p: &Arc<Process>, va: u64, len: u64) -> bool {
    let mut b = alloc::vec![0u8; (len as usize).min(1 << 20)];
    crate::rand::fill(&mut b);
    copy_to_user(p, va, &b).is_ok()
}
/// RtlGenRandom / SystemFunction036(buf, len) -> BOOLEAN
pub fn rtl_gen_random(p: &Arc<Process>, a: A) -> u64 {
    fill_user(p, a[0], a[1] as u32 as u64) as u64
}
/// BCryptGenRandom(hAlg, buf, len, flags) -> NTSTATUS (0 = success)
pub fn bcrypt_gen_random(p: &Arc<Process>, a: A) -> u64 {
    if fill_user(p, a[1], a[2] as u32 as u64) { 0 } else { 0xC000_0005 }
}
/// CryptGenRandom(hProv, len, buf) -> BOOL
pub fn crypt_gen_random(p: &Arc<Process>, a: A) -> u64 {
    fill_user(p, a[2], a[1] as u32 as u64) as u64
}
/// CryptAcquireContextA/W(phProv, ...): hand out a dummy provider handle
pub fn crypt_acquire_context(p: &Arc<Process>, a: A) -> u64 {
    if a[0] != 0 {
        put64(p, a[0], 0xC0DE_0001);
    }
    1
}
/// rand_s(unsigned *out) -> errno_t
pub fn rand_s(p: &Arc<Process>, a: A) -> u64 {
    let v = crate::rand::next_u64() as u32;
    put32(p, a[0], v);
    0
}
