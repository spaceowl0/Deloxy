//! deloxy-sh: the Deloxy shell (native ELF, ring 3). Everything it can do comes from capabilities it
//! was started with: a Tty (I/O), a Dir (initramfs), Spawn, Sys, Power, NetAdmin and an AuditStream.
#![no_std]
#![no_main]

use core::fmt::Write;

#[path = "../../common/sys.rs"]
mod sys;
use sys::*;

#[link_section = ".note.deloxy"]
#[used]
static NOTE: [u32; 5] = [7, 0, 1, u32::from_le_bytes(*b"Delo"), u32::from_le_bytes(*b"xy\0\0")];

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(255)
}

struct Caps {
    tty: u64,
    dir: u64,
    spawn: u64,
    sys: u64,
    power: u64,
    netadmin: u64,
    audit: u64,
    store: u64,
    policy: u64,
}

const VERSION: &str = "Deloxy v0.1.0-alpha";

fn line(out: &mut Out, caps: &Caps, buf: &mut [u8; 200]) -> usize {
    let mut n = 0;
    let mut esc = 0u8;
    loop {
        let mut c = [0u8; 1];
        if tty_read(caps.tty, &mut c, u64::MAX) <= 0 {
            continue;
        }
        let c = c[0];
        if esc == 1 {
            esc = if c == b'[' || c == b'O' { 2 } else { 0 };
            continue;
        }
        if esc == 2 {
            if (0x40..=0x7E).contains(&c) {
                esc = 0;
            }
            continue;
        }
        match c {
            0x1B => esc = 1,
            b'\r' | b'\n' => {
                out.write_str("\n").ok();
                out.flush();
                return n;
            }
            0x7F | 0x08 => {
                if n > 0 {
                    n -= 1;
                    out.write_str("\x08 \x08").ok();
                    out.flush();
                }
            }
            0x03 => {
                out.write_str("^C\n").ok();
                out.flush();
                return 0;
            }
            0x15 => {
                while n > 0 {
                    n -= 1;
                    out.write_str("\x08 \x08").ok();
                }
                out.flush();
            }
            0x20..=0x7E if n < buf.len() => {
                buf[n] = c;
                n += 1;
                out.write_str(core::str::from_utf8(&[c]).unwrap_or("?")).ok();
                out.flush();
            }
            _ => {}
        }
    }
}

/// Open a file by name: the read-only initramfs first, then the persistent store.
fn open(caps: &Caps, name: &str) -> i64 {
    // SAFETY: pointer/len describe a live string.
    let r = unsafe { sc(SYS_FS_OPEN, caps.dir, name.as_ptr() as u64, name.len() as u64, 0, 0, 0) };
    if r >= 0 || caps.store == 0 {
        return r;
    }
    // SAFETY: as above.
    let s = unsafe { sc(SYS_STORE_OPEN, caps.store, name.as_ptr() as u64, name.len() as u64, 0, 0, 0) };
    // no store disk (ENODEV) or no such file in the store (ENOENT): report the original initramfs result
    if s == -2 || s == -19 { r } else { s }
}

fn open_msg(e: i64) -> &'static str {
    match -e {
        2 => "not found",
        5 => "I/O error or checksum mismatch (file damaged)",
        _ => "cannot open",
    }
}

fn store_msg(e: i64) -> &'static str {
    match -e {
        1 => "not permitted (reserved name)",
        2 => "not found",
        5 => "I/O error or checksum mismatch",
        19 => "no store disk (attach one, or run 'format' if the disk is blank)",
        22 => "invalid name (letters, digits and . _ - + only, max 47)",
        27 => "file too large (max 4 MiB)",
        28 => "no space left (or too many files)",
        9 => "bad capability",
        _ => "error",
    }
}

fn cmd_ls(o: &mut Out, caps: &Caps) {
    let mut i = 0;
    loop {
        let mut name = [0u8; 100];
        // SAFETY: `name` is a live 100-byte buffer.
        let r = unsafe { sc(SYS_FS_LIST, caps.dir, i, name.as_mut_ptr() as u64, 100, 0, 0) };
        if r < 0 {
            break;
        }
        let (len, size) = ((r & 0xFF) as usize, r >> 8);
        writeln!(o, "{:>8}  {}", size, core::str::from_utf8(&name[..len]).unwrap_or("?")).ok();
        i += 1;
    }
    if i == 0 {
        writeln!(o, "(empty)").ok();
    }
    if caps.store != 0 {
        let mut j = 0;
        loop {
            let mut name = [0u8; 64];
            // SAFETY: `name` is a live 64-byte buffer.
            let r = unsafe { sc(SYS_STORE_LIST, caps.store, j, name.as_mut_ptr() as u64, 64, 0, 0) };
            if r == -19 {
                break;
            }
            if r < 0 {
                if j == 0 {
                    writeln!(o, "store: (empty)").ok();
                }
                break;
            }
            let (len, size) = ((r & 0xFF) as usize, r >> 8);
            writeln!(o, "{:>8}  {}   [store]", size, core::str::from_utf8(&name[..len]).unwrap_or("?")).ok();
            j += 1;
        }
    }
}

fn store_write(caps: &Caps, name: &str, data: &[u8]) -> i64 {
    // SAFETY: both pointers describe live slices.
    unsafe { sc(SYS_STORE_WRITE, caps.store, name.as_ptr() as u64, name.len() as u64, data.as_ptr() as u64, data.len() as u64, 0) }
}

fn cmd_save(o: &mut Out, caps: &Caps, args: &str) {
    let (name, text) = args.split_once(' ').unwrap_or((args, ""));
    if name.is_empty() {
        writeln!(o, "usage: save <name> <text...>").ok();
        return;
    }
    let r = store_write(caps, name, text.as_bytes());
    if r < 0 {
        writeln!(o, "save: {}: {}", name, store_msg(r)).ok();
    } else {
        writeln!(o, "saved {} bytes to {}", text.len(), name).ok();
    }
}

/// perms | perms allow NAME rw|r|none | perms revoke NAME   (application permissions, enforced by the kernel)
fn cmd_perms(o: &mut Out, caps: &Caps, args: &str) {
    if caps.policy == 0 {
        writeln!(o, "perms: no policy capability").ok();
        return;
    }
    let mut it = args.split(' ').filter(|p| !p.is_empty());
    match it.next() {
        None => {
            let mut i = 0;
            loop {
                let mut rec = [0u8; 80];
                // SAFETY: `rec` is a live 80-byte buffer.
                let r = unsafe { sc(SYS_PERM, caps.policy, 0, i, 0, rec.as_mut_ptr() as u64, 0) };
                if r < 0 {
                    break;
                }
                let n = rec[..40].iter().position(|&b| b == 0).unwrap_or(40);
                let fl = rec[56];
                if rec[58] == 1 {
                    let any = rec[66] & 1 != 0;
                    let secs = u32::from_le_bytes([rec[68], rec[69], rec[70], rec[71]]);
                    let kib = u32::from_le_bytes([rec[72], rec[73], rec[74], rec[75]]);
                    let nm = core::str::from_utf8(&rec[..n]).unwrap_or("?");
                    let hh = core::str::from_utf8(&rec[40..56]).unwrap_or("?");
                    if any {
                        write!(o, "{:<24} {} net ANY HOST{}", nm, hh, if rec[66] & 2 != 0 { " (internet only)" } else { "" }).ok();
                    } else if rec[60..64] == [0, 0, 0, 0] {
                        let port = u16::from_le_bytes([rec[64], rec[65]]);
                        if port == 0 {
                            write!(o, "{:<24} {} net DNS lookups", nm, hh).ok();
                        } else {
                            write!(o, "{:<24} {} net LISTEN port {}", nm, hh, port).ok();
                        }
                    } else {
                        write!(o, "{:<24} {} net {}.{}.{}.{}:{}", nm, hh, rec[60], rec[61], rec[62], rec[63], u16::from_le_bytes([rec[64], rec[65]])).ok();
                    }
                    if secs == 0 && kib == 0 {
                        write!(o, " no limits").ok();
                    } else {
                        write!(o, " limit: ").ok();
                        if secs == 0 { write!(o, "time unlimited").ok(); } else { write!(o, "{} s", secs).ok(); }
                        if kib == 0 { write!(o, ", data unlimited").ok(); } else { write!(o, ", {} KiB", kib).ok(); }
                    }
                    writeln!(o, " {}", if fl & 1 != 0 { "ALLOWED" } else { "DENIED" }).ok();
                    i += 1;
                    continue;
                }
                writeln!(
                    o,
                    "{:<24} {} files: {}{}{}{}",
                    core::str::from_utf8(&rec[..n]).unwrap_or("?"),
                    core::str::from_utf8(&rec[40..56]).unwrap_or("?"),
                    if fl & 1 != 0 { "read " } else { "" },
                    if fl & 2 != 0 { "write " } else { "" },
                    if fl == 0 { "DENIED" } else { "" },
                    if rec[57] != 0 { " (once)" } else { "" }
                )
                .ok();
                i += 1;
            }
            if i == 0 {
                writeln!(o, "no stored decisions (programs are asked on their first file access)").ok();
            }
        }
        Some("revoke") => {
            let Some(name) = it.next() else {
                writeln!(o, "usage: perms revoke <program>").ok();
                return;
            };
            // SAFETY: pointer/len describe a live string.
            let r = unsafe { sc(SYS_PERM, caps.policy, 2, name.as_ptr() as u64, name.len() as u64, 0, 0) };
            if r < 0 {
                writeln!(o, "perms: {}: no stored decision", name).ok();
            } else {
                writeln!(o, "revoked: {} will be asked again", name).ok();
            }
        }
        Some("net") => {
            // perms net <program> <a.b.c.d:port|any> allow|deny [time=30s|10m|2h|unlimited] [data=500K|64M|2G|unlimited] [nolan]
            const USAGE: &str = "usage: perms net <program> <ip:port|any|dns|listen:PORT> allow|deny [time=30s|10m|2h|unlimited] [data=500K|64M|2G|unlimited] [nolan]";
            let (Some(name), Some(dest), Some(mode)) = (it.next(), it.next(), it.next()) else {
                writeln!(o, "{}", USAGE).ok();
                return;
            };
            if mode != "allow" && mode != "deny" {
                writeln!(o, "{}", USAGE).ok();
                return;
            }
            let mut st = [0u8; 16];
            let any = dest == "any";
            let special = dest == "dns" || dest.starts_with("listen:");
            if dest == "dns" {
                // 0.0.0.0:0
            } else if let Some(pn) = dest.strip_prefix("listen:") {
                let Ok(portn) = pn.parse::<u16>() else {
                    writeln!(o, "bad port").ok();
                    return;
                };
                if portn == 0 {
                    writeln!(o, "bad port").ok();
                    return;
                }
                st[4..6].copy_from_slice(&portn.to_le_bytes());
            } else if !any {
                let Some((ip, port)) = dest.rsplit_once(':') else {
                    writeln!(o, "destination must be a.b.c.d:port, any, dns or listen:PORT").ok();
                    return;
                };
                let mut parts = 0;
                for (k, seg) in ip.split('.').enumerate() {
                    let Ok(v) = seg.parse::<u8>() else { parts = 99; break };
                    if k < 4 {
                        st[k] = v;
                    }
                    parts += 1;
                }
                let Ok(portn) = port.parse::<u16>() else {
                    writeln!(o, "bad port").ok();
                    return;
                };
                if parts != 4 || portn == 0 {
                    writeln!(o, "destination must be a.b.c.d:port, any, dns or listen:PORT").ok();
                    return;
                }
                st[4..6].copy_from_slice(&portn.to_le_bytes());
            }
            // limits: defaults = unlimited for 'any' (full access), 10 min / 64 MiB for one host
            let (mut secs, mut kib): (u32, u32) = if any || special { (0, 0) } else { (600, 64 * 1024) };
            let mut flags = any as u8;
            for opt in it {
                if let Some(v) = opt.strip_prefix("time=") {
                    if v == "unlimited" {
                        secs = 0;
                    } else {
                        let (num, unit) = match v.char_indices().last() {
                            Some((i, c)) if !c.is_ascii_digit() => (&v[..i], c),
                            _ => (v, 's'),
                        };
                        let Ok(n) = num.parse::<u32>() else {
                            writeln!(o, "bad time: {}", v).ok();
                            return;
                        };
                        secs = n.saturating_mul(match unit { 'm' => 60, 'h' => 3600, _ => 1 });
                    }
                } else if let Some(v) = opt.strip_prefix("data=") {
                    if v == "unlimited" {
                        kib = 0;
                    } else {
                        let (num, unit) = match v.char_indices().last() {
                            Some((i, c)) if !c.is_ascii_digit() => (&v[..i], c.to_ascii_uppercase()),
                            _ => (v, 'M'),
                        };
                        let Ok(n) = num.parse::<u32>() else {
                            writeln!(o, "bad data size: {}", v).ok();
                            return;
                        };
                        kib = n.saturating_mul(match unit { 'K' => 1, 'G' => 1024 * 1024, _ => 1024 });
                    }
                } else if opt == "nolan" {
                    flags |= 2;
                } else {
                    writeln!(o, "unknown option: {}", opt).ok();
                    return;
                }
            }
            st[6] = (mode == "allow") as u8;
            st[7] = flags;
            st[8..12].copy_from_slice(&secs.to_le_bytes());
            st[12..16].copy_from_slice(&kib.to_le_bytes());
            // SAFETY: pointer/len describe a live string; `st` is a live 16-byte buffer.
            let r = unsafe { sc(SYS_PERM, caps.policy, 3, name.as_ptr() as u64, name.len() as u64, st.as_ptr() as u64, 0) };
            if r < 0 {
                writeln!(o, "perms: {}: no such program", name).ok();
            } else {
                writeln!(o, "{}: {} to {} ({}, {})", name, if mode == "allow" { "connections allowed" } else { "connections denied" }, dest,
                    if secs == 0 { "no time limit" } else { "time limited" }, if kib == 0 { "no data limit" } else { "data capped" }).ok();
            }
        }
        Some("allow") => {
            let (Some(name), Some(mode)) = (it.next(), it.next()) else {
                writeln!(o, "usage: perms allow <program> rw|r|none").ok();
                return;
            };
            let flags = match mode {
                "rw" => 3,
                "r" => 1,
                "none" => 0,
                _ => {
                    writeln!(o, "mode must be rw, r or none").ok();
                    return;
                }
            };
            // SAFETY: pointer/len describe a live string.
            let r = unsafe { sc(SYS_PERM, caps.policy, 1, name.as_ptr() as u64, name.len() as u64, flags, 0) };
            if r < 0 {
                writeln!(o, "perms: {}: no such program", name).ok();
            } else {
                writeln!(o, "{}: file access set to {}", name, mode).ok();
            }
        }
        Some(_) => {
            writeln!(o, "usage: perms | perms allow <program> rw|r|none | perms net <program> <ip:port|any> allow|deny [time=..] [data=..] [nolan] | perms revoke <program>").ok();
        }
    }
}

fn cmd_rm(o: &mut Out, caps: &Caps, name: &str) {
    // SAFETY: pointer/len describe a live string.
    let r = unsafe { sc(SYS_STORE_CTL, caps.store, 0, name.as_ptr() as u64, name.len() as u64, 0, 0) };
    if r < 0 {
        writeln!(o, "rm: {}: {}", name, store_msg(r)).ok();
    } else {
        writeln!(o, "removed {}", name).ok();
    }
}

fn cmd_df(o: &mut Out, caps: &Caps) {
    let mut b = [0u8; 40];
    // SAFETY: `b` is a live 40-byte buffer.
    let r = unsafe { sc(SYS_STORE_CTL, caps.store, 1, 0, 0, b.as_mut_ptr() as u64, 0) };
    if r < 0 {
        writeln!(o, "df: {}", store_msg(r)).ok();
        return;
    }
    let w = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    writeln!(o, "store: {} KiB data area, {} KiB used, {} KiB free, {} file(s), generation {}", w(1) / 1024, w(2) / 1024, (w(1) - w(2)) / 1024, w(3), w(4)).ok();
}

fn cmd_format(o: &mut Out, caps: &Caps) {
    writeln!(o, "This ERASES everything on the store disk. Type 'yes' to continue:").ok();
    write!(o, "> ").ok();
    o.flush();
    let mut lb = [0u8; 200];
    let n = line(o, caps, &mut lb);
    if &lb[..n] != b"yes" {
        writeln!(o, "format cancelled").ok();
        return;
    }
    // SAFETY: integer arguments only.
    let r = unsafe { sc(SYS_STORE_CTL, caps.store, 2, 0, 0, 0, 0) };
    if r < 0 {
        writeln!(o, "format: {}", store_msg(r)).ok();
    } else {
        writeln!(o, "store formatted").ok();
    }
}

/// `cp <src> <dst>`: copy an initramfs or store file into the store (up to 1 MiB in this shell).
fn cmd_cp(o: &mut Out, caps: &Caps, args: &str) {
    let mut it = args.split(' ').filter(|p| !p.is_empty());
    let (Some(src), Some(dst)) = (it.next(), it.next()) else {
        writeln!(o, "usage: cp <src> <dst>   (dst is created in the store)").ok();
        return;
    };
    let f = open(caps, src);
    if f < 0 {
        writeln!(o, "cp: {}: not found (error {})", src, -f).ok();
        return;
    }
    const CAP: usize = 1 << 20;
    // SAFETY: anonymous mapping request; the result is checked.
    let m = unsafe { sc(SYS_MMAP_ANON, CAP as u64, 0, 0, 0, 0, 0) };
    if m <= 0 {
        writeln!(o, "cp: out of memory").ok();
        cap_drop(f as u64);
        return;
    }
    // SAFETY: the kernel mapped CAP writable bytes at `m` for this process.
    let buf = unsafe { core::slice::from_raw_parts_mut(m as *mut u8, CAP) };
    let mut off = 0usize;
    loop {
        // SAFETY: the destination range lies inside `buf`.
        let n = unsafe { sc(SYS_FILE_READ, f as u64, off as u64, buf.as_mut_ptr().add(off) as u64, 4096.min(CAP - off) as u64, 0, 0) };
        if n <= 0 {
            break;
        }
        off += n as usize;
        if off == CAP {
            writeln!(o, "cp: {} is larger than 1 MiB", src).ok();
            cap_drop(f as u64);
            return;
        }
    }
    cap_drop(f as u64);
    let r = store_write(caps, dst, &buf[..off]);
    if r < 0 {
        writeln!(o, "cp: {}: {}", dst, store_msg(r)).ok();
    } else {
        writeln!(o, "copied {} bytes to {}", off, dst).ok();
    }
}

fn cmd_cat(o: &mut Out, caps: &Caps, name: &str) {
    let f = open(caps, name);
    if f < 0 {
        writeln!(o, "cat: {}: {} (error {})", name, open_msg(f), -f).ok();
        return;
    }
    let mut off = 0u64;
    loop {
        let mut b = [0u8; 256];
        // SAFETY: `b` is a live 256-byte buffer.
        let n = unsafe { sc(SYS_FILE_READ, f as u64, off, b.as_mut_ptr() as u64, 256, 0, 0) };
        if n <= 0 {
            break;
        }
        for x in b[..n as usize].iter_mut() {
            if !(*x == b'\n' || (0x20..0x7F).contains(x)) {
                *x = b'.';
            }
        }
        tty_write(o.h, &b[..n as usize]);
        off += n as u64;
    }
    cap_drop(f as u64);
}

fn cmd_run(o: &mut Out, caps: &Caps, args: &str) {
    let name = args.split(' ').next().unwrap_or("");
    if name.is_empty() {
        writeln!(o, "usage: run <file> [args...]").ok();
        return;
    }
    let f = open(caps, name);
    if f < 0 {
        writeln!(o, "run: {}: {} (error {})", name, open_msg(f), -f).ok();
        return;
    }
    let mut a = [0u8; 200];
    let mut n = 0;
    for part in args.split(' ').filter(|p| !p.is_empty()) {
        for &c in part.as_bytes() {
            a[n] = c;
            n += 1;
        }
        a[n] = 0;
        n += 1;
    }
    let mut err = [0u8; 120];
    // SAFETY: all pointers describe live buffers of the stated sizes.
    let p = unsafe { sc(SYS_PROC_SPAWN, caps.spawn, f as u64, a.as_ptr() as u64, n as u64, err.as_mut_ptr() as u64, err.len() as u64) };
    cap_drop(f as u64);
    if p < 0 {
        let e = err.iter().position(|&c| c == 0).unwrap_or(0);
        writeln!(o, "run: cannot start {}: {}", name, core::str::from_utf8(&err[..e]).unwrap_or("?")).ok();
        return;
    }
    let mut code = [0u8; 8];
    // SAFETY: `code` is a live 8-byte buffer.
    unsafe { sc(SYS_PROC_WAIT, p as u64, code.as_mut_ptr() as u64, 0, 0, 0, 0) };
    cap_drop(p as u64);
    writeln!(o, "[exit {}]", i64::from_le_bytes(code)).ok();
}

fn cmd_ps(o: &mut Out, caps: &Caps) {
    writeln!(o, "PID  ABI     THR STATE   NAME").ok();
    let mut i = 0;
    loop {
        let mut r = [0u8; 64];
        // SAFETY: `r` is a live 64-byte buffer.
        if unsafe { sc(SYS_PROC_LIST, caps.sys, i, r.as_mut_ptr() as u64, 0, 0, 0) } < 0 {
            break;
        }
        let pid = u64::from_le_bytes(r[0..8].try_into().unwrap());
        let thr = u32::from_le_bytes(r[8..12].try_into().unwrap());
        let abi = ["native", "linux", "nt"].get(r[12] as usize).copied().unwrap_or("?");
        let nl = r[16..].iter().position(|&c| c == 0).unwrap_or(47);
        let mem = u32::from_le_bytes(r[56..60].try_into().unwrap());
        writeln!(o, "{:<4} {:<7} {:<3} {:<7} {}  [{} KiB]", pid, abi, thr, if r[13] != 0 { "exited" } else { "running" }, core::str::from_utf8(&r[16..16 + nl.min(39)]).unwrap_or("?"), mem).ok();
        i += 1;
    }
}

fn cmd_caps(o: &mut Out) {
    writeln!(o, "HANDLE            KIND       RIGHTS").ok();
    let mut i = 0;
    while let Some(c) = cap_list(i) {
        writeln!(o, "{:#018x} {:<10} {:#06x}", c.handle, kind_name(c.kind), c.rights).ok();
        i += 1;
    }
}

fn cmd_audit(o: &mut Out, caps: &Caps, arg: &str) {
    let want: u64 = arg.trim().parse().unwrap_or(10).min(32).max(1);
    let mut b = [0u8; 64 * 8];
    // SAFETY: `b` is a live 512-byte buffer (8 records).
    let n = unsafe { sc(SYS_AUDIT_READ, caps.audit, b.as_mut_ptr() as u64, want.min(8), 0, 0, 0) };
    if n <= 0 {
        writeln!(o, "(no pending audit events)").ok();
        return;
    }
    writeln!(o, "SEQ      PID  KIND SYSNO       RESULT  ARG0").ok();
    for i in 0..n as usize {
        let e = &b[i * 64..i * 64 + 64];
        let kind = u16::from_le_bytes(e[16..18].try_into().unwrap());
        let sysno = u32::from_le_bytes(e[20..24].try_into().unwrap());
        let res = i64::from_le_bytes(e[24..32].try_into().unwrap());
        let arg0 = u64::from_le_bytes(e[40..48].try_into().unwrap());
        let pid = u32::from_le_bytes(e[8..12].try_into().unwrap());
        let seq = u64::from_le_bytes(e[56..64].try_into().unwrap());
        let kn = match kind {
            1 => "syscall",
            2 => "CAP-DENIED",
            3 => "spawn",
            4 => "exit",
            5 => "fault",
            6 => "net-allow",
            7 => "NET-DENY",
            _ => "?",
        };
        writeln!(o, "{:<8} {:<4} {:<10} {:<#10x} {:<7} {:#x}", seq, pid, kn, sysno, res, arg0).ok();
    }
}

fn parse_ip(s: &str) -> Option<u32> {
    let mut v = 0u32;
    let mut n = 0;
    for p in s.split('.') {
        v = (v << 8) | p.parse::<u8>().ok()? as u32;
        n += 1;
    }
    if n == 4 { Some(v) } else { None }
}

fn cmd_upd(o: &mut Out, caps: &Caps, args: &str) {
    let mut it = args.split(' ').filter(|p| !p.is_empty());
    let sub = it.next().unwrap_or("");
    let op = match sub {
        "check" => 0u16,
        "stage" => 1u16,
        _ => {
            writeln!(o, "usage: upd check|stage [ip port path]   (default 10.0.2.2 8777 /ok)").ok();
            return;
        }
    };
    let ipstr = it.next().unwrap_or("10.0.2.2");
    let port: u64 = it.next().map_or(Some(8777), |p| p.parse().ok()).unwrap_or(0);
    let base = it.next().unwrap_or("/ok");
    let Some(ip) = parse_ip(ipstr) else {
        writeln!(o, "upd: bad ip address").ok();
        return;
    };
    if port == 0 || port > 65535 || base.len() > 64 {
        writeln!(o, "upd: bad port or path").ok();
        return;
    }
    writeln!(o, "deloxy-upd needs network access. Grant a NetGrant for tcp {}:{} for 60 s (max 1 MiB)?", ipstr, port).ok();
    write!(o, "Allow? [y/N] ").ok();
    o.flush();
    let mut lb = [0u8; 200];
    let n = line(o, caps, &mut lb);
    if !(n >= 1 && (lb[0] == b'y' || lb[0] == b'Y')) {
        writeln!(o, "denied: no grant issued, the network stays off").ok();
        return;
    }
    // SAFETY: integer arguments only.
    let g = unsafe { sc(SYS_NET_GRANT, caps.netadmin, ip as u64, port, 60, 1 << 20, 0) };
    if g < 0 {
        writeln!(o, "upd: grant failed ({})", -g).ok();
        return;
    }
    let mut req = [0u8; 256];
    req[0..4].copy_from_slice(&ip.to_be_bytes());
    req[4..6].copy_from_slice(&(port as u16).to_le_bytes());
    req[6..8].copy_from_slice(&op.to_le_bytes());
    req[8..12].copy_from_slice(&(base.len() as u32).to_le_bytes());
    req[24..24 + base.len()].copy_from_slice(base.as_bytes());
    // SAFETY: `req` is a live 256-byte buffer.
    let r = unsafe { sc(SYS_UPD, g as u64, req.as_mut_ptr() as u64, 0, 0, 0, 0) };
    cap_drop(g as u64); // dropping the last reference to the grant switches the NIC off again
    if r < 0 {
        writeln!(o, "upd: failed ({})", -r).ok();
        return;
    }
    let code = i32::from_le_bytes(req[12..16].try_into().unwrap());
    let ml = req[88..].iter().position(|&c| c == 0).unwrap_or(0);
    let msg = core::str::from_utf8(&req[88..88 + ml]).unwrap_or("?");
    if code == 0 {
        writeln!(o, "upd: OK: {}", msg).ok();
    } else {
        writeln!(o, "upd: REJECTED (code {}): {}", code, msg).ok();
    }
}

fn help(o: &mut Out) {
    writeln!(o, "builtins: help version echo ls cat <f> run <f> [args] ps caps audit [n]").ok();
    writeln!(o, "security: perms [allow <prog> rw|r|none | net <prog> <ip:port|any> allow|deny [time=..] [data=..] [nolan] | revoke <prog>]").ok();
    writeln!(o, "store:    df  save <name> <text>  cp <src> <dst>  rm <name>  format   (persistent disk; ls/cat/run see it too)").ok();
    writeln!(o, "          upd check|stage [ip port path]   reboot   poweroff").ok();
    writeln!(o, "try: run hello_win.exe | run hello_linux.elf | run monitor.elf 1").ok();
}

#[no_mangle]
#[link_section = ".text._start"]
pub unsafe extern "C" fn _start() -> ! {
    let caps = Caps {
        tty: find_cap(12),
        dir: find_cap(9),
        spawn: find_cap(11),
        sys: find_cap(13),
        power: find_cap(14),
        netadmin: find_cap(8),
        audit: find_cap(4),
        store: find_cap(16),
        policy: find_cap(18),
    };
    let mut o = Out::new(caps.tty);
    writeln!(o, "{} - type 'help'", VERSION).ok();
    loop {
        write!(o, "deloxy-sh> ").ok();
        o.flush();
        let mut lb = [0u8; 200];
        let n = line(&mut o, &caps, &mut lb);
        let text = core::str::from_utf8(&lb[..n]).unwrap_or("").trim();
        let (cmd, rest) = match text.split_once(' ') {
            Some((c, r)) => (c, r.trim()),
            None => (text, ""),
        };
        match cmd {
            "" => {}
            "help" => help(&mut o),
            "version" => {
                writeln!(o, "{}", VERSION).ok();
            }
            "echo" => {
                writeln!(o, "{}", rest).ok();
            }
            "ls" => cmd_ls(&mut o, &caps),
            "cat" => cmd_cat(&mut o, &caps, rest),
            "run" => cmd_run(&mut o, &caps, rest),
            "ps" => cmd_ps(&mut o, &caps),
            "caps" => cmd_caps(&mut o),
            "audit" => cmd_audit(&mut o, &caps, rest),
            "upd" => cmd_upd(&mut o, &caps, rest),
            "perms" => cmd_perms(&mut o, &caps, rest),
            "df" => cmd_df(&mut o, &caps),
            "save" => cmd_save(&mut o, &caps, rest),
            "cp" => cmd_cp(&mut o, &caps, rest),
            "rm" => cmd_rm(&mut o, &caps, rest),
            "format" => cmd_format(&mut o, &caps),
            "poweroff" | "reboot" => {
                o.flush();
                sc(SYS_POWER, caps.power, (cmd == "reboot") as u64, 0, 0, 0, 0);
            }
            _ => {
                writeln!(o, "unknown command '{}' (try 'help')", cmd).ok();
            }
        }
        o.flush();
    }
}
