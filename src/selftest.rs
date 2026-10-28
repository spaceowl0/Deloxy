//! In-kernel self tests, run with `--features selftest`. Exit code via QEMU
//! isa-debug-exit: 0x10 -> QEMU status 33 (pass), 0x11 -> 35 (fail).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use log::info;
use x86_64::structures::paging::PhysFrame;
use x86_64::VirtAddr;

use crate::mm::layout::*;
use crate::mm::vmm::{self, AddressSpace, KernelStack, VmFlags};
use crate::mm::{frame, heap};

pub static TEST_PF_ADDR: AtomicU64 = AtomicU64::new(0);

macro_rules! check {
    ($c:expr, $($m:tt)*) => {
        if !$c {
            log::error!("SELFTEST FAIL: {}", format_args!($($m)*));
            crate::arch::x86_64::qemu_exit(0x11);
        }
    };
}

/// M2 tests: run on the boot context before the scheduler starts.
pub fn run_mm() {
    test_heap();
    test_frames();
    test_vmm();
    test_user_space();
    test_stack();
}

/// M3 tests: run inside a kernel thread under the live scheduler.
pub fn run_tasks() {
    test_tick_rate();
    test_preemption();
    test_sleep();
    test_user_programs();
    test_ring_stress();
    test_ring_overflow();
    test_caps_and_audit();
    test_ipc();
    test_exec_poc();
    test_exec_failures();
    test_exec_fuzz();
    test_pci();
    test_firewall();
    test_updater();
    test_initramfs();
    test_net_grants_any();
    test_store_logic();
    test_store_device();
    #[cfg(feature = "net-test")]
    test_net_integration();
    test_shell();
    #[cfg(feature = "test-pf")]
    test_pf();
    info!("SELFTEST PASS");
    crate::arch::x86_64::qemu_exit(0x10)
}

fn test_heap() {
    let before = heap::stats();
    {
        let b = Box::new([0xABu8; 4096]);
        check!(b.iter().all(|&x| x == 0xAB), "box contents");

        let mut v: Vec<u64> = Vec::new();
        for i in 0..100_000u64 {
            v.push(i);
        }
        check!(v.iter().sum::<u64>() == 100_000 * 99_999 / 2, "vec sum");

        let s = Arc::new(spin::Mutex::new(String::from("deloxy")));
        let s2 = s.clone();
        s2.lock().push_str(" heap ok");
        check!(s.lock().as_str() == "deloxy heap ok", "arc<string>");
        check!(Arc::strong_count(&s) == 2, "arc count");

        // Force heap growth beyond the initial 1 MiB.
        let big = vec![7u8; 4 << 20];
        check!(big[(4 << 20) - 1] == 7, "big vec");
        let mid = heap::stats();
        check!(mid.mapped > before.mapped, "heap did not grow");
        info!("heap grew {} KiB -> {} KiB", before.mapped / 1024, mid.mapped / 1024);
    }
    let after = heap::stats();
    check!(after.used == before.used, "heap leak: used {} -> {}", before.used, after.used);
    info!("heap ok: used={} mapped={} KiB", after.used, after.mapped / 1024);
}

fn test_frames() {
    let (_, free0) = frame::stats();
    let mut fr: [Option<PhysFrame>; 64] = [None; 64];
    for slot in fr.iter_mut() {
        *slot = frame::allocate_frame();
        check!(slot.is_some(), "frame alloc");
    }
    for i in 0..64 {
        for j in i + 1..64 {
            check!(fr[i] != fr[j], "duplicate frame");
        }
    }
    for f in fr.iter().flatten() {
        check!(frame::deallocate_frame(*f), "dealloc");
    }
    let (_, free1) = frame::stats();
    check!(free0 == free1, "frame leak {} -> {}", free0, free1);
    info!("frames ok ({} free)", free1);
}

fn test_vmm() {
    let va = VirtAddr::new(KERNEL_SCRATCH);
    let mut ks = vmm::kernel_space().lock();
    check!(ks.map_anon(va, 4, VmFlags::WRITE).is_ok(), "map_anon");
    // SAFETY: 4 pages at KERNEL_SCRATCH were just mapped RW.
    unsafe {
        for i in 0..(4 * PAGE_SIZE) as usize {
            (KERNEL_SCRATCH as *mut u8).add(i).write_volatile((i & 0xFF) as u8);
        }
        check!((KERNEL_SCRATCH as *const u8).add(4097).read_volatile() == (4097 & 0xFF) as u8, "readback");
    }
    check!(ks.translate(va).is_some(), "translate");
    check!(ks.protect(va, VmFlags::NONE).is_ok(), "protect");
    check!(ks.map_anon(va, 1, VmFlags::WRITE) == Err(vmm::VmError::AlreadyMapped), "double map");
    for i in 0..4 {
        check!(ks.unmap_free(va + i * PAGE_SIZE).is_ok(), "unmap");
    }
    check!(ks.translate(va).is_none(), "still mapped");
    check!(ks.unmap(va) == Err(vmm::VmError::NotMapped), "unmap unmapped");
    check!(ks.map_anon(VirtAddr::new(USER_START), 1, VmFlags::WRITE).is_err(), "kernel map in user range");
    info!("vmm ok");
}

fn test_user_space() {
    let (_, free0) = frame::stats();
    let mut a = AddressSpace::new_user().expect("new_user");
    let uva = VirtAddr::new(USER_START + 0x10_0000);
    check!(a.map_anon(uva, 2, VmFlags::WRITE | VmFlags::USER).is_ok(), "user map");
    check!(a.translate(uva).is_some(), "user translate");
    check!(a.map_anon(VirtAddr::new(KERNEL_SCRATCH), 1, VmFlags::WRITE | VmFlags::USER).is_err(), "user map in kernel range");
    for i in 0..2 {
        check!(a.unmap_free(uva + i * PAGE_SIZE).is_ok(), "user unmap");
    }
    a.destroy();
    let (_, free1) = frame::stats();
    check!(free0 == free1, "user space leak {} -> {}", free0, free1);
    info!("user address space ok");
}

fn test_stack() {
    let s = KernelStack::new(4).expect("stack");
    {
        let mut ks = vmm::kernel_space().lock();
        check!(ks.translate(s.guard_addr()).is_none(), "guard page mapped");
        check!(ks.translate(s.top() - 8u64).is_some(), "stack top unmapped");
    }
    // SAFETY: top-8 lies in the freshly mapped, writable stack.
    unsafe { ((s.top().as_u64() - 8) as *mut u64).write_volatile(0xDEAD_BEEF) };
    drop(s);
    info!("kernel stack + guard ok");
}

#[cfg(feature = "test-pf")]
fn test_pf() {
    let s = KernelStack::new(1).expect("stack");
    let g = s.guard_addr().as_u64();
    TEST_PF_ADDR.store(g, Ordering::SeqCst);
    core::mem::forget(s);
    info!("provoking #PF on guard page {:#x}", g);
    // SAFETY: intentionally faults; the #PF handler recognises TEST_PF_ADDR and exits QEMU.
    unsafe { (g as *mut u8).write_volatile(1) };
    log::error!("SELFTEST FAIL: no #PF on guard page");
    crate::arch::x86_64::qemu_exit(0x11);
}

// ------------------------------------------------------------ M3 tests -----

fn test_tick_rate() {
    let t0 = crate::time::ticks();
    for _ in 0..4 {
        crate::arch::x86_64::apic::pit_delay_ms(50);
    }
    let dt = crate::time::ticks() - t0;
    info!("timer: {} ticks during 200 ms of PIT time", dt);
    check!((160..=240).contains(&dt), "tick rate off: {} ticks per 200 ms", dt);
}

static STOP: AtomicBool = AtomicBool::new(false);
static COUNTS: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

fn test_preemption() {
    let sw0 = crate::task::sched::context_switches();
    for i in 0..3 {
        crate::task::spawn_kernel("busy", move || {
            // Never yields: only preemption can let the other threads (and the
            // sleeping test thread) run.
            while !STOP.load(Ordering::Relaxed) {
                COUNTS[i].fetch_add(1, Ordering::Relaxed);
            }
        })
        .expect("spawn");
    }
    crate::task::sleep_ms(300);
    STOP.store(true, Ordering::SeqCst);
    crate::task::sleep_ms(30);
    let c: [u64; 3] = [
        COUNTS[0].load(Ordering::Relaxed),
        COUNTS[1].load(Ordering::Relaxed),
        COUNTS[2].load(Ordering::Relaxed),
    ];
    let sw = crate::task::sched::context_switches() - sw0;
    info!("preemption: busy counters {:?}, {} context switches in ~330 ms", c, sw);
    check!(c.iter().all(|&x| x > 0), "a busy thread was starved: {:?}", c);
    check!(sw >= 30, "too few context switches: {}", sw);
    let (min, max) = (*c.iter().min().unwrap(), *c.iter().max().unwrap());
    check!(max < min * 4, "unfair scheduling: {:?}", c);
}

fn test_sleep() {
    let t0 = crate::time::uptime_ms();
    crate::task::sleep_ms(500);
    let dt = crate::time::uptime_ms() - t0;
    info!("sleep_ms(500) took {} ms", dt);
    check!((500..=520).contains(&dt), "sleep drift: {} ms", dt);
}

fn run_blob(name: &str, image: &[u8]) -> i64 {
    let p = crate::task::spawn_user(name, image).expect("spawn_user");
    let code = crate::task::wait_process(&p);
    info!("process '{}' (pid {}) exited with {}", name, p.pid, code);
    code
}

fn test_user_programs() {
    use crate::sys::errno::*;
    use crate::task::blobs;

    check!(run_blob("hello", blobs::HELLO) == 42, "hello exit code");
    check!(run_blob("sysmix", blobs::SYSMIX) == 0, "sysmix (mmap/munmap/getpid) exit code");
    check!(run_blob("thread", blobs::THREAD) == 7, "thread test exit code");

    // Faulting programs must die alone; the kernel keeps running.
    check!(run_blob("nullptr", blobs::NULLPTR) == EXIT_FAULT_PF, "null deref must give #PF kill");
    check!(run_blob("priv", blobs::PRIV) == EXIT_FAULT_GP, "cli in ring 3 must give #GP kill");

    // No frame leaks across a full process lifecycle (after one warm-up run).
    crate::task::sleep_ms(50);
    let (_, free0) = frame::stats();
    check!(run_blob("hello", blobs::HELLO) == 42, "hello (2nd)");
    check!(run_blob("nullptr", blobs::NULLPTR) == EXIT_FAULT_PF, "nullptr (2nd)");
    crate::task::sleep_ms(50);
    let (_, free1) = frame::stats();
    check!(free0 == free1, "process lifecycle leaked frames: {} -> {}", free0, free1);
    info!("user programs ok (no frame leak)");
}

// ------------------------------------------------------------ M4 tests -----

use crate::audit::{self, EV_CAP_DENIED};
use crate::cap::{CapObject, Rights};
use crate::ipc::ring::Spsc;
use crate::task::{blobs, InitSpec};

static STRESS: Spsc<u64, 1024> = Spsc::new();
static STRESS_DONE: AtomicU64 = AtomicU64::new(0);
static STRESS_ERR: AtomicU64 = AtomicU64::new(0);
const STRESS_N: u64 = 1_000_000;

fn test_ring_stress() {
    let t0 = crate::time::uptime_ms();
    crate::task::spawn_kernel("ring-producer", || {
        for i in 0..STRESS_N {
            while STRESS.try_push(i).is_none() {
                crate::task::yield_now();
            }
        }
    })
    .expect("spawn");
    crate::task::spawn_kernel("ring-consumer", || {
        let mut expect = 0u64;
        while expect < STRESS_N {
            match STRESS.pop() {
                Some(v) => {
                    if v != expect {
                        STRESS_ERR.fetch_add(1, Ordering::SeqCst);
                        expect = v;
                    }
                    expect += 1;
                }
                None => crate::task::yield_now(),
            }
        }
        STRESS_DONE.store(expect, Ordering::SeqCst);
    })
    .expect("spawn");
    while STRESS_DONE.load(Ordering::SeqCst) == 0 {
        crate::task::sleep_ms(5);
    }
    let dt = crate::time::uptime_ms() - t0;
    check!(STRESS_ERR.load(Ordering::SeqCst) == 0, "ring reordered/lost items");
    check!(STRESS_DONE.load(Ordering::SeqCst) == STRESS_N, "ring lost items");
    info!("spsc ring: {} items in order, none lost ({} ms)", STRESS_N, dt);
}

fn test_ring_overflow() {
    let r: Spsc<u32, 8> = Spsc::new();
    let mut accepted = 0;
    for i in 0..20u32 {
        if r.push_lossy(i) {
            accepted += 1;
        }
    }
    check!(accepted == 8 && r.dropped() == 12, "overflow accounting: accepted {} dropped {}", accepted, r.dropped());
    check!(r.pop() == Some(0), "oldest item first");
    check!(r.push_lossy(99), "space after pop");
    info!("spsc overflow: non-blocking, dropped={}", r.dropped());
}

fn spawn_role(name: &str, role: u64, n: u64, side: u64, caps: alloc::vec::Vec<(CapObject, Rights)>) -> alloc::sync::Arc<crate::task::Process> {
    crate::task::spawn_process(name, blobs::UTEST, Some(InitSpec { role, n, side, caps })).expect("spawn_process")
}

fn test_caps_and_audit() {
    // Drain stale events so we only look at this process's.
    while audit::pop().is_some() {}
    let p = spawn_role(
        "captest",
        0,
        0,
        0,
        alloc::vec![
            (CapObject::IoPort { base: 0x3F8, len: 8 }, Rights::IO | Rights::READ | Rights::DUP),
            (CapObject::IoPort { base: 0x3F8, len: 8 }, Rights::READ),
        ],
    );
    let code = crate::task::wait_process(&p);
    check!(code == 0, "captest failed at step {}", code);

    let mut denied_eperm = 0;
    let mut denied_ebadf = 0;
    while let Some(ev) = audit::pop() {
        if ev.kind == EV_CAP_DENIED && ev.pid as u64 == p.pid {
            if ev.result == -crate::sys::errno::EPERM {
                denied_eperm += 1;
            }
            if ev.result == -crate::sys::errno::EBADF {
                denied_ebadf += 1;
            }
        }
    }
    info!("captest pid {}: audited denials EPERM={} EBADF={}, drops={}", p.pid, denied_eperm, denied_ebadf, audit::dropped());
    check!(denied_eperm >= 4, "missing EPERM audit events ({})", denied_eperm);
    check!(denied_ebadf >= 4, "missing EBADF audit events ({})", denied_ebadf);

    let p2 = spawn_role(
        "audit-reader",
        1,
        0,
        0,
        alloc::vec![(CapObject::AuditStream, Rights::AUDIT_READ), (CapObject::AuditStream, Rights::READ)],
    );
    check!(crate::task::wait_process(&p2) == 0, "audit reader failed");
    info!("capabilities + audit ok");
}

fn test_ipc() {
    const N: u64 = 100_000;
    let (a, b) = crate::ipc::create_channel().expect("channel");
    let rw = Rights::READ | Rights::WRITE | Rights::MAP;
    let t0 = crate::time::uptime_ms();
    let cons = spawn_role("ipc-consumer", 3, N, 1, alloc::vec![(b, rw)]);
    let prod = spawn_role("ipc-producer", 2, N, 0, alloc::vec![(a, rw)]);
    let pc = crate::task::wait_process(&prod);
    let cc = crate::task::wait_process(&cons);
    let dt = (crate::time::uptime_ms() - t0).max(1);
    check!(pc == 0, "producer exit {}", pc);
    check!(cc == 0, "consumer exit {}", cc);
    info!("ipc: {} messages of 64 B between two processes in {} ms (~{} msg/s), zero-copy shared rings", N, dt, N * 1000 / dt);
    drop((prod, cons));
    crate::task::sleep_ms(50);
    info!("ipc ok");
}

// ------------------------------------------------------------ M6 tests -----

use crate::exec::{self, SpawnOpts};

fn captured(p: &alloc::sync::Arc<crate::task::Process>) -> alloc::string::String {
    let f = p.foreign.lock();
    alloc::string::String::from_utf8_lossy(&f.out[..f.out_len]).into_owned()
}

fn run_exec(name: &str, image: &[u8], args: &[&str], console: bool) -> (i64, alloc::string::String) {
    let p = match exec::spawn(name, image, &SpawnOpts { args, console, caps: &[], foreign_caps: &[] }) {
        Ok(p) => p,
        Err(e) => {
            log::error!("SELFTEST FAIL: spawn '{}' failed: {}", name, e);
            crate::arch::x86_64::qemu_exit(0x11);
        }
    };
    let code = crate::task::wait_process(&p);
    let out = captured(&p);
    info!("exec '{}' [{}]: exit {} output {:?}", name, p.abi().name(), code, out.trim_end());
    (code, out)
}

fn test_exec_poc() {
    let (c, _) = run_exec("hello_native", blobs::HELLO_NATIVE_ELF, &[], false);
    check!(c == 0, "native ELF exit code {}", c);

    let (c, out) = run_exec("hello_linux", blobs::HELLO_LINUX_ELF, &["/bin/hello_linux", "alpha"], true);
    check!(c == 0, "linux ELF exit code {}", c);
    check!(out.starts_with("Hello from Linux ELF"), "linux ELF greeting missing");
    check!(out.contains("argc=2 argv0=/bin/hello_linux"), "linux ELF argv missing: {}", out);
    check!(out.contains("uname: Linux"), "linux uname missing");

    let (c, out) = run_exec("hello_linux_pie", blobs::HELLO_LINUX_PIE, &["hello_linux_pie"], true);
    check!(c == 0, "static-pie ELF exit code {}", c);
    check!(out.starts_with("Hello from Linux ELF"), "static-pie greeting missing");

    let (c, out) = run_exec("hello_win.exe", blobs::HELLO_WIN_EXE, &["hello_win.exe", "/test"], true);
    check!(c == 0, "PE exit code {}", c);
    check!(out.starts_with("Hello from Windows PE"), "PE greeting missing");
    check!(out.contains("cmdline: hello_win.exe /test"), "PE command line missing: {}", out);
    info!("exec: native ELF, Linux ELF, static-pie ELF and Windows PE all ran");
}

fn test_exec_failures() {
    // 1. unknown import -> named load error, nothing runs
    let mut pe: alloc::vec::Vec<u8> = alloc::vec::Vec::from(blobs::HELLO_WIN_EXE);
    let needle = b"ExitProcess";
    let at = pe.windows(needle.len()).position(|w| w == needle).expect("ExitProcess in import table");
    pe[at + needle.len() - 1] = b'X'; // ExitProcesX
    match exec::build("bad-import", &pe, &SpawnOpts { args: &[], console: true, caps: &[], foreign_caps: &[] }) {
        Err(crate::exec::ExecError::UnresolvedImport { dll, name }) => {
            info!("unknown import rejected cleanly: unimplemented: {}!{}", dll, name);
            check!(name == "ExitProcesX", "wrong name {}", name);
        }
        Err(e) => check!(false, "wrong error for unknown import: {}", e),
        Ok(_) => check!(false, "unknown import accepted"),
    }
    // 2. no Console capability -> stdout write denied, program reports exit code 3, audit shows denial
    while audit::pop().is_some() {}
    let p = exec::spawn("no-console", blobs::HELLO_LINUX_ELF, &SpawnOpts { args: &["x"], console: false, caps: &[], foreign_caps: &[] }).expect("spawn");
    let code = crate::task::wait_process(&p);
    check!(code == 3, "no-console process exit {} (expected 3)", code);
    let mut denied = 0;
    while let Some(ev) = audit::pop() {
        if ev.pid as u64 == p.pid && ev.kind == EV_CAP_DENIED {
            denied += 1;
        }
    }
    check!(denied >= 1, "write without Console capability was not audited as a denial");
    // 3. garbage and wrong-architecture input
    check!(exec::build("garbage", b"hello world, not a binary at all", &SpawnOpts { args: &[], console: false, caps: &[], foreign_caps: &[] }).is_err(), "garbage accepted");
    info!("exec failures ok (unknown import, missing console cap, garbage)");
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn test_exec_fuzz() {
    const ITER: usize = 10_000;
    let corpus: [&[u8]; 4] = [blobs::HELLO_NATIVE_ELF, blobs::HELLO_LINUX_ELF, blobs::HELLO_LINUX_PIE, blobs::HELLO_WIN_EXE];
    // Let the idle thread reap threads/processes of earlier tests first: their stacks are freed
    // lazily, which otherwise races with the snapshot below (seen as "leaked" frames going UP).
    crate::task::sleep_ms(100);
    let (_, free0) = frame::stats();
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    let (mut ok, mut err) = (0usize, 0usize);
    let t0 = crate::time::uptime_ms();
    let mut img: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for i in 0..ITER {
        let base = corpus[i % corpus.len()];
        img.clear();
        img.extend_from_slice(base);
        match rng.below(6) {
            0 => img.truncate(rng.below(img.len() + 1)),
            1 => {
                for _ in 0..1 + rng.below(8) {
                    let at = rng.below(img.len().min(640));
                    img[at] ^= 1 << rng.below(8);
                }
            }
            2 => {
                let at = rng.below(img.len().min(640).saturating_sub(8)) & !3;
                let v: [u64; 6] = [0, u64::MAX, 0x7FFF_FFFF, 0xFFFF_FFFF, 1 << 40, 0x8000_0000_0000_0000];
                let val = v[rng.below(6)].to_le_bytes();
                let n = if rng.below(2) == 0 { 4 } else { 8 };
                img[at..at + n].copy_from_slice(&val[..n]);
            }
            3 => {
                let lim = img.len().min(640);
                if lim > 48 {
                    let (a, b) = (rng.below(lim - 16), rng.below(lim - 16));
                    for k in 0..16 {
                        img.swap(a + k, b + k);
                    }
                }
            }
            4 => {
                for _ in 0..1 + rng.below(32) {
                    let at = rng.below(img.len());
                    img[at] = rng.next() as u8;
                }
            }
            _ => {
                let n = rng.below(64);
                let at = rng.below(img.len().saturating_sub(n).max(1));
                img[at..at + n].fill(0xFF);
            }
        }
        match exec::build("fuzz", &img, &SpawnOpts { args: &["fuzz"], console: false, caps: &[], foreign_caps: &[] }) {
            Ok(_proc) => ok += 1,  // dropped immediately: Drop must release every frame
            Err(_) => err += 1,
        }
    }
    let dt = crate::time::uptime_ms() - t0;
    crate::task::sleep_ms(20);
    let (_, free1) = frame::stats();
    info!("loader fuzz: {} mutated images -> {} loaded, {} rejected, no fault ({} ms)", ITER, ok, err, dt);
    check!(err > ITER / 4, "suspiciously few rejections ({})", err);
    check!(free0 == free1, "loader fuzz leaked frames: {} -> {}", free0, free1);
}


// ------------------------------------------------------------ Milestone 7 ---

fn test_pci() {
    use crate::drivers::pci;
    let devs = pci::devices();
    check!(!devs.is_empty(), "pci: no devices enumerated");
    check!(devs.iter().any(|d| d.class == 0x06 && d.subclass == 0x00), "pci: no host bridge found");
    if pci::using_ecam() {
        // Cross-check ECAM against the legacy 0xCF8/0xCFC mechanism for every function.
        for d in devs {
            let a = pci::cfg_read32(d.bdf, 0);
            let b = pci::legacy_read32(d.bdf, 0);
            check!(a == b && a & 0xFFFF == d.vendor as u32, "pci: ECAM/legacy id mismatch at {:?}", d.bdf);
            let a = pci::cfg_read32(d.bdf, 8);
            check!(a == pci::legacy_read32(d.bdf, 8), "pci: class dword mismatch at {:?}", d.bdf);
        }
    }
    info!("pci ok: {} functions (ECAM={})", devs.len(), pci::using_ecam());
    // Contiguous frame allocator: aligned, contiguous, leak-free.
    let (_, f0) = frame::stats();
    let a = frame::allocate_contiguous(8, 4).expect("contiguous alloc");
    check!((a.start_address().as_u64() / 4096) % 4 == 0, "contiguous alloc misaligned");
    let b = frame::allocate_contiguous(3, 1).expect("contiguous alloc 2");
    check!(b.start_address().as_u64() >= a.start_address().as_u64() + 8 * 4096 || b.start_address().as_u64() + 3 * 4096 <= a.start_address().as_u64(), "contiguous ranges overlap");
    check!(frame::allocate_contiguous(0, 1).is_none() && frame::allocate_contiguous(1, 3).is_none(), "bad contiguous args accepted");
    check!(frame::deallocate_contiguous(a, 8) == 8 && frame::deallocate_contiguous(b, 3) == 3, "contiguous free");
    check!(frame::deallocate_contiguous(a, 1) == 0, "contiguous double free accepted");
    let (_, f1) = frame::stats();
    check!(f0 == f1, "contiguous alloc leaked frames: {} -> {}", f0, f1);
}

fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x52, 0x55, 0x0a, 0, 2, 2, 0x52, 0x54, 0, 0x12, 0x34, 0x56]);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn ip4(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0x45, 0, 0, 0, 0, 1, 0x40, 0, 64, proto, 0, 0]);
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(l4);
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    eth(0x0800, &p)
}

fn tcp_seg(sport: u16, dport: u16, payload: usize) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&[0; 8]);
    t.extend_from_slice(&[0x50, 0x02, 0, 0, 0, 0, 0, 0]);
    t.resize(20 + payload, 0xAA);
    t
}

fn udp_dgram(sport: u16, dport: u16) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&[0, 8, 0, 0]);
    u
}

fn icmp_echo(ty: u8, id: u16) -> Vec<u8> {
    let mut i = alloc::vec![ty, 0, 0, 0];
    i.extend_from_slice(&id.to_be_bytes());
    i.extend_from_slice(&[0, 1]);
    i
}

fn arp(op: u16, spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
    let mut a = alloc::vec![0, 1, 8, 0, 6, 4];
    a.extend_from_slice(&op.to_be_bytes());
    a.extend_from_slice(&[0x52, 0x54, 0, 0x12, 0x34, 0x56]);
    a.extend_from_slice(&spa);
    a.extend_from_slice(&[0; 6]);
    a.extend_from_slice(&tpa);
    eth(0x0806, &a)
}

fn test_firewall() {
    use crate::net::firewall::{Firewall, Reason};
    use crate::net::grant::{GrantErr, NetGrant, Proto};
    const ME: [u8; 4] = [10, 0, 2, 15];
    const GW: [u8; 4] = [10, 0, 2, 2];
    const T0: u64 = 1_000;
    let mut fw = Firewall::new();

    // Disabled NIC: everything denied in both directions.
    let syn = ip4(6, ME, GW, &tcp_seg(50000, 80, 0));
    check!(!fw.outbound(&syn, T0).allow && fw.outbound(&syn, T0).reason == Reason::Disabled, "disabled out");
    check!(fw.inbound(&syn, T0).reason == Reason::Disabled, "disabled in");

    fw.enabled = true;
    fw.our_ip = ME;
    // Default deny: no grant -> nothing but ARP/DHCP infrastructure.
    check!(fw.outbound(&syn, T0).reason == Reason::NoGrant, "tcp without grant must be denied");
    check!(!fw.outbound(&ip4(17, ME, [8, 8, 8, 8], &udp_dgram(5353, 53)), T0).allow, "dns without grant");
    check!(!fw.outbound(&ip4(1, ME, GW, &icmp_echo(8, 7)), T0).allow, "ping without grant");
    check!(fw.outbound(&eth(0x86DD, &[0x60; 40]), T0).reason == Reason::UnsupportedL3, "ipv6 must be denied");
    check!(fw.outbound(&ip4(6, [1, 2, 3, 4], GW, &tcp_seg(50000, 80, 0)), T0).reason == Reason::Spoofed, "spoofed source");
    check!(fw.outbound(&arp(1, ME, GW), T0).allow, "arp request while enabled");
    check!(fw.outbound(&arp(1, [9, 9, 9, 9], GW), T0).reason == Reason::Spoofed, "spoofed arp");
    let dhcp_disc = ip4(17, [0; 4], [255; 4], &udp_dgram(68, 67));
    check!(fw.outbound(&dhcp_disc, T0).reason == Reason::InfraDhcp, "dhcp discover");
    check!(!fw.outbound(&ip4(17, [0; 4], [255; 4], &udp_dgram(68, 1234)), T0).allow, "bogus broadcast udp");
    check!(!fw.inbound(&ip4(6, GW, ME, &tcp_seg(80, 50000, 0)), T0).allow, "unsolicited inbound tcp (no listening sockets)");

    // Grant: tcp to 10.0.2.2:80 only.
    let g = NetGrant::new(Proto::Tcp, GW, 32, (80, 80), 10_000, 100_000, T0).unwrap();
    fw.add_grant(&g);
    let d = fw.outbound(&syn, T0);
    check!(d.allow && d.new_flow && d.grant == g.id, "granted syn");
    check!(!fw.outbound(&syn, T0).new_flow, "second packet is not a new flow");
    check!(fw.outbound(&ip4(6, ME, GW, &tcp_seg(50000, 81, 0)), T0).reason == Reason::NoGrant, "wrong port");
    check!(fw.outbound(&ip4(6, ME, [10, 0, 2, 3], &tcp_seg(50000, 80, 0)), T0).reason == Reason::NoGrant, "wrong host");
    check!(!fw.outbound(&ip4(17, ME, GW, &udp_dgram(50000, 80)), T0).allow, "wrong protocol");
    check!(fw.inbound(&ip4(6, GW, ME, &tcp_seg(80, 50000, 0)), T0).reason == Reason::Established, "reply of granted flow");
    check!(!fw.inbound(&ip4(6, GW, ME, &tcp_seg(80, 50001, 0)), T0).allow, "reply to a different local port");
    check!(!fw.inbound(&ip4(6, GW, ME, &tcp_seg(81, 50000, 0)), T0).allow, "reply from a different remote port");
    check!(!fw.inbound(&ip4(6, [10, 0, 2, 3], ME, &tcp_seg(80, 50000, 0)), T0).allow, "reply from a different host");
    check!(!fw.inbound(&ip4(6, GW, [255; 4], &tcp_seg(80, 50000, 0)), T0).allow, "broadcast inbound");

    // Expiry, revocation, budget, drop.
    check!(!fw.outbound(&syn, T0 + 20_000).allow, "expired grant must not allow");
    check!(!fw.inbound(&ip4(6, GW, ME, &tcp_seg(80, 50000, 0)), T0 + 20_000).allow, "expired grant must not allow replies");
    let g2 = NetGrant::new(Proto::Tcp, GW, 32, (80, 80), 10_000, 1000, T0).unwrap();
    fw.add_grant(&g2);
    g.revoke();
    let big = ip4(6, ME, GW, &tcp_seg(50002, 80, 600));
    check!(fw.outbound(&big, T0).allow, "within budget");
    check!(fw.outbound(&big, T0).reason == Reason::Budget, "budget exhausted must deny");
    g2.revoke();
    check!(!fw.has_live_grant(T0), "revoked grants still live");
    let g3 = NetGrant::new(Proto::Icmp, GW, 32, (0, 0), 10_000, 10_000, T0).unwrap();
    fw.add_grant(&g3);
    check!(fw.outbound(&ip4(1, ME, GW, &icmp_echo(8, 77)), T0).allow, "granted ping");
    check!(fw.inbound(&ip4(1, GW, ME, &icmp_echo(0, 77)), T0).allow, "echo reply");
    check!(!fw.inbound(&ip4(1, GW, ME, &icmp_echo(8, 77)), T0).allow, "inbound echo request");
    drop(g3);
    check!(!fw.has_live_grant(T0), "dropped grant (last Arc) must disappear");
    check!(!fw.outbound(&ip4(1, ME, GW, &icmp_echo(8, 77)), T0).allow, "ping after drop");

    // Grant validation.
    check!(NetGrant::new(Proto::Tcp, [0, 0, 0, 0], 0, (1, 65535), 1000, 10, 0).err() == Some(GrantErr::BadPrefix), "/0 grant");
    check!(NetGrant::new(Proto::Tcp, [127, 0, 0, 1], 32, (1, 80), 1000, 10, 0).err() == Some(GrantErr::ForbiddenRange), "loopback /32 grant");
    check!(NetGrant::new(Proto::Tcp, [127, 0, 0, 1], 24, (1, 80), 1000, 10, 0).err() == Some(GrantErr::ForbiddenRange), "loopback grant");
    check!(NetGrant::new(Proto::Tcp, [239, 1, 1, 1], 24, (1, 80), 1000, 10, 0).err() == Some(GrantErr::ForbiddenRange), "multicast grant");
    check!(NetGrant::new(Proto::Tcp, GW, 32, (0, 80), 1000, 10, 0).err() == Some(GrantErr::BadPorts), "port 0");
    check!(NetGrant::new(Proto::Tcp, GW, 32, (90, 80), 1000, 10, 0).err() == Some(GrantErr::BadPorts), "inverted ports");
    check!(NetGrant::new(Proto::Tcp, GW, 32, (1, 80), 0, 10, 0).err() == Some(GrantErr::BadDuration), "zero duration");
    check!(NetGrant::new(Proto::Tcp, GW, 32, (1, 80), 7_200_000, 10, 0).err() == Some(GrantErr::BadDuration), "huge duration");
    check!(NetGrant::new(Proto::Tcp, GW, 32, (1, 80), 1000, 0, 0).err() == Some(GrantErr::BadBudget), "zero budget");
    check!(NetGrant::new(Proto::Tcp, GW, 32, (1, 80), 1000, u64::MAX, 0).err() == Some(GrantErr::BadBudget), "huge budget");

    // Hostile input: every truncation and 30k random mutations must never fault.
    let g4 = NetGrant::new(Proto::Tcp, GW, 24, (1, 65535), 3_600_000, 1 << 30, T0).unwrap();
    fw.add_grant(&g4);
    let seeds = [ip4(6, ME, GW, &tcp_seg(50000, 80, 10)), ip4(17, ME, GW, &udp_dgram(1, 2)), ip4(1, ME, GW, &icmp_echo(8, 1)), arp(1, ME, GW), dhcp_disc.clone()];
    let mut seen_allow = 0;
    for seed in &seeds {
        for n in 0..seed.len() {
            let _ = fw.outbound(&seed[..n], T0);
            let _ = fw.inbound(&seed[..n], T0);
        }
    }
    let mut rng = Rng(0x5eed_1234_abcd_ef01);
    for i in 0..30_000usize {
        let mut f = seeds[i % seeds.len()].clone();
        for _ in 0..1 + rng.below(6) {
            let at = rng.below(f.len());
            f[at] = rng.next() as u8;
        }
        if rng.below(4) == 0 {
            let n = rng.below(f.len());
            f.truncate(n);
        }
        if fw.outbound(&f, T0).allow {
            seen_allow += 1;
        }
        let _ = fw.inbound(&f, T0);
    }
    // A NetGrant travels as a capability: rights narrow, revoking the parent kills the child, forged handles fail.
    {
        use crate::cap::{CapObject, CapTable, Rights};
        let mut t = CapTable::new();
        let ng = NetGrant::new(Proto::Tcp, GW, 32, (80, 80), 10_000, 1000, T0).unwrap();
        let h = t.insert(CapObject::Net(ng.clone()), Rights::NET.union(Rights::DUP)).unwrap();
        check!(matches!(t.lookup(h, Rights::NET), Ok((CapObject::Net(_), _))), "net cap lookup");
        check!(t.lookup(h, Rights::IO).err() == Some(crate::sys::errno::EPERM), "net cap without IO right");
        let c = t.derive(h, Rights::NET).unwrap();
        check!(t.lookup(c, Rights::DUP).err() == Some(crate::sys::errno::EPERM), "derived net cap cannot be re-derived");
        t.remove(h).unwrap();
        check!(t.lookup(c, Rights::NET).err() == Some(crate::sys::errno::EBADF), "revoked net cap child still valid");
        check!(t.lookup(0xDEAD_BEEF_0000_0001, Rights::NET).err() == Some(crate::sys::errno::EBADF), "forged net handle");
    }
    info!("firewall ok: default-deny, grants, flows, expiry, budget, revocation, {} fuzzed frames (allowed {} outbound)", 30_000, seen_allow);
}

fn test_updater() {
    use crate::upd::{self, manifest, testvec, UpdError};
    // SHA-256 known answers (FIPS 180-2).
    let abc = upd::sha256(b"abc");
    check!(abc[..4] == [0xba, 0x78, 0x16, 0xbf] && abc[28..] == [0xf2, 0x00, 0x15, 0xad], "sha256(abc)");
    check!(upd::sha256(b"")[..4] == [0xe3, 0xb0, 0xc4, 0x42], "sha256(empty)");
    // Ed25519: RFC 8032 section 7.1 test 1 (empty message) against ed25519-compact.
    let pk_bytes: [u8; 32] = [0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a];
    let sig_bytes: [u8; 64] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9,
        0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
    ];
    let pk = ed25519_compact::PublicKey::from_slice(&pk_bytes).unwrap();
    check!(pk.verify(b"", &ed25519_compact::Signature::from_slice(&sig_bytes).unwrap()).is_ok(), "ed25519 RFC8032 vector 1 must verify");
    check!(pk.verify(b"x", &ed25519_compact::Signature::from_slice(&sig_bytes).unwrap()).is_err(), "ed25519 wrong message must fail");
    let mut bad = sig_bytes;
    bad[10] ^= 1;
    check!(pk.verify(b"", &ed25519_compact::Signature::from_slice(&bad).unwrap()).is_err(), "ed25519 flipped signature bit must fail");

    // Manifests signed by the independent Python signer.
    check!(upd::verify_manifest(testvec::MANIFEST_OK, testvec::SIG_OK).is_ok(), "valid manifest must verify (python signer interop)");
    check!(upd::verify_manifest(testvec::MANIFEST_TAMPERED, testvec::SIG_OK) == Err(UpdError::BadSignature), "tampered manifest -> BadSignature");
    check!(upd::verify_manifest(testvec::MANIFEST_OK, testvec::SIG_WRONGKEY) == Err(UpdError::UnknownKey), "wrong key -> UnknownKey");
    check!(upd::verify_manifest(testvec::MANIFEST_OK, testvec::SIG_FORGED) == Err(UpdError::BadSignature), "forged key id -> BadSignature");
    check!(matches!(upd::verify_manifest(testvec::MANIFEST_OK, b"garbage"), Err(UpdError::SigFormat(_))), "garbage sig file");
    check!(matches!(upd::verify_manifest(testvec::MANIFEST_OK, &testvec::SIG_OK[..testvec::SIG_OK.len() - 1]), Err(UpdError::SigFormat(_))), "truncated sig file");
    check!(matches!(upd::verify_manifest(testvec::MANIFEST_OK, b""), Err(UpdError::SigFormat(_))), "empty sig file");

    // Manifest parser.
    let m = manifest::parse(testvec::MANIFEST_OK).expect("valid manifest parses");
    check!(m.version == [0, 1, 1] && m.min_version == [0, 1, 0] && m.artifacts.len() == 2, "manifest fields");
    let ok = core::str::from_utf8(testvec::MANIFEST_OK).unwrap();
    let h = "0".repeat(64);
    let art = |extra: &str| alloc::format!("{{\"format\":1,\"version\":\"1.0.0\",\"min_version\":\"0.7.0\",\"created\":1,\"artifacts\":[{{\"name\":\"a\",\"size\":1,\"sha256\":\"{}\",\"path\":\"/a\"}}]{}}}", h, extra);
    check!(manifest::parse(art("").as_bytes()).is_ok(), "minimal manifest");
    let bads: [(&str, alloc::string::String); 14] = [
        ("unknown key", art(",\"x\":1")),
        ("trailing data", alloc::format!("{} x", ok)),
        ("duplicate key", ok.replacen("\"created\"", "\"format\"", 1)),
        ("bad version", ok.replacen("0.1.1", "01.1.1", 1)),
        ("short version", ok.replacen("0.1.1", "0.1", 1)),
        ("huge version", ok.replacen("0.1.1", "0.1.99999", 1)),
        ("path traversal", ok.replacen("/artifacts/deloxy-core.bin", "/../etc/passwd", 1)),
        ("oversize artifact", ok.replacen("\"size\":3000", "\"size\":99999999999", 1)),
        ("u64 overflow", ok.replacen("\"size\":3000", "\"size\":99999999999999999999999", 1)),
        ("uppercase hash", ok.replacen("\"sha256\":\"", "\"sha256\":\"G", 1)),
        ("wrong format", ok.replacen("\"format\":1", "\"format\":2", 1)),
        ("float", ok.replacen("\"created\":1790000000", "\"created\":1.5", 1)),
        ("deep nesting", alloc::format!("{}{}", "[".repeat(40), "]".repeat(40))),
        ("empty", alloc::string::String::new()),
    ];
    for (what, b) in bads.iter() {
        check!(manifest::parse(b.as_bytes()).is_err(), "manifest parser accepted: {}", what);
    }
    check!(manifest::parse(&alloc::vec![b' '; manifest::MAX_MANIFEST + 1]).is_err(), "oversize manifest");
    let mut rng = Rng(0xfeed_f00d_0000_0001);
    for i in 0..20_000usize {
        let mut b = testvec::MANIFEST_OK.to_vec();
        for _ in 0..1 + rng.below(5) {
            let at = rng.below(b.len());
            b[at] = rng.next() as u8;
        }
        if i % 7 == 0 {
            let n = rng.below(b.len());
            b.truncate(n);
        }
        let _ = manifest::parse(&b); // must never panic
    }

    // Rollback policy (applied to authenticated manifests).
    let mk = |v: [u16; 3], min: [u16; 3]| manifest::Manifest { version: v, min_version: min, created: 0, artifacts: alloc::vec![] };
    let run = [0, 7, 0];
    check!(upd::check_policy(&mk([0, 7, 1], [0, 7, 0]), run, [0, 0, 0]).is_ok(), "newer version accepted");
    check!(matches!(upd::check_policy(&mk([0, 7, 0], [0, 0, 0]), run, [0, 0, 0]), Err(UpdError::NotNewer { .. })), "same version is a replay");
    check!(matches!(upd::check_policy(&mk([0, 6, 9], [0, 0, 0]), run, [0, 0, 0]), Err(UpdError::NotNewer { .. })), "older version is a rollback");
    check!(matches!(upd::check_policy(&mk([0, 7, 1], [0, 7, 0]), run, [0, 7, 1]), Err(UpdError::NotNewer { .. })), "already-staged version is a replay");
    check!(matches!(upd::check_policy(&mk([1, 0, 0], [0, 9, 0]), run, [0, 0, 0]), Err(UpdError::BelowMinVersion { .. })), "min_version enforced");
    check!(upd::check_policy(&mk([0, 10, 0], [0, 7, 0]), run, [0, 9, 0]).is_ok(), "numeric (not lexical) version compare");

    info!("updater ok: sha256+ed25519 KATs, python-signed manifest interop, tampered/wrong-key/forged distinct, parser + 20k fuzz, rollback policy");
}

/// End-to-end network test against tools/mock-update-server.py (run by tools/net-test.py; needs
/// `-netdev user,id=n0 -device virtio-net-pci,netdev=n0` and the server on the host at port 8777).
#[cfg(feature = "net-test")]
fn test_net_integration() {
    use crate::audit::{self, EV_NET_ALLOW, EV_NET_DENY};
    use crate::net::{self, NetErr, NetGrant, Proto};
    use crate::upd::{self, Server, UpdError};
    check!(net::has_nic(), "net-test needs a virtio-net device");
    let srv = Server { ip: [10, 0, 2, 2], port: 8777 };
    while audit::pop().is_some() {}
    upd::reset_for_test();

    // ---- Phase A: no grant anywhere. The NIC must stay inert and silent.
    let st = net::stats();
    check!(!st.enabled && st.tx_frames == 0 && st.device_status == 0, "NIC must start disabled and inert");
    let now = crate::time::uptime_ms();
    let dead = NetGrant::new(Proto::Tcp, srv.ip, 32, (8777, 8777), 60_000, 1 << 20, now).unwrap();
    dead.revoke();
    check!(net::tcp_connect(&dead, srv.ip, 8777) == Err(NetErr::Denied), "revoked grant must be refused");
    let other = NetGrant::new(Proto::Tcp, [10, 0, 2, 3], 32, (1, 65535), 60_000, 1 << 20, now).unwrap();
    check!(net::tcp_connect(&other, srv.ip, 8777) == Err(NetErr::Denied), "grant for another host must be refused");
    let unregistered = NetGrant::new(Proto::Tcp, srv.ip, 32, (8777, 8777), 60_000, 1 << 20, now).unwrap();
    check!(net::tcp_connect(&unregistered, srv.ip, 8777) == Err(NetErr::NotReady), "NIC must not wake for an unregistered grant");
    check!(upd::check(&dead, srv, "/ok").err() == Some(UpdError::Net(NetErr::Denied)), "upd check without a live grant");
    crate::task::sleep_ms(3000);
    let st = net::stats();
    check!(!st.enabled && st.tx_frames == 0 && st.rx_frames == 0 && st.device_status == 0, "NIC activity without a grant: {:?}", st);
    let mut denies = 0;
    while let Some(e) = audit::pop() {
        if e.kind == EV_NET_DENY {
            denies += 1;
        }
    }
    check!(denies >= 3, "socket-layer denials must be audited (saw {})", denies);
    info!("NETTEST: PHASE A DONE (no grant: {} denials audited, 0 frames, device status 0)", denies);
    crate::task::sleep_ms(2000); // lets the host sample the packet capture before any grant exists

    // ---- Phase B: time-boxed grant for exactly one host:port.
    let g = net::issue_grant(Proto::Tcp, srv.ip, 32, (8777, 8777), 120_000, 8 << 20).expect("grant");
    check!(net::wait_ready(20_000), "no DHCP lease within 20 s");
    let st = net::stats();
    check!(st.enabled && st.ip == Some([10, 0, 2, 15]), "unexpected lease: {:?}", st);
    check!(net::tcp_connect(&g, srv.ip, 8778) == Err(NetErr::Denied), "other port must be refused by the grant");
    check!(net::tcp_connect(&g, [10, 0, 2, 3], 8777) == Err(NetErr::Denied), "other host must be refused by the grant");

    let m = upd::check(&g, srv, "/ok").expect("valid manifest");
    check!(m.manifest.version == [0, 1, 1], "offered version");
    info!("NETTEST: valid signed manifest accepted: update 0.1.1 available");
    let expect: [(&str, UpdError); 7] = [
        ("/tampered", UpdError::BadSignature),
        ("/wrongkey", UpdError::UnknownKey),
        ("/forged", UpdError::BadSignature),
        ("/replay", UpdError::NotNewer { offered: [0, 0, 9], current: [0, 1, 0] }),
        ("/belowmin", UpdError::BelowMinVersion { required: [0, 9, 0], current: [0, 1, 0] }),
        ("/malformed", UpdError::ManifestFormat("bad object")),
        ("/missing", UpdError::Http(404)),
    ];
    for (path, want) in expect.iter() {
        let got = upd::check(&g, srv, path).err();
        check!(got.as_ref() == Some(want), "{}: expected {:?}, got {:?}", path, want, got);
        info!("NETTEST: {} rejected: {:?}", path, want);
    }
    check!(upd::fetch_and_stage(&g, srv, "/ok", &m).is_ok(), "staging valid update");
    check!(upd::staged_version() == Some([0, 1, 1]) && upd::staged_files() == 2, "staged state");
    check!(matches!(upd::check(&g, srv, "/ok").err(), Some(UpdError::NotNewer { .. })), "re-offering a staged version is a replay");
    let hb = upd::check(&g, srv, "/badhash").expect("badhash manifest is validly signed");
    check!(upd::fetch_and_stage(&g, srv, "/badhash", &hb).err() == Some(UpdError::ArtifactHash("initramfs.tar".into())), "artifact hash mismatch must be rejected");
    check!(upd::staged_version() == Some([0, 1, 1]), "failed staging must not replace the staged update");
    info!("NETTEST: update staged; tampered artifact rejected");
    let mut allows = 0;
    let mut denies = 0;
    while let Some(e) = audit::pop() {
        match e.kind {
            EV_NET_ALLOW => allows += 1,
            EV_NET_DENY => denies += 1,
            _ => {}
        }
    }
    check!(allows >= 1 && denies >= 2, "audit: allows {} denies {}", allows, denies);
    let st = net::stats();
    info!("NETTEST: PHASE B DONE (tx {} rx {} frames, firewall allowed {} denied {}, audit allow {} deny {})", st.tx_frames, st.rx_frames, st.fw_allowed, st.fw_denied, allows, denies);

    // ---- Phase C: grant dropped -> NIC reset, silence again.
    drop(g);
    drop(m);
    drop(hb);
    crate::task::sleep_ms(300);
    let st = net::stats();
    check!(!st.enabled && st.device_status == 0, "NIC must be disabled after the last grant is gone: {:?}", st);
    let (tx, rx) = (st.tx_frames, st.rx_frames);
    crate::task::sleep_ms(3000);
    let st2 = net::stats();
    check!(st2.tx_frames == tx && st2.rx_frames == rx && !st2.enabled, "traffic after grant drop");
    info!("NETTEST: PHASE C DONE (grant dropped: NIC disabled again, device status 0)");
}

// ------------------------------------------------------------ Milestone 8 ---

fn test_initramfs() {
    use crate::fs;
    let root = fs::root().expect("initramfs module missing: build the ISO with tools/mkiso.sh (or dev-container/mkiso.sh)");
    for name in ["README.txt", "deloxy-sh.elf", "monitor.elf", "hello_native.elf", "hello_linux.elf", "hello_win.exe"] {
        check!(root.lookup(name).is_some(), "initramfs lacks {}", name);
    }
    let sh = root.lookup("deloxy-sh.elf").unwrap();
    check!(sh.data.len() > 1000 && &sh.data[..4] == b"\x7fELF", "deloxy-sh.elf content");
    check!(root.lookup("../etc/passwd").is_none() && root.lookup("").is_none() && root.lookup("hello_win.exe/").is_none(), "lookup must be exact, flat");

    // Strict parser: hostile archives must be rejected or parsed harmlessly, never fault.
    let mut tar: Vec<u8> = Vec::new();
    for f in root.files.iter() {
        let mut h = [0u8; 512];
        h[..f.name.len()].copy_from_slice(f.name.as_bytes());
        let sz = alloc::format!("{:011o}\0", f.data.len());
        h[124..136].copy_from_slice(sz.as_bytes());
        h[156] = b'0';
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        h[148..156].copy_from_slice(alloc::format!("{:06o}\0 ", sum).as_bytes());
        tar.extend_from_slice(&h);
        tar.extend_from_slice(f.data);
        tar.resize((tar.len() + 511) & !511, 0);
    }
    tar.resize(tar.len() + 1024, 0);
    let ok = fs::scan(&tar).expect("rebuilt archive parses");
    check!(ok.len() == root.files.len(), "rebuilt archive file count");
    check!(fs::scan(&tar[..tar.len() - 1500]).is_err(), "truncated archive must be rejected");
    let mut bad = tar.clone();
    bad[0] ^= 0x55;
    check!(fs::scan(&bad) == Err(fs::TarError::BadChecksum), "corrupted header must fail its checksum");
    let mut rng = Rng(0xA11C_E000_0000_0007);
    let (mut accepted, mut rejected) = (0, 0);
    for i in 0..20_000usize {
        let mut t = tar[..tar.len().min(4096 + (i % 8) * 512)].to_vec();
        for _ in 0..1 + rng.below(8) {
            let at = rng.below(t.len());
            t[at] = rng.next() as u8;
        }
        if i % 5 == 0 {
            let n = rng.below(t.len());
            t.truncate(n);
        }
        match fs::scan(&t) {
            Ok(v) => {
                accepted += 1;
                for (_, r) in v {
                    check!(r.start <= r.end && r.end <= t.len(), "range outside archive");
                }
            }
            Err(_) => rejected += 1,
        }
    }
    info!("initramfs ok: {} files, tar parser fuzz 20000 (accepted {}, rejected {})", root.files.len(), accepted, rejected);
}

/// Drive the real ring-3 shell through the kernel TTY: type commands, read what it prints.
fn test_shell() {
    use crate::tty;
    let mut pos = tty::out_total();
    let mut seen: alloc::string::String = alloc::string::String::new();
    let mut expect = |pos: &mut u64, seen: &mut alloc::string::String, needle: &str, ms: u64| -> bool {
        let t0 = crate::time::uptime_ms();
        loop {
            let mut buf = [0u8; 512];
            let (n, np) = tty::read_output(*pos, &mut buf);
            *pos = np;
            seen.push_str(&alloc::string::String::from_utf8_lossy(&buf[..n]));
            if seen.contains(needle) {
                let i = seen.find(needle).unwrap() + needle.len();
                *seen = seen[i..].into();
                return true;
            }
            if crate::time::uptime_ms() - t0 > ms {
                log::error!("shell test: timed out waiting for {:?}; got {:?}", needle, seen);
                return false;
            }
            crate::task::sleep_ms(5);
        }
    };
    let sh = crate::init::spawn_shell().expect("spawn shell");
    check!(expect(&mut pos, &mut seen, "deloxy-sh> ", 8000), "shell never printed its prompt");
    let mut cmd = |pos: &mut u64, seen: &mut alloc::string::String, line: &str, want: &[&str], ms: u64| {
        tty::push_input(line.as_bytes());
        tty::push_input(b"\r");
        for w in want {
            check!(expect(pos, seen, w, ms), "shell: after {:?} expected {:?}", line, w);
        }
        check!(expect(pos, seen, "deloxy-sh> ", ms), "shell: no prompt after {:?}", line);
    };
    cmd(&mut pos, &mut seen, "help", &["builtins:"], 3000);
    cmd(&mut pos, &mut seen, "ls", &["monitor.elf", "hello_win.exe"], 3000);
    cmd(&mut pos, &mut seen, "cat README.txt", &["Deloxy initramfs"], 3000);
    cmd(&mut pos, &mut seen, "echo hi there", &["hi there"], 3000);
    cmd(&mut pos, &mut seen, "frobnicate", &["unknown command 'frobnicate'"], 3000);
    cmd(&mut pos, &mut seen, "run nosuchfile", &["not found"], 3000);
    cmd(&mut pos, &mut seen, "run README.txt", &["cannot start README.txt", "not an ELF or PE"], 3000);
    cmd(&mut pos, &mut seen, "run hello_native.elf", &["[exit 0]"], 5000);
    cmd(&mut pos, &mut seen, "run hello_linux.elf", &["Hello from Linux ELF", "[exit 0]"], 5000);
    cmd(&mut pos, &mut seen, "run hello_win.exe", &["Hello from Windows PE", "[exit 0]"], 5000);
    cmd(&mut pos, &mut seen, "run monitor.elf", &["deloxy-monitor sample 1/1", "frames used", "[exit 0]"], 5000);
    cmd(&mut pos, &mut seen, "ps", &["running", "deloxy-sh"], 3000);
    cmd(&mut pos, &mut seen, "caps", &["tty", "dir", "spawn", "power", "net-admin", "audit"], 3000);
    // Backspace editing: "ecXX" + 2 DEL + "ho ok" must execute as "echo ok".
    tty::push_input(b"ecXX\x7f\x7fho ok\r");
    check!(expect(&mut pos, &mut seen, "ok\n", 3000), "backspace editing");
    check!(expect(&mut pos, &mut seen, "deloxy-sh> ", 3000), "prompt after editing");
    cmd(&mut pos, &mut seen, "audit 8", &["SEQ"], 3000);
    // Consent: answering anything but y must leave the network off and issue no grant.
    let tx0 = crate::net::stats().tx_frames;
    tty::push_input(b"upd check\rn\r");
    check!(expect(&mut pos, &mut seen, "Allow? [y/N] ", 3000), "upd consent prompt");
    check!(expect(&mut pos, &mut seen, "denied: no grant issued", 3000), "upd must respect a refusal");
    check!(expect(&mut pos, &mut seen, "deloxy-sh> ", 3000), "prompt after refusal");
    check!(!crate::net::stats().enabled && crate::net::stats().tx_frames == tx0, "refused upd must leave the NIC off");
    check!(!sh.has_exited(), "shell died");
    info!("shell ok: prompt, builtins, run native/linux/pe, monitor, ps, caps, audit, line editing, upd consent refusal");
}

// ------------------------------------------------------------------ persistent store ---

fn test_store_logic() {
    use crate::store::{crc32, valid_name, RamDisk, Store, StoreErr, DATA_START, MAX_FILES};
    check!(crc32(b"123456789") == 0xCBF4_3926, "crc32 check value");
    check!(valid_name("a.b-c_d+e") && !valid_name("") && !valid_name("a/b") && !valid_name("..") && !valid_name(&"x".repeat(48)), "name validation");

    let mut st = Store::format(RamDisk::new(4096)).ok().expect("format ramdisk");
    check!(st.list().is_empty() && st.stats().files == 0, "fresh store is empty");
    st.write("hello.txt", b"hello deloxy").unwrap();
    st.write("big.bin", &vec![0x5Au8; 100_000]).unwrap();
    st.write("empty", b"").unwrap();
    check!(st.read("hello.txt").unwrap() == b"hello deloxy", "read back small file");
    check!(st.read("big.bin").unwrap().len() == 100_000 && st.read("big.bin").unwrap().iter().all(|&b| b == 0x5A), "read back 100 KB file");
    check!(st.read("empty").unwrap().is_empty(), "empty file");
    check!(st.read("nope") == Err(StoreErr::NotFound), "missing file -> NotFound");
    check!(st.write("bad/name", b"x") == Err(StoreErr::BadName), "bad name rejected");
    check!(st.write("huge", &vec![0u8; crate::store::MAX_FILE_BYTES + 1]) == Err(StoreErr::TooLarge), "too large rejected");
    st.write("hello.txt", b"replaced").unwrap();
    check!(st.read("hello.txt").unwrap() == b"replaced" && st.list().len() == 3, "atomic replace keeps one entry");
    let gen = st.stats().generation;

    // persistence across a "reboot" (remount the same bytes)
    let dev = st.into_dev();
    let mut st = match Store::mount(dev) {
        Ok(s) => s,
        Err((e, _)) => {
            check!(false, "remount failed: {:?}", e);
            unreachable!()
        }
    };
    check!(st.stats().generation == gen && st.list().len() == 3, "remount sees the committed generation");
    check!(st.read("hello.txt").unwrap() == b"replaced", "data survives remount");
    st.delete("big.bin").unwrap();
    check!(st.read("big.bin") == Err(StoreErr::NotFound) && st.delete("big.bin") == Err(StoreErr::NotFound), "delete");

    // space is reused after delete
    let before = st.stats().used_bytes;
    st.write("again", &vec![1u8; 100_000]).unwrap();
    check!(st.stats().used_bytes > before, "stats reflect new file");

    // fill the disk until NoSpace, then free it
    let mut n = 0;
    loop {
        match st.write(&alloc::format!("fill{}", n), &vec![7u8; 64 * 1024]) {
            Ok(()) => n += 1,
            Err(StoreErr::NoSpace) => break,
            Err(StoreErr::TooManyFiles) => break,
            Err(e) => {
                check!(false, "unexpected error while filling: {:?}", e);
            }
        }
        check!(n < 200, "fill loop runaway");
    }
    check!(n >= 10, "filled {} files before NoSpace", n);
    for i in 0..n {
        st.delete(&alloc::format!("fill{}", i)).unwrap();
    }
    st.write("after-fill", &vec![9u8; 64 * 1024]).unwrap();
    check!(st.read("again").unwrap().iter().all(|&b| b == 1), "earlier data untouched by fill/delete");

    // file-count limit
    let mut st = Store::format(RamDisk::new(4096)).ok().unwrap();
    for i in 0..MAX_FILES {
        st.write(&alloc::format!("f{}", i), b"x").unwrap();
    }
    check!(st.write("one-too-many", b"x") == Err(StoreErr::TooManyFiles), "file count limit");
    check!(st.write("f0", b"y").is_ok(), "replacing at the limit is fine");

    // ---- crash safety: tear the n-th device write of a replace and of a create, then remount
    for create in [false, true] {
        for k in 0..6usize {
            let mut st = Store::format(RamDisk::new(2048)).ok().unwrap();
            st.write("keep", b"stable").unwrap();
            st.write("a", b"version-one").unwrap();
            {
                let d = st.dev_mut();
                d.revive();
                d.fail_at_write = Some(k);
            }
            let name = if create { "new" } else { "a" };
            let r = st.write(name, &vec![0xEEu8; 3000]);
            let mut dev = st.into_dev();
            dev.revive();
            let mut st = match Store::mount(dev) {
                Ok(s) => s,
                Err((e, _)) => {
                    check!(false, "crash k={} create={}: remount failed {:?}", k, create, e);
                    unreachable!()
                }
            };
            check!(st.read("keep").unwrap() == b"stable", "crash k={}: unrelated file damaged", k);
            let a = st.read("a");
            if create {
                let new = st.read("new");
                check!(a.as_deref() == Ok(&b"version-one"[..]), "crash k={} (create): existing file lost", k);
                check!(new == Err(StoreErr::NotFound) || new.as_deref().map_or(false, |d| d.len() == 3000 && d.iter().all(|&b| b == 0xEE)), "crash k={} (create): torn new file visible", k);
                check!(r.is_ok() == new.is_ok(), "crash k={} (create): result {:?} disagrees with disk", k, r);
            } else {
                let ok_old = a.as_deref() == Ok(&b"version-one"[..]);
                let ok_new = a.as_deref().map_or(false, |d| d.len() == 3000 && d.iter().all(|&b| b == 0xEE));
                check!(ok_old || ok_new, "crash k={} (replace): file is neither old nor new ({:?})", k, a.as_ref().map(|d| d.len()));
                check!(r.is_ok() == ok_new, "crash k={} (replace): write result {:?} but disk has {}", k, r, if ok_new { "new" } else { "old" });
            }
        }
    }

    // ---- corruption detection
    let mut st = Store::format(RamDisk::new(2048)).ok().unwrap();
    st.write("x", &vec![3u8; 2000]).unwrap(); // gen 2 -> slot B
    st.write("y", b"second").unwrap(); // gen 3 -> slot A
    let slot_a_cur = true;
    let mut dev = st.into_dev();
    // flip a data byte of x
    dev.data[(DATA_START as usize) * 512 + 7] ^= 0xFF;
    let mut st = Store::mount(dev).ok().unwrap();
    check!(st.read("x") == Err(StoreErr::Corrupt), "flipped data byte detected by CRC");
    // destroy the newest directory: mount must fall back to the previous generation (without "y")
    let mut dev = st.into_dev();
    let cur_slot_sector = if slot_a_cur { 1 } else { 1 + crate::store::DIR_SECTORS as usize };
    dev.data[cur_slot_sector * 512 + 40] ^= 0xFF;
    let st = Store::mount(dev).ok().expect("fallback mount");
    check!(st.list().iter().any(|e| e.name == "x") && !st.list().iter().any(|e| e.name == "y"), "damaged newest directory falls back to the previous generation");
    // both directories destroyed -> refuse to mount (never guess)
    let mut dev = st.into_dev();
    dev.data[(1 + crate::store::DIR_SECTORS as usize) * 512 + 40] ^= 0xFF;
    dev.data[512 + 41] ^= 0xFF;
    check!(matches!(Store::mount(dev), Err((StoreErr::Corrupt, _))), "both directories bad -> Corrupt");
    // blank disk -> NoFilesystem, never auto-formatted
    check!(matches!(Store::mount(RamDisk::new(2048)), Err((StoreErr::NoFilesystem, _))), "blank disk -> NoFilesystem");
    info!("selftest: store logic ok (format/mount, atomic replace, ENOSPC, 12 power-cut points, CRC + fallback)");
}

fn test_store_device() {
    use crate::store::{self, State, StoreErr};
    use crate::upd;
    match store::state() {
        State::NoDevice => {
            info!("selftest: store device: no virtio-blk attached, skipping the device tests");
            return;
        }
        s => info!("selftest: store device state {:?}", s),
    }
    // The selftest only ever gets a scratch disk, so it may format it.
    check!(store::format_device().is_ok(), "format real virtio-blk disk");
    check!(store::state() == State::Ready, "state Ready after format");
    let big: Vec<u8> = (0..300_000u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
    check!(store::with(|s| s.write("dev.big", &big)).unwrap().is_ok(), "write 300 KB through virtio-blk");
    check!(store::with(|s| s.write("dev.small", b"hi")).unwrap().is_ok(), "write small file");
    check!(store::with(|s| s.read("dev.big")).unwrap().unwrap() == big, "read 300 KB back through virtio-blk");
    check!(store::with(|s| s.delete("dev.small")).unwrap().is_ok(), "delete");
    check!(store::with(|s| s.read("dev.small")).unwrap() == Err(StoreErr::NotFound), "deleted file gone");
    // out-of-range access is refused by the driver, not by luck
    let r = store::with(|s| {
        let cap = s.dev_mut().capacity_sectors();
        let mut buf = vec![0u8; 512];
        (s.dev_mut().read(cap, &mut buf), s.dev_mut().read(u64::MAX, &mut buf))
    })
    .unwrap();
    check!(r.0.is_err() && r.1.is_err(), "reads past the end are rejected");

    // updater persistence: stage -> persist -> "reboot" (forget RAM state) -> recover
    let files = vec![(String::from("deloxy-core.bin"), vec![0xC3u8; 3000]), (String::from("initramfs.tar"), vec![0x42u8; 5000])];
    upd::stage_for_test([0, 1, 1], files);
    check!(upd::persist_staged() == upd::PersistOutcome::Saved(2), "persist staged update");
    upd::reset_for_test();
    check!(upd::highest_staged() == [0, 0, 0], "RAM floor cleared");
    let rep = upd::recover_report();
    check!(rep.floor == Some([0, 1, 1]) && upd::highest_staged() == [0, 1, 1], "rollback floor restored from disk: {:?}", rep);
    check!(rep.pending == Some((String::from("0.1.1"), true)), "pending update verified on disk: {:?}", rep);
    // damage an artifact on disk: recovery must notice
    check!(store::with(|s| s.write("upd.0.1.1.initramfs.tar", &vec![0u8; 5000])).unwrap().is_ok(), "tamper with artifact");
    let rep = upd::recover_report();
    check!(rep.pending == Some((String::from("0.1.1"), false)), "tampered artifact detected: {:?}", rep);
    // clean up so later tests start from the in-RAM defaults
    upd::reset_for_test();
    check!(store::format_device().is_ok(), "re-format scratch disk");
    info!("selftest: virtio-blk store + persistent update staging ok");
}

// ------------------------------------------------------------------ any-host grants ---

fn test_net_grants_any() {
    use crate::net::{NetGrant, Proto};
    let t = Proto::Tcp as u8;
    // "full access": any host, unlimited time and data
    let g = NetGrant::any(Proto::Tcp, false, 0, 0, 1000);
    check!(g.live(1_000_000_000_000) && g.charge(1 << 40) && g.live(1_000_000_000_000), "unlimited any-host grant never expires or runs out");
    check!(g.covers(t, [8, 8, 8, 8], 443) && g.covers(t, [10, 0, 2, 2], 8777) && g.covers(t, [192, 168, 1, 5], 22), "any-host grant covers public and LAN hosts and every port");
    check!(!g.covers(t, [127, 0, 0, 1], 80) && !g.covers(t, [0, 0, 0, 0], 80) && !g.covers(t, [224, 0, 0, 1], 80) && !g.covers(t, [255, 255, 255, 255], 80), "any-host grant never covers loopback/this-net/multicast/broadcast");
    check!(!g.covers(Proto::Udp as u8, [8, 8, 8, 8], 53), "a TCP grant does not cover UDP");
    // internet only
    let g = NetGrant::any(Proto::Tcp, true, 0, 0, 1000);
    check!(g.covers(t, [8, 8, 8, 8], 443) && g.covers(t, [172, 32, 0, 1], 443) && g.covers(t, [100, 63, 0, 1], 443), "internet-only grant covers public addresses");
    check!(!g.covers(t, [10, 1, 2, 3], 80) && !g.covers(t, [172, 16, 0, 1], 80) && !g.covers(t, [172, 31, 255, 255], 80) && !g.covers(t, [192, 168, 0, 1], 80) && !g.covers(t, [169, 254, 1, 1], 80) && !g.covers(t, [100, 64, 0, 1], 80), "internet-only grant excludes RFC1918, link-local and CGNAT ranges");
    // custom time limit and data cap
    let g = NetGrant::any(Proto::Tcp, false, 5000, 100, 1000);
    check!(g.live(5999) && !g.live(6000), "custom time limit expires exactly");
    check!(g.charge(60) && !g.charge(60) && g.live(2000) && g.charge(40) && !g.live(2000), "custom data cap is enforced and ends the grant when spent");
    let g = NetGrant::any(Proto::Tcp, false, 0, 100, 1000);
    g.revoke();
    check!(!g.live(1500), "revoked grant is dead");
    // the narrow constructor keeps its ceilings
    check!(NetGrant::new(Proto::Tcp, [93, 184, 216, 34], 32, (443, 443), crate::net::grant::MAX_GRANT_MS + 1, 1, 0).is_err(), "narrow grants still have a time ceiling");
    info!("selftest: any-host grants ok (unlimited, internet-only, time limit, data cap, forbidden ranges)");
}
