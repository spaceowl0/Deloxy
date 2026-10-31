//! Processes and threads.

pub mod blobs;
pub mod sched;


use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use spin::{Mutex, Once};
use x86_64::structures::paging::PhysFrame;
use x86_64::VirtAddr;

use crate::arch::x86_64::context::FxArea;
use crate::cap::{CapObject, CapTable, Rights};
use crate::ipc::memobj::MemObject;
use crate::mm::layout::PAGE_SIZE;
use crate::mm::vmm::{self, AddressSpace, KernelStack, VmFlags};
use crate::sync::IrqMutex;

pub use sched::{kill_current_process, sleep_ms, yield_now};
use crate::abi::{AbiKind, ForeignState};

pub const USER_INFO_BASE: u64 = 0x0000_0000_0030_0000;
pub const USER_CODE_BASE: u64 = 0x0000_0000_0040_0000;
pub const USER_MMAP_BASE: u64 = 0x0000_2000_0000_0000;
pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_0000;
pub const USER_STACK_PAGES: usize = 4;
pub const KERNEL_STACK_PAGES: usize = 16; // 64 KiB

pub(crate) static NEXT_PID: AtomicU64 = AtomicU64::new(1);
static NEXT_TID: AtomicU64 = AtomicU64::new(1);

/// Registry of user processes (weak: it never keeps a process alive) for `ps` / process listing.
pub static PROCS: IrqMutex<Vec<alloc::sync::Weak<Process>>> = IrqMutex::new(Vec::new());

fn register(p: &Arc<Process>) {
    let mut g = PROCS.lock();
    g.retain(|w| w.strong_count() > 0);
    g.push(Arc::downgrade(p));
}

/// Snapshot of live processes (oldest first).
/// Default memory cap for Linux/Windows programs: 128 MiB.
pub const FOREIGN_MEM_LIMIT_PAGES: u64 = 32768;

pub fn list_processes() -> Vec<Arc<Process>> {
    PROCS.lock().iter().filter_map(|w| w.upgrade()).collect()
}

// ------------------------------------------------------------- process -----

/// A region of a user address space that the process object must tear down.
pub struct Mapping {
    pub va: u64,
    pub pages: usize,
    /// true: anonymous memory (frames freed on unmap); false: shared view of a `MemObject`.
    pub owned: bool,
    _keep: Option<Arc<MemObject>>, // keeps shared frames alive as long as the view exists
}

pub struct Process {
    pub pid: u64,
    pub name: String,
    /// `None` for the kernel process; taken on drop.
    pub space: IrqMutex<Option<AddressSpace>>,
    pub cr3: PhysFrame,
    pub mmap_next: AtomicU64,
    /// Cap on anonymous memory in pages (0 = unlimited). Foreign programs get `FOREIGN_MEM_LIMIT_PAGES`.
    pub mem_limit_pages: AtomicU64,
    /// (base VA, pages) of every anonymous region we own and must free.
    pub mappings: IrqMutex<Vec<Mapping>>,
    pub caps: IrqMutex<CapTable>,
    abi: AtomicU8,
    /// State used by the Linux/NT compatibility layers (brk, heap, TLS slots, console handle...).
    pub foreign: IrqMutex<ForeignState>,
    pub live_threads: AtomicUsize,
    pub exited: AtomicBool,
    pub exit_code: AtomicI64,
    exit_code_set: AtomicBool,
}

impl Process {
    pub(crate) fn new(pid: u64, name: &str, space: Option<AddressSpace>, cr3: PhysFrame) -> Process {
        Process {
            pid,
            name: String::from(name),
            space: IrqMutex::new(space),
            cr3,
            mmap_next: AtomicU64::new(USER_MMAP_BASE),
            mem_limit_pages: AtomicU64::new(0),
            mappings: IrqMutex::new(Vec::new()),
            caps: IrqMutex::new(CapTable::new()),
            abi: AtomicU8::new(AbiKind::Native as u8),
            foreign: IrqMutex::new(ForeignState::new()),
            live_threads: AtomicUsize::new(0),
            exited: AtomicBool::new(false),
            exit_code: AtomicI64::new(0),
            exit_code_set: AtomicBool::new(false),
        }
    }

    /// First writer wins (a fault-kill must not be overwritten by a racing exit).
    pub fn set_exit_code(&self, code: i64) {
        if !self.exit_code_set.swap(true, Ordering::SeqCst) {
            self.exit_code.store(code, Ordering::SeqCst);
        }
    }

    pub fn abi(&self) -> AbiKind {
        AbiKind::from_u8(self.abi.load(Ordering::Relaxed))
    }

    pub fn set_abi(&self, a: AbiKind) {
        self.abi.store(a as u8, Ordering::Relaxed);
    }

    pub fn has_exited(&self) -> bool {
        self.exited.load(Ordering::SeqCst)
    }

    /// Map fresh anonymous pages into this process and remember them for cleanup.
    /// Pages currently mapped in this address space (anonymous + shared views).
    pub fn mem_pages(&self) -> u64 {
        self.mappings.lock().iter().map(|m| m.pages as u64).sum()
    }

    pub fn map_region(&self, va: u64, pages: usize, flags: VmFlags) -> Result<(), vmm::VmError> {
        let lim = self.mem_limit_pages.load(Ordering::Relaxed);
        if lim != 0 && self.mem_pages() + pages as u64 > lim {
            return Err(vmm::VmError::OutOfFrames); // per-process memory limit reached
        }
        let mut sp = self.space.lock();
        let space = sp.as_mut().ok_or(vmm::VmError::NotMapped)?;
        space.map_anon(VirtAddr::new(va), pages, flags)?;
        drop(sp);
        self.mappings.lock().push(Mapping { va, pages, owned: true, _keep: None });
        Ok(())
    }

    /// fork: give `child` a private copy of every anonymous page this process has mapped (same addresses, same
    /// permissions). Shared (IPC) views are not copied. Eager copy: simple and safe, no copy-on-write.
    pub fn fork_memory_into(&self, child: &Process) -> Result<(), ()> {
        use crate::mm::{frame, vmm::phys_to_virt};
        let maps = self.mappings.lock();
        let mut psp = self.space.lock();
        let mut csp = child.space.lock();
        let (Some(ps), Some(cs)) = (psp.as_mut(), csp.as_mut()) else { return Err(()) };
        let mut child_maps = child.mappings.lock();
        for m in maps.iter().filter(|m| m.owned) {
            let mut copied = 0usize;
            for i in 0..m.pages {
                let va = VirtAddr::new(m.va + i as u64 * PAGE_SIZE);
                let Some((src, flags)) = ps.query(va) else { continue };
                let Some(dst) = frame::allocate_frame() else { return Err(()) };
                // SAFETY: both frames are 4 KiB HHDM-mapped frames (one the parent's, one freshly allocated for the child).
                unsafe { core::ptr::copy_nonoverlapping(phys_to_virt(src.start_address()), phys_to_virt(dst.start_address()), PAGE_SIZE as usize) };
                if cs.map(va, dst, flags).is_err() {
                    frame::deallocate_frame(dst);
                    return Err(());
                }
                copied += 1;
            }
            // pages are recorded per mapping entry; holes (partial munmap) simply stay unmapped in the child too
            if copied > 0 {
                child_maps.push(Mapping { va: m.va, pages: m.pages, owned: true, _keep: None });
            }
        }
        child.mmap_next.store(self.mmap_next.load(Ordering::SeqCst), Ordering::SeqCst);
        child.mem_limit_pages.store(self.mem_limit_pages.load(Ordering::Relaxed), Ordering::Relaxed);
        Ok(())
    }

    /// execve: drop the whole user image (the address space object, i.e. the page-table root, stays).
    pub fn wipe_user_mappings(&self) {
        let old: alloc::vec::Vec<Mapping> = core::mem::take(&mut *self.mappings.lock());
        let mut sp = self.space.lock();
        if let Some(space) = sp.as_mut() {
            for m in old {
                for i in 0..m.pages {
                    let va = VirtAddr::new(m.va + i as u64 * PAGE_SIZE);
                    if m.owned {
                        let _ = space.unmap_free(va);
                    } else {
                        let _ = space.unmap(va);
                    }
                }
            }
        }
        self.mmap_next.store(USER_MMAP_BASE, Ordering::SeqCst);
    }

    /// munmap semantics: unmap `pages` pages at `addr` wherever they are mapped, trimming/splitting the bookkeeping
    /// entries they belong to (owned pages are freed). Unmapped holes are ignored.
    pub fn unmap_range(&self, addr: u64, pages: usize) {
        let end = addr + pages as u64 * PAGE_SIZE;
        let mut maps = self.mappings.lock();
        let old: alloc::vec::Vec<Mapping> = core::mem::take(&mut *maps);
        let mut sp = self.space.lock();
        for m in old {
            let mend = m.va + m.pages as u64 * PAGE_SIZE;
            if mend <= addr || m.va >= end {
                maps.push(m);
                continue;
            }
            if m.va < addr {
                maps.push(Mapping { va: m.va, pages: ((addr - m.va) / PAGE_SIZE) as usize, owned: m.owned, _keep: m._keep.clone() });
            }
            if mend > end {
                maps.push(Mapping { va: end, pages: ((mend - end) / PAGE_SIZE) as usize, owned: m.owned, _keep: m._keep.clone() });
            }
            if let Some(space) = sp.as_mut() {
                let lo = m.va.max(addr);
                let hi = mend.min(end);
                let mut v = lo;
                while v < hi {
                    if let Ok(va) = VirtAddr::try_new(v) {
                        if m.owned {
                            let _ = space.unmap_free(va);
                        } else {
                            let _ = space.unmap(va);
                        }
                    }
                    v += PAGE_SIZE;
                }
            }
        }
    }

    /// Map a shared-memory object into this process; returns the user VA.
    pub fn map_shared(&self, mem: &Arc<MemObject>, writable: bool) -> Result<u64, i64> {
        use crate::sys::errno::ENOMEM;
        let pages = mem.pages();
        let va = self
            .mmap_next
            .fetch_add((pages as u64 + 1) * PAGE_SIZE, Ordering::SeqCst); // +1 guard page
        if !crate::mm::layout::is_user_range(va, pages as u64 * PAGE_SIZE) {
            return Err(ENOMEM);
        }
        let flags = if writable { VmFlags::WRITE | VmFlags::USER } else { VmFlags::USER };
        let mut g = self.space.lock();
        let space = g.as_mut().ok_or(ENOMEM)?;
        for (i, &f) in mem.frames().iter().enumerate() {
            if space.map(VirtAddr::new(va + i as u64 * PAGE_SIZE), f, flags).is_err() {
                for j in 0..i {
                    let _ = space.unmap(VirtAddr::new(va + j as u64 * PAGE_SIZE));
                }
                return Err(ENOMEM);
            }
        }
        drop(g);
        self.mappings.lock().push(Mapping { va, pages, owned: false, _keep: Some(mem.clone()) });
        Ok(va)
    }
}

impl Process {
    /// Free everything an exited process owns: user pages, page tables, open files and sockets, network grants.
    /// Idempotent. Called when the last thread has been reaped (a parent may keep its `Arc<Process>` in a capability
    /// long after that, e.g. to read the exit code - that must not pin the memory), and again from `Drop`.
    pub fn release_resources(&self) {
        let space = self.space.lock().take();
        if let Some(mut sp) = space {
            for m in self.mappings.lock().iter() {
                for i in 0..m.pages {
                    let va = VirtAddr::new(m.va + i as u64 * PAGE_SIZE);
                    if m.owned {
                        let _ = sp.unmap_free(va);
                    } else {
                        let _ = sp.unmap(va);
                    }
                }
            }
            sp.destroy();
        }
        self.mappings.lock().clear();
        let (fds, grants) = {
            let mut f = self.foreign.lock();
            (core::mem::take(&mut f.fds), core::mem::take(&mut f.net_grants))
        };
        drop(fds); // sockets / listeners close here, outside the foreign-state lock
        drop(grants);
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.release_resources();
    }
}

static KERNEL_PROCESS: Once<Arc<Process>> = Once::new();

pub fn kernel_process() -> Arc<Process> {
    KERNEL_PROCESS
        .call_once(|| {
            let cr3 = vmm::kernel_space().lock().pml4_frame();
            Arc::new(Process::new(0, "kernel", None, cr3))
        })
        .clone()
}

// -------------------------------------------------------------- thread -----

pub const READY: u8 = 0;
pub const RUNNING: u8 = 1;
pub const SLEEPING: u8 = 2;
pub const BLOCKED: u8 = 3;
pub const DEAD: u8 = 4;

pub struct Thread {
    pub tid: u64,
    pub name: String,
    pub process: Arc<Process>,
    pub(crate) saved_rsp: UnsafeCell<u64>,
    pub(crate) kstack_top: u64,
    _kstack: Option<KernelStack>,
    entry: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    pub(crate) fpu: UnsafeCell<Box<FxArea>>,
    pub(crate) state: AtomicU8,
    pub(crate) wake_at: AtomicU64,
    /// User FS/GS base (Linux TLS via arch_prctl, NT TEB); restored on every switch.
    pub(crate) fs_base: AtomicU64,
    pub(crate) gs_base: AtomicU64,
    /// Linux signal mask of this thread (`u64::MAX` = never set: inherit the process-level mask on first use)
    pub(crate) sigmask: AtomicU64,
    /// signals sent to this thread only (tkill/tgkill/pthread_kill)
    pub(crate) tpending: AtomicU64,
    pub is_idle: bool,
}

// SAFETY: the UnsafeCell fields (saved RSP, FPU area) are only touched by the
// context-switch code with interrupts disabled on the single CPU.
unsafe impl Sync for Thread {}
unsafe impl Send for Thread {}

impl Thread {
    pub(crate) fn state(&self) -> u8 {
        self.state.load(Ordering::SeqCst)
    }
    pub(crate) fn set_state(&self, s: u8) {
        self.state.store(s, Ordering::SeqCst)
    }
    pub(crate) fn take_entry(&self) -> Option<Box<dyn FnOnce() + Send>> {
        self.entry.lock().take()
    }
}

/// `(pid, tid)` of the running thread.
pub fn current_ids() -> (u64, u64) {
    let t = sched::current();
    (t.process.pid, t.tid)
}

/// Like `current_ids` but safe before the scheduler exists (returns zeros).
pub fn try_current_ids() -> (u64, u64) {
    sched::try_current().map_or((0, 0), |t| (t.process.pid, t.tid))
}

pub fn current_process() -> Arc<Process> {
    sched::current().process.clone()
}

/// Create the idle thread out of the boot context and enable FPU/SSE for users.
pub fn init() {
    crate::arch::x86_64::context::enable_fpu();
    let idle = Arc::new(Thread {
        tid: 0,
        name: String::from("idle"),
        process: kernel_process(),
        saved_rsp: UnsafeCell::new(0),
        kstack_top: crate::boot::boot_stack_top(),
        _kstack: None,
        entry: Mutex::new(None),
        fpu: UnsafeCell::new(Box::new(FxArea::new())),
        state: AtomicU8::new(RUNNING),
        wake_at: AtomicU64::new(0),
        fs_base: AtomicU64::new(0),
        gs_base: AtomicU64::new(0),
        sigmask: AtomicU64::new(u64::MAX),
        tpending: AtomicU64::new(0),
        is_idle: true,
    });
    sched::install_idle(idle);
}

fn create_thread(process: &Arc<Process>, name: &str, f: Box<dyn FnOnce() + Send>) -> Option<Arc<Thread>> {
    let stack = KernelStack::new(KERNEL_STACK_PAGES)?;
    let top = stack.top().as_u64();
    // SAFETY: `top` is the aligned end of a freshly mapped, unused kernel stack.
    let rsp = unsafe { crate::arch::x86_64::context::prepare_stack(top, sched::thread_start) };
    process.live_threads.fetch_add(1, Ordering::SeqCst);
    let t = Arc::new(Thread {
        tid: NEXT_TID.fetch_add(1, Ordering::SeqCst),
        name: String::from(name),
        process: process.clone(),
        saved_rsp: UnsafeCell::new(rsp),
        kstack_top: top,
        _kstack: Some(stack),
        entry: Mutex::new(Some(f)),
        fpu: UnsafeCell::new(Box::new(FxArea::new())),
        state: AtomicU8::new(READY),
        wake_at: AtomicU64::new(0),
        fs_base: AtomicU64::new(0),
        gs_base: AtomicU64::new(0),
        sigmask: AtomicU64::new(u64::MAX),
        tpending: AtomicU64::new(0),
        is_idle: false,
    });
    {
        let mut reg = THREADS.lock();
        reg.retain(|w| w.strong_count() > 0);
        reg.push(Arc::downgrade(&t));
    }
    Some(t)
}

/// Registry of live threads, for tid lookups (tkill/tgkill).
static THREADS: IrqMutex<Vec<alloc::sync::Weak<Thread>>> = IrqMutex::new(Vec::new());

pub fn find_thread(tid: u64) -> Option<Arc<Thread>> {
    THREADS.lock().iter().filter_map(|w| w.upgrade()).find(|t| t.tid == tid)
}

/// Start a kernel thread (runs in the kernel process, kernel address space).
pub fn spawn_kernel<F: FnOnce() + Send + 'static>(name: &str, f: F) -> Option<u64> {
    let t = create_thread(&kernel_process(), name, Box::new(f))?;
    let tid = t.tid;
    sched::enqueue(t);
    Some(tid)
}

/// Add a user thread to `process` starting at `rip` with stack pointer `rsp`.
pub fn spawn_user_thread(process: &Arc<Process>, name: &str, rip: u64, rsp: u64, arg0: u64) -> Option<u64> {
    spawn_user_thread_ex(process, name, rip, rsp, arg0, 0)
}

/// Like `spawn_user_thread`, with an initial user GS base (NT TEB).
pub fn spawn_user_thread_ex(process: &Arc<Process>, name: &str, rip: u64, rsp: u64, arg0: u64, gs_base: u64) -> Option<u64> {
    let t = create_thread(
        process,
        name,
        Box::new(move || {
            // SAFETY: rip/rsp were validated by the creator as user addresses mapped
            // in this process; the scheduler activated this process's CR3 before running us.
            unsafe { crate::arch::x86_64::syscall::enter_user(rip, rsp, arg0) }
        }),
    )?;
    t.gs_base.store(gs_base, Ordering::SeqCst);
    let tid = t.tid;
    sched::enqueue(t);
    Some(tid)
}

/// Like `spawn_user_thread_ex`, also with an initial user FS base (Linux TLS for `clone(CLONE_SETTLS)`).
pub fn spawn_user_thread_full(process: &Arc<Process>, name: &str, rip: u64, rsp: u64, arg0: u64, gs_base: u64, fs_base: u64) -> Option<u64> {
    let t = create_thread(
        process,
        name,
        Box::new(move || {
            // SAFETY: as in `spawn_user_thread_ex`.
            unsafe { crate::arch::x86_64::syscall::enter_user(rip, rsp, arg0) }
        }),
    )?;
    t.gs_base.store(gs_base, Ordering::SeqCst);
    t.fs_base.store(fs_base, Ordering::SeqCst);
    let tid = t.tid;
    sched::enqueue(t);
    Some(tid)
}

/// Start a thread in `process` that begins in user mode with exactly `regs` (and rax = 0): a forked child.
pub fn spawn_user_thread_regs(process: &Arc<Process>, name: &str, regs: crate::arch::x86_64::syscall::UserRegs, fs_base: u64, gs_base: u64) -> Option<u64> {
    let t = create_thread(
        process,
        name,
        Box::new(move || {
            // SAFETY: the child's address space is a copy of the parent's, so rip/rsp are valid there.
            unsafe { crate::arch::x86_64::syscall::enter_user_regs(&regs) }
        }),
    )?;
    t.gs_base.store(gs_base, Ordering::SeqCst);
    t.fs_base.store(fs_base, Ordering::SeqCst);
    let tid = t.tid;
    sched::enqueue(t);
    Some(tid)
}

/// Allocate an empty user process (fresh address space, no threads yet).
pub fn create_process(name: &str) -> Option<Arc<Process>> {
    let space = AddressSpace::new_user()?;
    let cr3 = space.pml4_frame();
    let pid = NEXT_PID.fetch_add(1, Ordering::SeqCst);
    let p = Arc::new(Process::new(pid, name, Some(space), cr3));
    register(&p);
    Some(p)
}

#[derive(Debug)]
pub enum SpawnError {
    OutOfMemory,
}

/// Startup parameters handed to a user program via a read-only info page.
pub struct InitSpec {
    pub role: u64,
    pub n: u64,
    pub side: u64,
    /// Capabilities installed before the first instruction runs (first 5 handles go in the info page).
    pub caps: Vec<(CapObject, Rights)>,
}

/// Layout of the info page (`u64` words): `[role, n, side, handle0..handle4]`.
pub const INFO_HANDLES: usize = 5;

/// Create a process from a flat binary (entry = offset 0, loaded at `USER_CODE_BASE`).
/// With `init`, RDI receives the address of the info page and RSP is 8 mod 16 (SysV entry).
pub fn spawn_process(name: &str, image: &[u8], init: Option<InitSpec>) -> Result<Arc<Process>, SpawnError> {
    let space = AddressSpace::new_user().ok_or(SpawnError::OutOfMemory)?;
    let cr3 = space.pml4_frame();
    let pid = NEXT_PID.fetch_add(1, Ordering::SeqCst);
    let proc = Arc::new(Process::new(pid, name, Some(space), cr3));
    register(&proc);

    let code_pages = ((image.len() as u64 + PAGE_SIZE - 1) / PAGE_SIZE).max(1) as usize;
    proc.map_region(USER_CODE_BASE, code_pages, VmFlags::WRITE | VmFlags::USER)
        .map_err(|_| SpawnError::OutOfMemory)?;
    {
        let mut g = proc.space.lock();
        let sp = g.as_mut().unwrap();
        for (i, chunk) in image.chunks(PAGE_SIZE as usize).enumerate() {
            let va = VirtAddr::new(USER_CODE_BASE + i as u64 * PAGE_SIZE);
            let pa = sp.translate(va).ok_or(SpawnError::OutOfMemory)?;
            // SAFETY: freshly mapped, zeroed, exclusively owned page reachable via the HHDM.
            unsafe { core::ptr::copy_nonoverlapping(chunk.as_ptr(), vmm::phys_to_virt(pa), chunk.len()) };
        }
        // W^X: drop write, allow execute.
        for i in 0..code_pages {
            sp.protect(VirtAddr::new(USER_CODE_BASE + i as u64 * PAGE_SIZE), VmFlags::EXEC | VmFlags::USER)
                .map_err(|_| SpawnError::OutOfMemory)?;
        }
    }
    let stack_base = USER_STACK_TOP - USER_STACK_PAGES as u64 * PAGE_SIZE;
    proc.map_region(stack_base, USER_STACK_PAGES, VmFlags::WRITE | VmFlags::USER)
        .map_err(|_| SpawnError::OutOfMemory)?;

    let (rsp, arg0) = match init {
        None => (USER_STACK_TOP, 0),
        Some(spec) => {
            let mut words = [0u64; 3 + INFO_HANDLES];
            words[0] = spec.role;
            words[1] = spec.n;
            words[2] = spec.side;
            {
                let mut caps = proc.caps.lock();
                for (i, (obj, rights)) in spec.caps.into_iter().enumerate() {
                    let h = caps.insert(obj, rights).map_err(|_| SpawnError::OutOfMemory)?;
                    if i < INFO_HANDLES {
                        words[3 + i] = h;
                    }
                }
            }
            proc.map_region(USER_INFO_BASE, 1, VmFlags::WRITE | VmFlags::USER)
                .map_err(|_| SpawnError::OutOfMemory)?;
            let mut g = proc.space.lock();
            let sp = g.as_mut().unwrap();
            let pa = sp.translate(VirtAddr::new(USER_INFO_BASE)).ok_or(SpawnError::OutOfMemory)?;
            // SAFETY: freshly mapped, exclusively owned page; 64 bytes fit in it.
            unsafe {
                core::ptr::copy_nonoverlapping(words.as_ptr() as *const u8, vmm::phys_to_virt(pa), core::mem::size_of_val(&words))
            };
            sp.protect(VirtAddr::new(USER_INFO_BASE), VmFlags::USER).map_err(|_| SpawnError::OutOfMemory)?;
            (USER_STACK_TOP - 8, USER_INFO_BASE)
        }
    };

    crate::audit_log!(crate::audit::EV_PROC_SPAWN, 0, 0, pid, 0, 0);
    spawn_user_thread(&proc, name, USER_CODE_BASE, rsp, arg0).ok_or(SpawnError::OutOfMemory)?;
    Ok(proc)
}

/// Legacy helper: flat binary with no init info.
pub fn spawn_user(name: &str, image: &[u8]) -> Result<Arc<Process>, SpawnError> {
    spawn_process(name, image, None)
}

/// Block (by sleeping in 1 ms steps) until `p` has exited; returns its exit code.
pub fn wait_process(p: &Arc<Process>) -> i64 {
    while !p.has_exited() {
        sleep_ms(1);
    }
    p.exit_code.load(Ordering::SeqCst)
}
