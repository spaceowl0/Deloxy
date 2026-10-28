# Deloxy OS - Roadmap: Milestone 2 -> v0.1.0 Alpha

Baseline (verified): Limine boot, COM1 logger, GDT/TSS/IDT with #PF/#DF/#GP, bitmap frame allocator.
Booted in QEMU (BIOS, 256 MiB): 249 MiB usable, frame alloc + double-free rejection working.

## 0. Design decisions that shape every phase

| Topic | Decision | Why |
|---|---|---|
| User address range | `0x0000_0000_0000_0000 ..= 0x0000_7FFF_FFFF_FFFF` | x86_64 has 48-bit canonical addressing; `0x7FFF_FFFF_FFFF_FFFF` is NOT canonical and would #GP. |
| "Hardware capability tokens" | Kernel-enforced, unforgeable handles (index + generation + rights), seL4/Fuchsia style | x86_64 has no capability hardware (that is CHERI/Morello). Isolation comes from page tables + ring 3. Optional later hardening: Memory Protection Keys. |
| "Hardware-accelerated GUI" | Alpha = software renderer (SSE2 blits, dirty rects). GPU path (virtio-gpu 2D) is post-alpha | A real GPU driver is a project by itself; the protocol is designed so the backend can be swapped. |
| Microkernel vs alpha reality | Drivers live in-kernel for alpha behind trait boundaries; IPC + capabilities are real from Phase 4 so drivers can move out later | Keeps the alpha achievable without changing the security model. |
| Windows PoC scope | Native PE loader + hand-written kernel32 shim (~40 functions) running a mingw-built static console exe | "Unmodified" exe means unmodified binary, not unmodified Windows. Full NT/ucrt emulation is post-alpha. |
| "Air-gapped" | NIC is disabled until the user grants a `NetCap`; updates are user-initiated pulls only | Air-gapped-by-default, not "no network code". |
| SMP | BSP only until after alpha; per-CPU structs (GS base) introduced in Phase 3 so SMP is additive | Avoids a rewrite later. |
| Offline dev | `cargo vendor` (done for M1 deps); vendor `smoltcp`, `ed25519-compact`, `sha2` before Phase 7 | No internet needed to build. |

Cross-cutting rules (all phases):
* Every `unsafe` block has a `// SAFETY:` comment. Port/MMIO access only inside driver modules.
* Locks touched by interrupt handlers use `IrqMutex` (interrupt-disabling). Plain `spin::Mutex` only for data never touched from IRQ context.
* Errors: `#[repr(i64)] enum Errno` shared by kernel and user ABI. Syscall ABI is versioned (`SYS_ABI_VERSION`).
* Tests run in QEMU: `isa-debug-exit` (iobase 0xf4) for pass/fail exit codes + serial log assertions. Driver: `tools/qemu-test.sh`.

---

## Milestone 1.5 - Hardening pass (small, do first)
Objective: remove hazards in M1 before building on it.
* Serial uses `spin::Mutex` + `without_interrupts`; switch to `sync::IrqMutex` (draft exists in `src/sync.rs`).
* Kernel stack: Limine's default stack is small; allocate an own 64 KiB boot stack (guard page after Phase 2).
* Panic/fault paths: dump a short backtrace of return addresses (frame-pointer walk, `-Cforce-frame-pointers=yes`).
* `tools/qemu-test.sh` + exit-code protocol (0x10 = pass, 0x11 = fail via `isa-debug-exit`).
Exit: `tools/qemu-test.sh` boots, greps `Milestone 1 complete`, returns 0 within 10 s.

---

## Phase 2 - Memory management & kernel heap
Objective: own the page tables, give the kernel `alloc`, define address-space layout.

Layout:
```
src/mm/mod.rs      // init order, MemoryStats
src/mm/frame.rs    // + allocate_contiguous(n, align), reserve_range()
src/mm/layout.rs   // all virtual address constants
src/mm/vmm.rs      // Vmm, AddressSpace, map/unmap/protect, map_mmio
src/mm/heap.rs     // #[global_allocator]
src/mm/slab.rs     // fixed-size block cache (32..2048) on top of heap pages (optional but recommended)
```
Virtual layout (`layout.rs`):
```rust
pub const USER_START:      u64 = 0x0000_0000_0000_1000;      // page 0 unmapped (null guard)
pub const USER_END:        u64 = 0x0000_7FFF_FFFF_F000;
pub const HHDM_BASE:       u64 = 0xFFFF_8000_0000_0000;      // from Limine
pub const KERNEL_HEAP:     u64 = 0xFFFF_C000_0000_0000;      // 1 GiB max, grows on demand
pub const KERNEL_MMIO:     u64 = 0xFFFF_D000_0000_0000;      // uncached device mappings
pub const KERNEL_STACKS:   u64 = 0xFFFF_E000_0000_0000;      // guard-paged per-thread stacks
pub const KERNEL_IMAGE:    u64 = 0xFFFF_FFFF_8000_0000;      // linker.ld
```
Key APIs:
```rust
bitflags! { pub struct VmFlags: u32 { const READ=1; const WRITE=2; const EXEC=4; const USER=8; const MMIO=16; const GLOBAL=32; } }
pub struct AddressSpace { pml4: PhysFrame, /* user-half only owned */ }
impl AddressSpace {
    pub fn new_user() -> Self;                    // clones kernel-half PML4 entries 256..512
    pub fn map(&mut self, va: VirtAddr, pa: PhysFrame, f: VmFlags) -> Result<(), VmError>;
    pub fn map_anon(&mut self, va: VirtAddr, pages: usize, f: VmFlags) -> Result<(), VmError>;
    pub fn unmap(&mut self, va: VirtAddr) -> Option<PhysFrame>;
    pub fn protect(&mut self, va: VirtAddr, f: VmFlags) -> Result<(), VmError>;
    pub fn translate(&self, va: VirtAddr) -> Option<PhysAddr>;
    pub unsafe fn activate(&self);                // write CR3
}
pub fn kernel_space() -> &'static IrqMutex<AddressSpace>;
pub fn map_mmio(phys: u64, len: usize) -> Option<*mut u8>;   // used by apic.rs (already drafted)
pub fn copy_from_user(dst: &mut [u8], src: UserPtr) -> Result<(), Errno>; // used from Phase 3
```
* Use `x86_64::structures::paging::OffsetPageTable` over the HHDM; implement `FrameAllocator` for the bitmap allocator.
* Enable NX (EFER.NXE), WP (CR0.WP), SMEP/SMAP when CPUID reports them (SMAP needs `stac/clac` in `copy_*_user`).
* Kernel-half PML4 entries are pre-populated once so all address spaces share them.
* Heap: start with `linked_list_allocator`-style own implementation (`Heap` + fixed-size-block fast path) behind `IrqMutex`; map 1 MiB initially, grow by mapping more pages on OOM.
* TLB: `invlpg` on unmap/protect; full flush on CR3 switch is automatic (use PCID later).

Exit criteria:
1. Boot log prints `heap: 1 MiB at 0xffffc00000000000`, then a self-test: `Box<[u8;4096]>`, `Vec<u64>` of 100k pushes, `Arc<Mutex<String>>`, and all freed leaves `heap.used == 0`.
2. Deliberate write to unmapped kernel VA is reported as #PF with CR2 (test-only feature `--features test-pf`).
3. `frame.free` returns to its pre-test value (no leak).
4. Guard-page test: overflow of a test stack hits the guard and faults on the #DF/#PF path with a readable message.

---

## Phase 3 - Interrupts, timer, preemptive scheduling, SYSCALL
Objective: run multiple kernel threads preemptively, then enter ring 3 via SYSCALL/SYSRET.

Already drafted (uncompiled, need `vmm::map_mmio`): `src/sync.rs`, `src/time.rs`, `arch/x86_64/{cpu,pic,acpi,apic}.rs`.

Layout:
```
src/arch/x86_64/{cpu,pic,acpi,apic,percpu,syscall}.rs
src/arch/x86_64/syscall_entry.S      // included with core::arch::global_asm!(include_str!(..))
src/arch/x86_64/context.rs           // switch_context asm
src/task/{mod,process,thread,sched,wait,futex}.rs
src/sys/{mod,dispatch,errno,uaccess}.rs
```
GDT order (required by SYSRET arithmetic): null, kcode `0x08`, kdata `0x10`, udata `0x18`, ucode `0x20`, TSS `0x28`.
`STAR[47:32]=0x08`, `STAR[63:48]=0x10` (SYSRET: SS=0x18|3, CS=0x20|3). `LSTAR=syscall_entry`, `SFMASK=IF|DF|TF`, `EFER.SCE=1`.
Timer: calibrate LAPIC timer against PIT once, periodic vector `0x20`, 1 kHz tick, 10 ms quantum. Spurious `0xFF`. PIC remapped+masked. IOAPIC route for keyboard (IRQ1) later.

Data structures:
```rust
#[repr(C)] pub struct PerCpu { self_ptr: *mut PerCpu, kernel_rsp: u64, user_rsp_scratch: u64, current: *mut Thread, lapic_id: u32 }
// GS base = PerCpu; SWAPGS on syscall entry/exit; TSS.rsp0 updated on every switch.

pub struct Process { pub pid: Pid, pub space: AddressSpace, pub caps: CapTable /*Phase 4*/, pub threads: Vec<Tid>, pub state: ProcState }
pub struct Thread  { pub tid: Tid, pub pid: Pid, kstack: KernelStack, saved_rsp: u64, pub state: ThreadState, fpu: FxArea /*512B fxsave, 16-aligned*/, wake_at: u64 }
pub enum ThreadState { Ready, Running, Blocked(WaitReason), Sleeping, Dead }
pub trait Scheduler { fn enqueue(&mut self, t: Arc<Thread>); fn pick_next(&mut self) -> Option<Arc<Thread>>; fn tick(&mut self, now: u64) -> bool; }
pub struct RoundRobin { queue: VecDeque<Arc<Thread>>, quantum_ms: u32 }
```
* `switch_context(prev_rsp: *mut u64, next_rsp: u64)` pushes/pops rbx, rbp, r12-r15 + rflags; new threads start at a trampoline that `iretq`s (user) or calls the entry fn (kernel).
* User code is built for a target with SSE, so FXSAVE/FXRSTOR each switch (`CR4.OSFXSR|OSXMMEXCPT`, `CR0.EM=0, MP=1`); the kernel itself stays soft-float.
* Syscall table in `sys/dispatch.rs`: `fn(&mut SyscallFrame) -> i64`, args in rdi, rsi, rdx, r10, r8, r9, number in rax. Initial set: `exit, yield, sleep_ms, write_debug, mmap_anon, munmap, thread_spawn, futex_wait/wake, time_now`.
* User pointers only through `uaccess::{copy_from_user, copy_to_user}` (range-checked against `USER_END`, SMAP-aware).
* Idle thread does `sti; hlt`.

Exit criteria:
1. Three kernel threads print interleaved `A`/`B`/`C` for 3 s under 1 kHz preemption; ticks == uptime within 2 %.
2. `sleep_ms(500)` wakes at 500-510 ms.
3. A hand-assembled ring-3 blob (embedded bytes) calls `write_debug` then `exit(42)`; kernel logs `pid 1 exited with 42`.
4. Ring-3 null deref and privileged-instruction test both kill only that process (no kernel halt).

---

## Phase 4 - Capabilities, IPC & lockless audit (`deloxy-audit`)
Objective: every privilege check goes through capabilities; every syscall can emit an audit event without ever blocking.

Layout:
```
src/sys/cap/{mod,table,rights,object}.rs
src/ipc/{mod,ring,channel,shm}.rs
src/audit/{mod,event,sink}.rs
```
Lockless SPSC ring (used for audit AND IPC):
```rust
#[repr(align(64))] struct CachePadded<T>(T);
pub struct Spsc<T: Copy, const N: usize> {           // N power of two
    head: CachePadded<AtomicUsize>,                    // consumer
    tail: CachePadded<AtomicUsize>,                    // producer
    dropped: AtomicU64,
    buf: [UnsafeCell<MaybeUninit<T>>; N],
}
impl<T: Copy, const N: usize> Spsc<T, N> {
    pub fn push(&self, v: T) -> bool;   // Release store on tail; returns false + bumps `dropped` when full
    pub fn pop(&self) -> Option<T>;     // Acquire load on tail
}
```
* SPSC requires ONE producer: use one ring per CPU (BSP only for now) and a per-CPU producer; the consumer is the audit drain thread. Interrupt-context producers use a second ring.
```rust
#[repr(C)] #[derive(Clone, Copy)] pub struct AuditEvent { // 64 bytes, stable ABI
    ts_ns: u64, pid: u32, tid: u32, kind: u16, result: i16, _pad: u32, cap: u64, arg0: u64, arg1: u64, arg2: u64, seq: u64 }
macro_rules! audit_log { ($kind:expr, $cap:expr, $a0:expr, $a1:expr, $res:expr) => {...} } // non-blocking, no alloc
```
Capabilities:
```rust
#[derive(Clone, Copy, PartialEq, Eq)] #[repr(transparent)] pub struct CapHandle(u64); // [gen:24 | index:32 | kind:8]
bitflags! { pub struct Rights: u32 { const READ=1; const WRITE=2; const EXEC=4; const MAP=8; const GRANT=16; const DUP=32; const IO=64; const NET=128; const AUDIT_READ=256; } }
pub enum CapObject { Memory(Arc<MemObject>), Channel(Arc<Channel>), IoPort{base:u16,len:u16}, Mmio{phys:u64,len:usize}, Net(NetGrant), AuditStream, Process(Pid), Irq(u8) }
impl CapTable {
    pub fn insert(&mut self, obj: CapObject, r: Rights) -> CapHandle;
    pub fn lookup(&self, h: CapHandle, need: Rights) -> Result<&CapObject, Errno>; // checks gen + rights
    pub fn derive(&mut self, h: CapHandle, narrower: Rights) -> Result<CapHandle, Errno>; // attenuate only
    pub fn revoke(&mut self, h: CapHandle);
}
```
* Syscalls added: `cap_dup, cap_drop, cap_derive, chan_create, chan_send/recv (ring), shm_create, shm_map, audit_read`.
* Zero-copy IPC: `Channel` = two `Spsc` rings living in a shared-memory `MemObject` mapped into both processes; `futex` wake for notification; messages are fixed 64-byte headers + optional `CapHandle` transfer.
* Enforcement point: `dispatch()` resolves handles BEFORE calling the implementation and emits the audit event with the result (incl. denials).
* Init process gets a root set of caps; everything else is derived. No ambient authority (no global "open by path" until a filesystem service hands out caps).

Exit criteria:
1. Unit test in QEMU: 1M push/pop across producer/consumer threads, zero loss, order preserved; overflow test reports `dropped > 0` without blocking.
2. User process without `IO` cap calling `port_in` gets `Errno::PermissionDenied` and an audit event with `result=-EPERM` visible via `audit_read`.
3. Forged handle (random u64) and stale handle (reused slot, old generation) are rejected.
4. Two user processes exchange 100k messages over a shared-memory channel; throughput logged (target: > 1M msg/s in QEMU TCG is not required, just measured).

---

## Phase 5 - Framebuffer, input, compositor protocol
Objective: pixels and input; a window protocol independent of the window manager.

Layout:
```
src/drivers/fb/{mod,console,draw,font}.rs        // deloxy-fb
src/drivers/input/{ps2,keyboard,mouse,event}.rs
src/gfx/{surface,compositor,damage}.rs
src/wm/{protocol,server}.rs                     // deloxy-wm-protocol
user/deloxy-de/                                 // reference desktop (user-space, no_std client lib in user/libdeloxy)
```
* Limine `FramebufferRequest`; require 32bpp; map via HHDM (later PAT write-combining).
* `Framebuffer{ front: MmioSlice, back: Vec<u32> }`; `present(dirty: &[Rect])` copies rects only. Bitmap font (embedded 8x16 PSF) for the boot console (`log` mirrors to screen).
* PS/2: controller init (self-test, disable/enable ports), IRQ1/IRQ12 via IOAPIC, scancode set 1/2 -> `KeyEvent{code, pressed, mods}`, 3-byte mouse packets -> `MouseEvent{dx,dy,buttons}`. VirtIO-input deferred to Phase 7 (shares the virtio transport).
```rust
#[repr(C)] pub struct InputEvent { kind: u16, code: u16, value: i32, ts_ns: u64 }   // 16 bytes
#[repr(C, u32)] pub enum WmMsg {                   // fixed 64-byte slots over a Phase-4 channel
    CreateSurface{ id: u32, w: u32, h: u32, fmt: u32 }, AttachBuffer{ id: u32, shm: CapHandle, stride: u32 },
    Commit{ id: u32, damage: Rect }, Move{ id: u32, x: i32, y: i32 }, Focus{ id: u32 }, Close{ id: u32 },
    Input(InputEvent), Configure{ id: u32, w: u32, h: u32 } }
```
* Roles: **compositor** owns the framebuffer cap and composites committed surfaces (z-order, damage tracking); **window manager** (policy) is a separate client that only sends Move/Resize/Focus requests over the WM channel and never touches pixels. `deloxy-de` = a WM + panel + taskbar + a diagnostics window.
* Alpha simplification: compositor runs as a kernel thread; the protocol/ABI is identical so it moves to user space without client changes.

Exit criteria:
1. Boot shows banner + log on screen (QEMU `-display gtk|sdl`), no tearing during scroll.
2. Typing on the keyboard echoes to the console; mouse cursor moves at 60 Hz without flicker.
3. Two user client processes each draw an animated window; drag with mouse; focus changes on click.
4. `deloxy-de` shows a live diagnostics window (uptime, free frames, heap used, ticks, audit drops).
5. Screenshot test: `qemu ... -monitor` `screendump` compared to a golden PPM (tolerance 0).

---

## Phase 6 - Binary execution & syscall translation (`deloxy-wltd`)
Objective: load ELF and PE images into isolated user spaces and translate foreign ABIs to native caps.

Layout:
```
src/exec/{mod,elf,pe,loader,stack}.rs
src/abi/{mod,native,linux,nt}.rs
src/abi/nt/{kernel32,ntdll_min}.rs        // hand-written shim, no Microsoft code
```
```rust
pub trait BinaryFormat { fn probe(data: &[u8]) -> bool; fn load(data: &[u8], space: &mut AddressSpace) -> Result<LoadedImage, ExecError>; }
pub struct LoadedImage { entry: VirtAddr, stack_top: VirtAddr, brk: VirtAddr, abi: AbiKind, tls: Option<VirtAddr> }
pub enum AbiKind { Native, Linux, Nt }
pub trait Abi: Sync { fn handle_syscall(&self, p: &Process, f: &mut SyscallFrame) -> i64; fn setup_process(&self, p: &mut Process, img: &LoadedImage); }
```
* ELF64: PT_LOAD mapping with W^X (map RW, copy, then `protect` to final flags), static-PIE relocation (R_X86_64_RELATIVE), auxv + argv/envp on the initial stack.
* Linux table (subset for static binaries): `read, write, writev, open*, close, mmap, munmap, brk, exit, exit_group, arch_prctl(SET_FS), set_tid_address, clock_gettime, getpid, uname, ioctl(TCGETS)`. Every call maps onto caps the process was launched with (stdout = a `Channel` cap) - no ambient files.
* PE32+: DOS/NT headers, section mapping at ImageBase (or relocate via `.reloc`), import table resolved to stub addresses in a per-process thunk page; each stub does `syscall` with an NT-ABI number. Shim set (~40): `GetStdHandle, WriteFile, WriteConsoleA, ReadFile, ExitProcess, GetCommandLineA, GetModuleHandleA, GetProcAddress, VirtualAlloc/Free/Protect, HeapCreate/Alloc/Free, GetLastError/SetLastError, TlsAlloc/GetValue/SetValue, EnterCriticalSection/Leave/Initialize/Delete, GetSystemTimeAsFileTime, QueryPerformanceCounter, Sleep, GetCurrentProcessId/ThreadId, SetUnhandledExceptionFilter`.
* PoC binaries (built offline in `tests/bins/`): `hello_native` (Rust no_std, native ABI), `hello_linux` (static, `-nostdlib`), `hello_win.exe` (`x86_64-w64-mingw32-gcc -static -nostartfiles`, kernel32 only).
* Failure containment: unsupported syscall/import returns `ENOSYS` and logs `unimplemented: kernel32!Foo` once - this becomes the to-do list for the translator.

Exit criteria:
1. `run /bin/hello_native`, `run /bin/hello_linux`, `run /bin/hello_win.exe` each print their greeting and return exit code 0.
2. A PE with an unknown import fails cleanly with a named error, not a kernel panic.
3. ELF and PE fuzz corpus (truncated headers, overlapping sections, huge sizes) produces errors, never a fault in the kernel (run under `tools/fuzz-loaders.sh` with 10k mutated inputs).

---

## Phase 7 - PCI, VirtIO-net, default-deny firewall, update client (`deloxy-upd`)
Objective: controlled networking; signed, pull-only updates.

Layout:
```
src/drivers/pci/{mod,ecam,config,msix}.rs
src/drivers/virtio/{mod,pci_transport,queue}.rs
src/drivers/net/virtio_net.rs
src/net/{mod,stack,firewall,socket,dhcp}.rs      // stack: smoltcp (vendored) behind our Socket caps
src/upd/{mod,manifest,verify,fetch}.rs
```
* PCI: enumerate via ACPI MCFG (ECAM) with 0xCF8/0xCFC fallback; `PciDevice{bus,dev,func,vendor,device,class,bars}`; BAR sizing; MSI-X or legacy INTx routed through IOAPIC.
* VirtIO 1.x modern transport (capabilities: common/notify/isr/device), split virtqueues, DMA memory from `frame::allocate_contiguous`. Feature negotiation: `VIRTIO_F_VERSION_1`, MAC.
* NIC state: `Disabled` (default) -> `Enabled` only when a process presents a valid `NetGrant` cap.
```rust
pub struct NetGrant { pub remote: IpEndpointMask, pub proto: Proto, pub dir: Outbound, pub expires_ticks: u64, pub bytes_max: u64 }
pub struct Rule { action: Action /*Allow*/, proto: Proto, remote: Cidr, port: PortRange, cap_id: u64 }
// Default policy = Deny for ALL directions. No listening sockets in alpha. Every allow/deny -> audit event.
```
* Update flow (explicit, user-triggered from `deloxy-sh`: `upd check`): user grants a time-boxed `NetGrant` for one host:port -> agent fetches `manifest.json` + `manifest.sig` -> verify Ed25519 signature against a public key compiled into the kernel image -> check `version` strictly greater (rollback protection) -> fetch artifacts, verify SHA-256 from the manifest -> stage to `/updates/` -> apply only on user confirmation + reboot. No timers, no background polling, no telemetry.
```rust
#[repr(C)] pub struct Manifest { format: u32, version: [u16;3], min_version: [u16;3], created: u64, artifacts: Vec<Artifact> }
pub struct Artifact { name: String, size: u64, sha256: [u8;32], url_path: String }
```
* Crypto: `ed25519-compact` + `sha2` (both no_std); constant-time compare; reject on any parse error.
* Test server: `tools/mock-update-server.py` (host) with a test keypair; production key ceremony is out of scope for alpha but documented.

Exit criteria:
1. Boot log lists all PCI devices; virtio-net found under `-device virtio-net-pci`.
2. With no grant: `ping`/connect attempts are denied and audited; with a grant: DHCP + TCP to the mock server on QEMU user-net works.
3. Valid signed manifest -> `upd check` reports "update available"; tampered manifest, wrong key, replayed older version -> each rejected with a distinct error.
4. Packet capture (`-object filter-dump`) proves zero packets leave the NIC while no grant exists.

---

## Phase 8 - Shell, monitor, ISO, public test suite
Objective: something a stranger can download and boot.

Layout:
```
user/deloxy-sh/        // line editor, builtins: help, ls, cat, run, ps, caps, audit, upd, reboot, poweroff
user/deloxy-monitor/   // reads kernel stats via `sys_stat` -> text UI or a window in deloxy-de
src/fs/{ramfs,tar}.rs  // initramfs from a Limine module (USTAR), read-only, cap-based open
tools/{mkiso.sh,qemu-run.sh,qemu-test.sh,check-offline.sh}
tests/{boot.rs,heap.rs,sched.rs,caps.rs,loaders.rs,net.rs}   // run in QEMU, results via isa-debug-exit
```
* `sys_stat` returns a `#[repr(C)] SysStats{ uptime_ms, frames_total, frames_free, heap_used, procs, threads, ctx_switches, audit_dropped, net_tx, net_rx }`.
* ISO: xorriso hybrid BIOS+UEFI (Limine 8.x binaries vendored in `third_party/limine/`), `limine.conf`, kernel + initramfs module. Output `deloxy-v0.1.0-alpha.iso` + `SHA256SUMS` (+ signature when key exists).
* Public test suite = `tools/qemu-test.sh all` (must pass on a clean checkout, offline), plus a boot-time `selftest` cmdline switch.
* Docs: `README.md` (build/run), `docs/SECURITY.md` (threat model, what "capability" means here), `docs/ABI.md` (syscall table, versioned), `docs/KNOWN_ISSUES.md`.

Exit criteria:
1. `tools/mkiso.sh` on a clean offline machine produces the ISO; `qemu-system-x86_64 -M q35 -m 512M -cdrom deloxy-v0.1.0-alpha.iso -serial stdio` reaches the `deloxy-sh>` prompt in < 5 s.
2. In the shell: `ps`, `caps`, `audit`, `run hello_win.exe`, `upd check` (with grant) all work.
3. Test suite green in both BIOS and UEFI (OVMF) boots; ISO boots on at least one real machine.

---

## Milestone checklist

- [x] M1   Boot, serial log, GDT/IDT/TSS, frame allocator (verified in QEMU)
- [x] M1.5 Hardening: IrqMutex everywhere, boot stack, backtraces, QEMU test harness
- [x] M2   Phase 2: VMM, page tables, kernel heap, layout, NX/WP/SMEP
- [x] M3   Phase 3: ACPI/APIC timer, scheduler, context switch, SYSCALL/SYSRET, ring 3
- [x] M4   Phase 4: capabilities, SPSC rings, zero-copy IPC, `audit_log!`
- [x] M5   Phase 5: framebuffer, PS/2, compositor + WM protocol, `deloxy-de`
- [x] M6   Phase 6: ELF + PE loaders, Linux/NT ABI shims, three PoC binaries
- [x] M7   Phase 7 (verified; see HANDOFF s8 for the not-done list): PCI, VirtIO-net, firewall, signed pull-only updater
- [x] M8   Phase 8: shell, monitor, initramfs, ISO, public tests -> **v0.1.0 Alpha** (real-hardware boot NOT verified; see KNOWN_ISSUES)
- [x] P1   Post-alpha step 1: virtio-blk driver, crash-safe DeloxyStore, `Store` capability + syscalls 33-36, shell commands, persisted update staging + rollback floor (QEMU-verified; update *activation* still open, see HANDOFF s9b)
- [x] P2   deloxy-de v2: themes/customization (de.conf, hot reload), start menu, icons, Settings, minimize, tray + RTC clock
- [x] P3   deloxy-wltd v2: capability-gated files, glibc static ELF and MinGW PE (msvcrt subset, TLS) run unmodified
- [x] P4   deloxy-de v3: dock/glass/flat titles/shadows, PPM wallpapers, Files app + text viewer, calendar, Alt+Tab/Alt+F4/Super/Ctrl+Alt+T
- [x] P5   deloxy-wltd v3: interactive stdin, directories, file mmap, Win32 file API, scanf/strtol, qsort + atexit stubs
- [x] P6   deloxy-wltd v4: Linux clone/futex threads, pipes/dup/poll, Windows CreateThread + events/mutex/semaphores/critical sections/TLS
- [x] P7   Permissions (kernel-enforced consent, perms.db, `perms`), 128 MiB limits, kill_process, Task Manager, toasts, context menu, SRW locks + condition variables
- [x] P8   Sockets (Linux + Winsock) with per-destination network permission and minted NetGrants; Permissions manager GUI
- [x] P9   Full network access mode + custom time/data limits + internet-only (prompt, shell, Permissions manager)

**M1-M8 are done (verified in QEMU). Next: post-alpha work, see docs/HANDOFF.md section 9 and docs/KNOWN_ISSUES.md.** Original note: start with M1.5, then M2. M2 is the critical path: the APIC (`map_mmio`), scheduler stacks, user address spaces, and every later phase depend on the VMM and heap.
