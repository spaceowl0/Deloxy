# Deloxy - handoff document (state after Milestone 8 + post-alpha steps 1-8: persistent storage, deloxy-de v2-v5, deloxy-wltd v2-v6, application permissions (files + network, full-access mode, custom limits), resource limits, sockets; kernel v0.1.0-alpha)

Purpose: let a fresh chat (or a human) continue the project with no other context. Read this first, then `docs/ROADMAP.md`.
Everything claimed "verified" below was run in QEMU (BIOS boot, q35, 256 MiB) in the previous session.

## 1. What Deloxy is
A from-scratch, `#![no_std]` Rust x86_64 kernel (`deloxy-core`, target `x86_64-unknown-none`), booted by Limine (v8 protocol).
Goals: capability security (no ambient authority), zero-copy lock-free ring IPC, local audit stream (`deloxy-audit`),
binary compatibility layers (`deloxy-wltd`: Linux ELF + Windows PE), a desktop environment named **deloxy-de**,
air-gapped-by-default networking with a pull-only signed updater (`deloxy-upd`, done in M7).
Owner's naming: the desktop environment is called **deloxy-de** (compositor + window management + taskbar + built-in apps).

## 2. Milestone status
| M | Content | Status |
|---|---|---|
| 1 | Limine boot, COM1 logger, GDT/IDT/TSS, bitmap frame allocator | done |
| 1.5 | IrqMutex, own boot stack, backtraces, QEMU test harness | done |
| 2 | VMM (own PML4, NX/WP/SMEP), kernel heap, guard-paged stacks | done |
| 3 | ACPI MADT, LAPIC timer 1 kHz, preemptive RR scheduler, SYSCALL/SYSRET, ring 3, fault containment | done |
| 4 | Capabilities, SPSC rings, shared-memory channels, futex, audit stream | done |
| 5 | Framebuffer + boot console, PS/2 input, **deloxy-de** compositor + wm-protocol + 3 apps | done |
| 6 | ELF/PE loaders, Linux syscall layer, Win32 shim, console capability, 10k-case loader fuzz | done |
| 7 | PCI (ECAM+legacy), VirtIO-net, default-deny firewall + NetGrant, signed pull-only updater `deloxy-upd` | done |
| 8 | Shell (`deloxy-sh`), monitor, USTAR initramfs, ISO (BIOS+UEFI), `tools/test-all.sh` -> v0.1.0 Alpha | done |

## 3. Repository map (`deloxy-core/`)
```
Cargo.toml, rust-toolchain.toml, build.rs, linker.ld, limine.conf, .cargo/config.toml, vendor/ (deps vendored, offline)
src/main.rs            boot sequence (kmain), Limine requests, panic handler
src/boot.rs            _start stub (own 64 KiB stack), backtrace helper
src/sync.rs            IrqMutex (interrupt-disabling spinlock) - use for anything touched by IRQ handlers
src/time.rs            tick counter (1 kHz)
src/arch/x86_64/       gdt (+TSS, user segs), idt (exceptions, timer 0x20, kbd 0x21, mouse 0x2C, spurious 0xFF),
                       apic (LAPIC+IOAPIC+PIT calibration), acpi (RSDP->MADT, maps tables on demand), pic (disabled),
                       cpu (CPUID), context (switch_context asm, FXSAVE), syscall (SYSCALL entry asm, enter_user)
src/mm/                frame (bitmap allocator), vmm (AddressSpace, map/protect, MMIO, kernel stacks, shm views),
                       heap (size classes + coalescing fallback, grows on demand), layout (all VA constants)
src/task/              mod (Process, Thread, spawn_*), sched (RR scheduler, sleep, futex_block/wake, kill), blobs (include_bytes)
src/sys/               dispatch (native syscall table), uaccess (copy via HHDM), errno, abi (SysStats, shared with user)
src/cap/               CapTable, Rights, CapObject
src/ipc/               ring.rs (Spsc<T,N>, SHARED with user space), memobj (shared memory), mod (channels, Msg)
src/audit/             AuditEvent (64 B), lossy ring, audit_log! macro
src/gfx/               draw.rs + font.rs (SHARED with user space): Rect, Surface, text, blit; 8x16 font
src/wm/                proto.rs (SHARED): deloxy-wm-protocol messages; server.rs = deloxy-de compositor
src/drivers/blk/       virtio-blk driver (polled, 1 request in flight, fail-stop on timeout)
src/store/             DeloxyStore: crash-safe flat file store on a block device (+ RamDisk with write-failure injection for tests), global instance
src/drivers/pci/       ECAM/legacy enumeration, BAR sizing; virtio/ modern transport + split queues; net/virtio_net.rs
src/net/               mod (smoltcp stack, poll thread, tcp sockets), grant.rs (NetGrant), firewall.rs (default-deny, per-frame)
src/upd/               mod (HTTP/1.0 client, verify, policy, RAM staging), manifest.rs (strict JSON), keys.rs (TEST key), testvec.rs (generated)
src/drivers/           serial (COM1 + log backend, mirrors to screen), fb (framebuffer + console), input (ps2)
src/exec/              mod (build/spawn, validate, Linux stack), elf.rs, pe.rs
src/abi/               mod (AbiKind, ForeignState, console_write), linux.rs, nt.rs
src/selftest.rs        in-kernel tests (feature "selftest")
user/                  user programs: utest (cap/IPC tests), de (= deloxy-de-apps: anim/diag/bars), poc/ (hello_* sources),
                       blobs/ (committed build outputs), user.ld (flat), elf.ld (ELF)
tools/                 test-all.sh, ui-test.py, build-user.sh, build-poc.sh, gen_font.py, dev-container/{b.sh,run-test.sh}
docs/                  ROADMAP.md, HANDOFF.md (this), screenshots/
```
Files shared verbatim between kernel and user crates via `#[path]`: `ipc/ring.rs`, `gfx/draw.rs`, `gfx/font.rs`, `wm/proto.rs`, `sys/abi.rs`.
They must stay dependency-free (no `crate::` imports).

## 4. Key design decisions (do not silently change)
* **Single CPU (BSP only).** SYSCALL kernel stack is a global (`SYSCALL_KERNEL_RSP`), no SWAPGS/GS use in the kernel; user GS/FS are free
  for Linux TLS / NT TEB. All kernel code runs with IF=0 except idle and user mode, so syscalls are non-preemptible.
  SMP needs: per-CPU data (GS), per-CPU audit rings, TLB shootdowns, proper locking review.
* **Address space:** user `0x1000..0x7FFF_FFFF_F000` (NOT 0x7FFF_FFFF_FFFF_FFFF: non-canonical). Kernel half is shared by all PML4s
  (slots 256..512 pre-populated). HHDM `0xFFFF_8000_0000_0000`; heap `0xFFFF_C000_...`; MMIO `0xFFFF_D000_...`; shm views `0xFFFF_D800_...`;
  stacks `0xFFFF_E000_...`; scratch `0xFFFF_F000_...`; image `0xFFFF_FFFF_8000_0000`.
  User: images at fixed bases (flat blobs 0x400000; PE at its ImageBase), info page 0x300000, mmap area from 0x2000_0000_0000,
  NT thunk page 0x7FFE_0000_0000 (+TEB/PEB/strings), stack top 0x7FFF_FFFF_0000.
* **Strict W^X** everywhere (loaders reject W+X segments; VirtualAlloc refuses exec).
* **Capabilities** = `[gen:32|index:32]` handles, per-process table, rights narrowing only, cascade revoke, EBADF (bad/stale/forged) vs EPERM (rights).
  There is no capability *hardware* on x86_64: enforcement is kernel + page tables.
* **Foreign ABIs have no ambient authority:** Linux/NT stdout exists only with a `Console` capability (launch option).
* **Audit:** every syscall emits an event; EPERM/EBADF become `EV_CAP_DENIED`. Foreign-ABI sysno = nr | (abi<<16).
* **deloxy-de**: compositor is a kernel thread (alpha); clients are ring-3 processes using only channels + shared pixel buffers.
  Buffers are provisioned by the compositor at client launch (clients cannot create shared memory yet: needs a factory capability).
  WM policy (move/focus/raise/close) is built into the compositor; external WM client is post-alpha. Software rendering only.
* Kernel is soft-float (target has no SSE); user threads get FXSAVE/FXRSTOR per switch. No AVX/XSAVE support (QEMU default CPU lacks AVX).

## 5. Native syscall ABI (RAX = number; args RDI,RSI,RDX,R10,R8,R9; result RAX, negative = -errno)
0 exit, 1 yield, 2 sleep_ms, 3 write_debug(ptr,len), 4 mmap_anon(len), 5 munmap(addr,len), 6 thread_spawn(entry,stack_top), 7 thread_exit,
8 time_now_ms, 9 getpid, 10 gettid, 11 cap_drop, 12 cap_derive(h,rights), 13 cap_info(h), 14 shm_map(h), 15 futex_wait(addr,expected),
16 futex_wake(addr,n), 17 port_in(h,port), 18 port_out(h,port,val), 19 audit_read(h,buf,max), 20 stat(buf: SysStats).
Foreign processes (ELF without the Deloxy PT_NOTE, or PE) use Linux / NT conventions instead (dispatch checks `Process::abi()`).
Linux subset: read(0) write writev close fstat newfstatat mmap(anon) mprotect munmap brk rt_sig* ioctl(ENOTTY) nanosleep getpid uname exit exit_group
arch_prctl(SET_FS) set_tid_address gettimeofday clock_gettime getrandom (+ENOSYS/ENOENT stubs; unknown calls log once + ENOSYS).
Win32 shim (kernel32 only, 35 functions): ExitProcess GetStdHandle WriteFile WriteConsoleA GetCommandLineA GetModuleHandleA GetProcAddress(0) VirtualAlloc/Free
HeapCreate/GetProcessHeap/HeapAlloc/HeapReAlloc/HeapFree(no-op) Get/SetLastError Tls* *CriticalSection(no-op) GetSystemTimeAsFileTime QueryPerformanceCounter/Frequency
GetTickCount(64) Sleep GetCurrentProcess/ProcessId/ThreadId SetUnhandledExceptionFilter TerminateProcess. Unknown import = load error "unimplemented: dll!name".

## 6. How to build and test
Normal environment (online or vendored): nightly Rust with `rust-src`, target `x86_64-unknown-none`; `cargo build` -> `target/x86_64-unknown-none/debug/deloxy-core`.
Build an ISO with `tools/mkiso.sh <kernel-elf> <out.iso>` (Limine is vendored), then
`qemu-system-x86_64 -M q35 -m 256M -cdrom deloxy.iso -serial stdio`.
Test builds:
* `cargo build --features selftest` -> boot with `-device isa-debug-exit,iobase=0xf4,iosize=4`; QEMU exit status **33 = pass**, 35 = fail. Runs: heap, frames, VMM, user AS,
  guard page, timer rate, preemption, sleep, 5 asm ring-3 programs, SPSC 1M items, overflow, capabilities+audit, 100k-message IPC, ELF/PE PoCs,
  failure cases, 10,000-mutation loader fuzz.
* `cargo build --features test-pf` -> also proves the guard-page #PF path (status 33).
* Normal build + `python3 tools/ui-test.py <iso> <outdir>` -> 15 end-to-end desktop checks (monitor-injected keys/mouse, screendump pixel checks).
* User programs: `tools/build-user.sh` (utest, de), `tools/build-poc.sh` (Linux/PE; needs gcc + gcc-mingw-w64-x86-64); committed outputs live in `user/blobs/`.
  `hello_native.elf` is built from `user/poc/native` with `-T user/elf.ld` (see commands in section 9).

### Sandbox recipe used in the previous sessions (rustc 1.75 from apt; no rustup/nightly available)
```
apt-get install -y rustc cargo rust-src qemu-system-x86 xorriso lld nasm binutils gcc-mingw-w64-x86-64   # (remove broken nodesource apt source first)
# build-std needs a lockfile for the std workspace; compiler_builtins must be pinned to 0.1.109:
cd /usr/lib/rustlib/src/rust && cargo generate-lockfile && cargo update -p compiler_builtins --precise 0.1.104 && cargo update -p compiler_builtins --precise 0.1.109
git clone --depth 1 -b v8.x-binary https://github.com/limine-bootloader/limine.git /home/claude/limine-bin && (cd /home/claude/limine-bin && make)
```
`tools/dev-container/b.sh` builds a vendor-free copy with the old-rustc workarounds (`RUSTC_BOOTSTRAP=1`, `--ignore-rust-version`,
`-Zcrate-attr=feature(c_str_literals)`, `-Zbuild-std=core,alloc,compiler_builtins`, x86_64 crate pinned to 0.15.1 in Cargo.lock).
`tools/dev-container/run-test.sh <elf> <secs>` builds an ISO and boots it (paths are hard-coded to /home/claude; adjust).
Real nightly users may need small fixes (not verified outside the sandbox).

## 7. Known limitations / gotchas
* Single CPU; syscalls non-preemptible; no SMAP; SMEP only if CPUID reports it (QEMU default CPU does not).
* Futex has no timeouts. Audit ring is global (single producer assumption). Capability transfer over channels not implemented.
* Userspace cannot create shm/channels (needs a factory capability) - kernel provisions them.
* Only a read-only initramfs exists (no writable storage).
* Linux layer: static single-threaded programs only; no glibc validation yet (freestanding C tested). A glibc-static hello would additionally need
  more syscalls (prlimit64, readlinkat details, futex, ...); `getrandom` is NOT cryptographic. `uname` claims "Linux" for compatibility.
* Win32 layer: freestanding kernel32-only programs. mingw programs using msvcrt.dll (printf, malloc...) will fail with a named unresolved import.
  HeapFree/Critical sections are stubs; TLS is a flat per-process array (no TEB TLS slots); no SEH/exception unwinding.
* mmap/munmap are whole-region oriented (Linux munmap partial unmaps free pages but keep bookkeeping; safe because VAs never recycle).
* A process killed while one of its threads is blocked may keep its `Arc<Process>` alive (leak of the process object only).
* Limine's bootloader-reclaimable memory and its page-table pages are never reclaimed.
* Lesson learned: loader arithmetic must use checked ops - the fuzz test found an overflow in `elf.rs` (fixed). Keep the fuzz test running when touching `exec/`.
* Process hygiene note: a mid-session patch script was accidentally applied twice, producing duplicate definitions; if you script multi-file edits, make them idempotent.

## 8. Milestone 7 as built (verified in QEMU)
**Verified:** `cargo build --features selftest` (with and without `-device virtio-net-pci`) = status 33; `--features test-pf` = 33; `tools/ui-test.py` 15/15;
`tools/net-test.py <iso> <out>` (kernel built with `--features net-test`) 16/16: zero packets in the `filter-dump` capture while no grant exists, DHCP + TCP only with a grant,
all updater scenarios, silence again after the grant is dropped.
* **PCI:** MCFG parsed in `acpi.rs`; ECAM windows mapped per bus on demand; legacy 0xCF8/0xCFC fallback; selftest cross-checks both mechanisms for every function. `frame::allocate_contiguous(n, align)` for DMA.
* **VirtIO:** modern (1.x) transport only (QEMU's `virtio-net-pci` exposes it). `probe()` negotiates then RESETS the device (inert); `start()` builds rings + DRIVER_OK; `stop()` resets. Polled, no interrupts.
* **Net:** `net::run` thread (spawned only if a NIC exists) polls smoltcp. NIC is started only while a live `NetGrant` is registered (`net::issue_grant`) and reset when the last one expires/drops.
  `Firewall` sees EVERY frame both ways: default deny; allows only ARP + DHCP client on the link, granted outbound flows, and replies of those flows. No listening sockets, no IPv6.
  Allows (new flows) and denies (rate-limited 20/s) are audited as `EV_NET_ALLOW/DENY` (see `audit/mod.rs` for the field encoding). Grants: proto/prefix(>=/16)/port range/expiry(<=1 h)/byte budget(<=1 GiB); loopback/multicast refused. `CapObject::Net` carries a grant as a capability.
* **deloxy-upd:** `upd::check(grant, server, base)` -> verifies Ed25519 signature BEFORE parsing; distinct errors (SigFormat / UnknownKey / BadSignature / ManifestFormat / NotNewer / BelowMinVersion / ArtifactHash / Http / Net); `fetch_and_stage` verifies size+SHA-256 and stages in RAM.
  Key: the compiled-in key is a public TEST key (private half in `tools/mock-update-server.py`) - NOT a release key. `tools/lib/ed25519_ref.py` is a non-constant-time reference signer for tests only; `tools/gen-upd-testvec.py` regenerates `src/upd/testvec.rs`.
* **Fixed along the way:** the loader-fuzz leak check was racy (idle-thread reaping of earlier tests' stacks) and failed ~1 run in 5; it now waits 100 ms before taking its snapshot.
**NOT done in M7 (be honest in later docs):** user-space socket syscalls (sockets are kernel-only; `CapObject::Net` exists but no syscall consumes it yet); applying a staged update (no writable storage; staging is RAM-only);
`deloxy-sh upd check` UI (shell is M8); interrupts for virtio (polling); MSI-X; IPv6; DNS; TLS (updates are authenticated by signature, not confidential); real key ceremony; real-hardware NICs; SMP safety of the net lock.
Sandbox helpers added: `tools/dev-container/{mkiso.sh,st.sh}`; `st.sh <elf> <secs> [qemu args]` prints `QEMU_RC` (33 = pass).

## 9. Milestone 8 as built (verified in QEMU)
**Verified (release builds, `tools/test-all.sh`, ~2 min):** selftest BIOS without NIC / with virtio-net / UEFI (OVMF) = status 33; test-pf = 33; ui-test 18/18 (incl. typing into the terminal window);
net-test 16/16; shell-test 25/25 on BIOS and on UEFI (UEFI firmware's own PXE/IPv6 packets are excluded from the zero-packet checks); prompt after 0.9 s at 512 MiB.
* `src/fs/mod.rs` strict USTAR parser (flat names only), root = `Dir` capability. Limine module `boot():/boot/initramfs.tar` (`tools/mkinitramfs.py`: shell, monitor, 4 PoC programs, README).
* `src/tty.rs` kernel TTY: COM1 RX poller thread, input queue, output ring (feeds the terminal window and tests). Foreign (Linux/PE) console writes now go to the TTY.
* `src/sys/sysx.rs` syscalls 21-32 (see docs/ABI.md). `exec::SpawnOpts` gained `caps`; native ELFs get an info page (handles + argv). `task::PROCS` registry for `ps`.
* `src/init.rs` starts `deloxy-sh` with Tty, Dir, Spawn(console), Sys, Power, NetAdmin, AuditStream. `upd` in the shell asks for consent, mints a 60 s grant, runs the in-kernel updater, drops the grant.
* `user/sh`, `user/monitor`, `user/common/sys.rs` (native ELFs, `tools/build-native.sh`; sandbox wrapper `tools/dev-container/bn.sh`; prebuilt outputs committed in `user/blobs/`).
* deloxy-de: built-in **terminal window** (80x24 grid over the TTY; keys -> TTY). It has no client process (uses the kernel process) and ignores its close box.
* Release/test tooling: `tools/mkiso.sh` (vendored Limine in `third_party/limine/`), `tools/make-release.sh`, `tools/test-all.sh`, `tools/shell-test.py`; sandbox: `DELOXY_BUILD="bash tools/dev-container/b.sh" DELOXY_TARGET_DIR=/home/claude/target-shared`.
* Versions: kernel/crate 0.1.0, updater `CURRENT_VERSION` = [0,1,0]; mock-server scenario versions are relative to it.
**Not done:** see docs/KNOWN_ISSUES.md (no real hardware boot, updates are not applied, no user sockets, test signing key). **Ideas for what next (storage part is DONE, see 9b):**
user-space sockets via `Net` caps, capability transfer over channels, shm factory, SMAP/SMP, real key ceremony, real-hardware bring-up (AHCI/NVMe, USB HID, e1000/virtio), mouse/keyboard focus polish in deloxy-de, scrollback.

## 9b. Post-alpha step 1: persistent storage + persisted update staging (verified in QEMU)
**Verified (`tools/test-all.sh`, now 11 phases):** selftest incl. `test_store_logic` (RAM disk: format/mount, atomic replace, ENOSPC, 128-file limit, **12 torn-write power-cut points**, CRC corruption detection, fallback to the previous directory generation,
blank disk is never auto-formatted) and `test_store_device` (real virtio-blk: 300 KB round trip, out-of-range rejection, updater persistence/recovery/tamper detection); `tools/store-test.py` = 3 QEMU boots sharing one raw disk image (BIOS and UEFI):
blank disk behaviour + explicit confirmed format, save/cp/rm/df, programs run from the store, reserved `upd.*` names, persisted update staging, **persisted rollback floor rejects the staged version after a reboot**, bit flip on the raw disk is detected.
* **`drivers/blk/virtio_blk.rs`**: modern transport only (like virtio-net). 3-descriptor chains via the new `VirtQueue::post_chain`; bounce buffer (4 KiB = 8 sectors/request); completion polled with an iteration bound (the tick counter is frozen inside syscalls: IF=0). A timeout resets the device and the driver refuses further I/O.
* **`store/mod.rs` (DeloxyStore v1)**: superblock + two directory slots (A/B, 16 KiB each, generation + CRC-32) + contiguous data extents. Write = data to free extents -> flush -> new directory image to the *other* slot -> flush. Mount picks the valid slot with the highest generation.
  Flat names (`[A-Za-z0-9._+-]`, <= 47), <= 128 files, <= 4 MiB per file, whole-file atomic replace, CRC-32 per file verified on read. No directories, no partial writes, no permissions beyond capabilities, no wear levelling.
  `State`: NoDevice / Unformatted / Ready / Failed. `init()` mounts but **never formats**; formatting needs the `Store` capability with `GRANT` and, in the shell, typing `yes`.
* **Capabilities/syscalls:** `CapObject::Store` (kind 16; READ list/open/stats, WRITE write/delete, GRANT format) and `StoreFile` (kind 17; READ|EXEC). Syscalls 33 store_list, 34 store_open, 35 store_write, 36 store_ctl (see ABI.md). `file_read` and `proc_spawn` accept `StoreFile`, so programs can be run from the store.
  Names starting `upd.` are kernel-owned: user programs can read them, never create/replace/delete them (EPERM).
* **Shell:** `df`, `save <name> <text>`, `cp <src> <dst>` (<= 1 MiB), `rm`, `format`; `ls`, `cat`, `run` search the initramfs first, then the store.
* **Updater persistence (`upd/mod.rs`):** after a verified `upd stage`, artifacts are written as `upd.<ver>.<artifact>`, then `upd.pending` (record: version + name/size/SHA-256 per file, the commit marker), then `upd.floor` (persistent anti-rollback floor).
  `upd::recover()` (boot) loads the floor into `HIGHEST_STAGED` and re-hashes the pending update; a damaged set is reported and ignored.
* **Sandbox:** attach a disk with `-drive file=disk.img,if=none,id=d0,format=raw -device virtio-blk-pci,drive=d0`. For UEFI in this sandbox `apt-get install ovmf` provides `/usr/share/ovmf/OVMF.fd`, which `tools/test-all.sh` finds by itself (no symlink needed). When running long suites from a tool call use `setsid nohup ... &`; plain `nohup` children died with the call.
**NOT done / honest limits:** an update is *persisted and re-verified but never activated*: Limine loads the kernel from the (read-only) boot medium and Deloxy cannot rewrite it; real A/B activation needs a writable boot partition (FAT32/ext2 that Limine can read) plus a boot-attempt counter/rollback in the bootloader config.
Not verified: real NVMe/AHCI/USB disks (only virtio-blk), power-loss on real media (flush semantics were only exercised against QEMU and a RAM-disk fault injector), disks > 2^32 sectors, concurrent writers (single global lock, IF=0 during I/O so timer ticks are lost during long writes; <= 4 MiB files keep this to well under a second in QEMU),
files larger than 4 MiB, no fsck/repair tool (a store whose both directories are damaged refuses to mount and is left untouched). `StoreFile` EXEC means anyone with `WRITE` on the store plus a `Spawn` cap can run code from disk; there is no signature check on stored programs.

## 9c. Post-alpha step 2: deloxy-de v2 (desktop) - verified in QEMU
`src/wm/server.rs` was rewritten (1300 lines), new `src/wm/theme.rs`, new drawing primitives in `src/gfx/draw.rs` (alpha blend, gradients, anti-aliased rounded rects, soft shadows).
* **Look:** wallpaper cached per theme (4 built-in: midnight, aurora, dusk, graphite), desktop icons (Terminal, Monitor, Settings), windows with rounded gradient title bars + minimize/close buttons + drop shadows, a taskbar with a **start button + menu** (Terminal, Activity Monitor, Animation Demo, Colour Bars, Settings, Restart, Shut down), window buttons with an accent underline for the active one, tray icons (network = a NIC exists, disk = store mounted) and a **real clock** (CMOS RTC via `time::wall_clock`, UTC, no timezone) with date. Hover highlights everywhere.
* **Behaviour:** minimize (box or taskbar click toggles), restore, raise, drag clamped to the work area, launching an already-running app focuses/restores it. The terminal's close box now *hides* it (the shell keeps running; restore from the taskbar or menu). The Settings window is compositor-drawn (no client process).
* **Customization (`wm/theme.rs`):** dark/light, 8 accent colours or any `#rrggbb`, 4 wallpapers, taskbar top/bottom, square/rounded corners, 12/24 h clock. Persisted to **`de.conf`** in the store (plain text; unknown keys ignored) and **hot-reloaded**: `save de.conf theme=light accent=orange taskbar=top wallpaper=dusk corners=square clock=12` in the shell changes the live desktop within a second; the theme is restored at boot. Without a store disk, changes work but are not saved (Settings says so).
* **Tests:** `tools/ui-test.py` (40 checks: start menu, Settings clicks for accent/wallpaper/light/top/corners/reset, close, minimize/restore, icon launch, drag, shadows, clock) and `tools/store-test.py` (shell-driven `de.conf` hot reload + restore after reboot).
* **Not done:** window resize/maximize, keyboard shortcuts (Alt-Tab...), multiple terminals (one kernel TTY), fonts other than 8x16, window animations, notifications, a file-manager GUI, per-theme wallpapers/icons set, HiDPI, multi-monitor, a real clock zone/NTP, screen lock, a Settings app for network/disk/users. Drawing is integer software rendering; a full repaint of 1280x800 is fast enough in QEMU but was not measured on real hardware.

## 9d. Post-alpha step 3: deloxy-wltd v2 (Linux + Windows compatibility) - verified in QEMU
* **Capability-gated files for foreign programs (`abi/vfs.rs`)**: `CapObject::Spawn { console, files }`; a spawn with `files` installs `Dir`(READ) + `Store`(READ|WRITE) in the child's cap table **for foreign ABIs only** (new `SpawnOpts.foreign_caps`; native programs never see them). Paths are flat (`README.txt`, `./x`, `/x`, `/store/x`); reads look in the initramfs first, writes go to the store, buffered in memory (<= 4 MiB) and committed atomically on close/exit. `upd.*` is never writable. The shell's `run` passes `files`.
* **Linux:** open/openat/close/read/pread64/write/lseek/fstat/stat/newfstatat/access/getcwd/fcntl/ioctl(TCGETS, TIOCGWINSZ)/prlimit64/getrlimit/sysinfo/futex(stub)/sched_getaffinity/clock_nanosleep/set_robust_list... A **statically linked glibc program** (printf, qsort, malloc, fopen/fread/fseek/ftell, fopen for write -> persisted file, clock_gettime) runs unmodified (`user/poc/linux_glibc.c`, built with `gcc -static`). Still single-threaded: no clone/fork/exec, no pipes/sockets, no directories (getdents), no signals, no dynamic linking.
* **Windows (`abi/msvcrt.rs`, `abi/nt.rs`, `exec/pe.rs`):** a hand-written msvcrt subset (~90 functions: printf family incl. `%d %u %x %c %s %p %f` with flags/width/precision, `fopen/fread/fwrite/fgets/fseek/...`, malloc/calloc/realloc (bump allocator, `free` is a no-op), mem*/str*, `exit/abort`, `__getmainargs` with real argv, `time/clock/rand`), data imports (`_fmode`, `_commode`, `__initenv`), **user-mode code stubs** for `_initterm`/`_initterm_e` (they must call user function pointers) and `__C_specific_handler`, PE **static TLS** (template copied into a per-process block reached via `TEB+0x58`; TLS callbacks are ignored), extra kernel32 (`MultiByteToWideChar`, `WideCharToMultiByte`, `VirtualProtect/Query` stubs). Imports now resolve through `nt::resolve` (thunk, code stub or data address). Variadic/5+ argument calls read stack arguments through `ForeignState.nt_rsp`. A **mingw-w64 C program** (`user/poc/win_msvcrt.c`) runs unmodified.
  Limits: `%e`/`%g` print like `%f`; no `qsort`/`bsearch`/`atexit` (they call user code); no scanf, wide-char stdio, locale, signals, C++ runtime/exceptions (SEH is a stub), threads, DLL loading, GUI APIs (user32/gdi32); only `kernel32` and `msvcrt` imports resolve (anything else is a load error naming the function).
* **Tests:** `tools/compat-test.py` (BIOS + UEFI): the glibc ELF and the mingw PE run on the real kernel with a disk; the file the Linux program writes is visible to the shell afterwards.

## 9e. Post-alpha step 4: deloxy-de v3 - verified in QEMU (`tools/ui-test.py`: 63 checks)
* **More customization (`wm/theme.rs`, Settings window now 440x500):** panel style **Bar | Dock** (floating rounded dock), panel look **Solid | Glass** (translucent, blends with the wallpaper), titles **Gradient | Flat**, shadows **Off | Soft | Strong**, plus everything from v2. New `de.conf` keys: `panel=bar|dock`, `glass=on|off`, `titles=gradient|flat`, `shadows=off|soft|strong`, `wallpaper=file:NAME`.
* **Custom wallpapers:** `wallpaper=file:NAME` loads a binary **P6 PPM** (maxval 255) from the initramfs or the store, scaled "cover" (centre-cropped, nearest neighbour). `sample-wall.ppm` (128x80) ships in the initramfs. A bad file falls back to the built-in wallpaper and says so in Settings. No PNG/JPEG decoder yet.
* **Files app (Kind::Files, desktop icon + start menu):** lists initramfs ("system", read-only) and store files with sizes; click to select, double-click / Open / Enter to open, Delete (store only; `upd.*` and `de.conf` are protected), Refresh, Up/Down keys, auto-refresh when the store changes. Open by type: `.elf`/`.exe` run the program with console + file capabilities (output appears in the terminal, which is restored), `.ppm` becomes the wallpaper, anything else opens in the **text viewer** (UTF-8 text wrapped at 62 columns, binary as a hex dump; j/k, space/b, arrows, PgUp/PgDn).
* **Calendar popup:** click the clock (month grid, today highlighted, Esc/click-away closes). Uses the CMOS RTC (UTC).
* **Keyboard:** the PS/2 driver now reports modifier bits in `InputEvent.y` for key events (1 shift, 2 ctrl, 4 alt, 8 super) and tracks Alt/Super. Shortcuts: **Alt+Tab** (cycle/restore), **Alt+F4** (close focused window; the terminal hides), **Super** (toggle start menu), **Ctrl+Alt+T** (terminal), **Esc** (close menu/calendar).
* **Fixes:** closing a window now repaints its shadow margin; the wallpaper blit used the wrong destination for partial repaints (fixed in v2); dock/glass outline.
* **Not done:** window resize/maximize/snap, multiple terminals, alt-tab switcher overlay, notifications, drag & drop, right-click menus, per-window icons, PNG/JPEG, fonts other than 8x16, screen lock, multi-monitor.

## 9f. Post-alpha step 5: deloxy-wltd v3 - verified in QEMU (`tools/compat-test.py`: 9 checks, BIOS + UEFI)
* **Interactive stdin for foreign programs (`abi::stdin_read`)**: cooked line input (echo, backspace, Ctrl-D = EOF) from the kernel TTY, gated by the console capability. Linux `read(0)`, msvcrt `fgets/fgetc/getchar/fread/scanf` on stdin, kernel32 `ReadFile/ReadConsoleA` on the stdin handle.
* **Linux:** directories (`open("/")`, `getdents64`; so `opendir/readdir` work; `.` `..` + initramfs + store names), file-backed private `mmap` (bytes copied; writes never reach the file), `unlink/unlinkat`, `ftruncate`, `fsync` (no-op), `mkdir/rename/chdir` -> EACCES. Real glibc programs: `user/poc/linux_stdin.c`.
* **Windows:** kernel32 `CreateFileA/ReadFile/WriteFile/CloseHandle/GetFileSize/SetFilePointer/FlushFileBuffers/DeleteFileA/GetFileAttributesA/GetFileType/FindFirstFileA/FindNextFileA/FindClose/GetModuleFileNameA/GetCurrentDirectoryA/GetEnvironmentVariableA/GetConsoleMode/GetLocalTime`... (`abi/win32.rs`; handles `0x100 + 4*slot`); msvcrt `scanf/sscanf` (ints/hex/chars/strings; no floats), `strtol/strtoul/strtoll/atol`, ctype (`isalpha`...), `strdup/strcspn/strspn/_stricmp/memchr/ungetc/perror/setlocale`, **`qsort`** and **`exit` as user-mode machine-code stubs** (so comparator and `atexit` callbacks really run in ring 3; atexit table of 32 in the msvcrt globals page; stubs are patched with addresses in `msvcrt::build_stub`). Real MinGW programs: `user/poc/win_k32.c`.
* **Still missing:** threads/`clone`/`fork`/`exec`/pipes/sockets/signals (Linux); wide-char (`W`) kernel32 APIs, `scanf("%f")`/`strtod`/float parsing, `bsearch`, C++ runtime, DLL loading, user32/gdi32/ws2_32 (Windows). `malloc` still never reuses freed memory.

## 9g. Post-alpha step 6: deloxy-wltd v4 - threads, pipes, synchronization (verified in QEMU, `tools/compat-test.py`: 12 checks, BIOS + UEFI)
* **Linux threads (`abi/linux.rs`):** `clone(CLONE_VM|CLONE_THREAD|...)` creates a real kernel thread in the same process (`task::spawn_user_thread_full`, up to 32 threads; child resumes after the syscall with rax=0 on the given stack, `CLONE_SETTLS` -> FS base, `PARENT_SETTID/CHILD_SETTID/CHILD_CLEARTID`). `exit` ends only the calling thread (zeroes + futex-wakes its CLEARTID word, so `pthread_join` works; the last thread ends the process), `exit_group` ends the process. `set_tid_address`, `gettid`, `tkill/tgkill` (no-op: signals are not delivered). **Real futexes** (`FUTEX_WAIT/WAKE/_BITSET` with optional timeout; key = physical address, on the kernel's existing `futex_block/futex_wake`) so glibc mutexes, condvars and `pthread_join` run unmodified. `fork/vfork/execve/clone3` -> ENOSYS (glibc falls back to `clone`).
* **Pipes, dup, poll:** `pipe/pipe2` (in-memory, <= 1 MiB, blocking reads by polling; EOF when all write ends are closed), `dup/dup2/dup3` for files and pipes (not onto fds 0-2: no stdio redirection yet), `poll/ppoll` (stdin, files, pipes, with timeouts).
* **Windows threads/sync (`abi/win32_thr.rs`):** `CreateThread`, `_beginthread(ex)`, `ExitThread/_endthreadex` (new thread gets its own 1 MiB stack, TEB, static-TLS block and a user-mode trampoline stub `<thread_start>` that calls the routine and then `ExitThread`), `WaitForSingleObject(Ex)`, `WaitForMultipleObjects` (any/all), `CreateEventA/SetEvent/ResetEvent`, `CreateMutexA/ReleaseMutex`, `CreateSemaphoreA/ReleaseSemaphore`, `GetExitCodeThread`, **real critical sections**, `Interlocked*` (32/64-bit), `SwitchToThread`; **per-thread `TlsAlloc` values** (and per-thread static TLS blocks; MinGW's `__thread` uses emulated TLS on top of TlsAlloc and works). Handles: kernel objects `0x2000 + 4*index`, files `0x100 + 4*slot`. The NT thunk area is now **two pages** (`NT_DATA_BASE = NT_THUNK_BASE + 2 pages`, user code stubs start at page 2).
* **Atomicity model:** syscalls run with interrupts disabled on one CPU, so futex/critical-section/Interlocked operations done in the kernel are atomic; waiting is by 1 ms polling for Windows objects (`sleep_ms(1)`) and by `futex_block` for Linux futexes. SMP would need real locking here.
* **Real programs:** `user/poc/linux_threads.c` (4 pthreads + mutex, join values, `__thread` TLS, condvar, pipe + poll) and `user/poc/win_threads.c` (CreateThread/_beginthreadex, critical section, Interlocked, events, semaphores, mutex, WaitForMultipleObjects, TLS) run unmodified. Note: GCC for MinGW ignores `__declspec(thread)` (it becomes a plain global); use `__thread`.
* **Still missing:** `fork/exec`, signals, sockets, `epoll/select`, Linux `clone` flags beyond threads, thread priorities/affinity, `WaitOnAddress`, condition variables (`SleepConditionVariable*`), SRW locks, fibers, Windows wide APIs, `bsearch`, dynamic linking (DLLs, ld.so).
* **Tools added:** `tools/runone.py` (boot an ISO, run shell commands, print the output), `tools/run-qemu.sh` / `run-qemu.bat` (run the shipped ISO).

## 9h. Running the ISO
`dist/deloxy.iso` (BIOS + UEFI bootable, built by `tools/mkiso.sh` from the release kernel + initramfs). With QEMU: `qemu-system-x86_64 -M q35 -m 512M -cdrom deloxy.iso -serial stdio -netdev user,id=n0 -device virtio-net-pci,netdev=n0` (or `tools/run-qemu.sh deloxy.iso [--uefi] [--disk disk.img]`; Windows: `run-qemu.bat`). For a persistent store add a disk (`--disk disk.img`, then run `format` once in the terminal). Real hardware and VirtualBox/VMware are untested; only virtio devices have drivers (no NVMe/AHCI/USB/e1000 yet), so use QEMU/KVM or a VM that offers virtio.

## 9i. Post-alpha step 7: permissions, resource limits, Task Manager, notifications (verified in QEMU)
* **Application permissions (`src/perm/mod.rs`, kernel-enforced).** Linux/Windows programs start with NO file access. When one first touches a file (`abi::vfs::can()` -> `perm::resolve`: open, opendir, unlink, msvcrt `remove`), the kernel looks up a decision for (program name, first 8 bytes of the SHA-256 of its image); if none, it **asks the user on the program's console**: `[o]nce [a]lways [n]o [d]eny always`. once = rw for this run; always = rw stored; no = this run without files; deny always = stored denial. Programs with no console capability are denied silently. A modified binary has a different hash and is asked again. Programs that never touch files (hello-world) never prompt. Decisions persist in `perms.db` (store; `NAME HASH16 R W`), loaded at boot (`perm::init`). `store::is_reserved()` = names starting `upd.` or `perms.` that no user program, the shell or the Files app may write/delete.
* **`perms` shell command** + **`CapObject::Policy`** (kind 18; the shell holds READ|WRITE) + **syscall 37** `perm(h, op, a2, a3, a4)`: op 0 list (index, 64-byte record), 1 set (program file name in initramfs/store, flags bit0 R / bit1 W / bit8 once; the kernel hashes that file), 2 revoke. `perms`, `perms allow NAME rw|r|none`, `perms revoke NAME`. Read-only grants work (`fs_store_write` is cleared).
* **Resource limits:** `Process.mem_limit_pages` (0 = unlimited): Linux/NT programs are capped at **128 MiB** (`task::FOREIGN_MEM_LIMIT_PAGES`) enforced in `Process::map_region` (mmap, brk, thread stacks, TEB/TLS), so a runaway allocator gets ENOMEM instead of exhausting the machine; threads <= 32 and open files <= 64 per process (earlier). `ps` and the process-list syscall (28) now report memory (record offset 56, KiB; name limited to 39 chars).
* **`task::sched::kill_process(&Arc<Process>, code)`**: terminates another process (all threads in ready/sleeping/futex states; single CPU assumed).
* **deloxy-de v4:** **Task Manager** (desktop icon, start menu; live process list with PID, threads, memory, type; End process / Delete key; the shell is protected), **toast notifications** (`Server::notify`, top-right, 4 s: program started, file deleted, process ended, wallpaper changed), **right-click desktop context menu** (Open Terminal/Files, Task Manager, Settings, Next wallpaper). `Hover::Ctx`, `Kind::Tasks`. Tests: `tools/ui-test.py` now 72 checks.
* **wltd v5:** Windows **SRW locks** (`Acquire/Release/TryAcquireSRWLockExclusive/Shared`) and **condition variables** (`SleepConditionVariableCS/SRW`, `Wake(All)ConditionVariable`) in `win32_thr.rs`; `user/poc/win_sync.c` (producer/consumer, shared readers, timeout). `tools/compat-test.py` now 31 checks (permissions flow with prompt/once/always/deny/revoke/hash binding, memory limit, SRW/condvar).
* **Not done:** per-user accounts/login, a permission model for network/devices/camera (there are no sockets yet), a DE dialog for consent (prompts appear in the terminal; launching from the Files app brings the terminal forward), per-program file scoping (a grant is all-or-nothing: system files + store), CPU-time limits/quotas, signals for graceful termination, resource limits for native programs, SMP-safe kill.

## 9j. Post-alpha step 8: sockets + network permissions + Permissions manager (verified in QEMU)
* **Sockets for foreign programs (`abi/sock.rs`, `abi/winsock.rs`, `abi/linux.rs`):** TCP client sockets over the kernel's smoltcp stack. Linux: `socket(AF_INET, SOCK_STREAM)`, `connect`, `read/write/send/recv/sendto/recvfrom`, `poll`, `fcntl/ioctl` non-blocking, `getpeername`, `getsockopt/setsockopt` (no-ops), `shutdown` (no-op); `bind/listen/accept` -> EOPNOTSUPP. Windows (`ws2_32`/`wsock32`): `WSAStartup/Cleanup`, `WSAGet/SetLastError`, `socket`, `connect`, `send`, `recv`, `closesocket`, `ioctlsocket(FIONBIO)`, `htons/htonl/ntohs/ntohl`, `inet_addr`; `gethostbyname` fails (no DNS). A socket is an `OpenFile` (`vfs::Data::Sock`, SOCKET = `0x100 + 4*slot`); dropping it closes the TCP connection.
* **Network permission:** creating a socket is free; **`connect` asks the user, per destination**: `[permission] NAME wants to connect to a.b.c.d:port (TCP). Allow? [o]nce [a]lways [n]o [d]eny always`. Rules are keyed by (program name, image hash, ip:port) and stored in `perms.db` (`NAME HASH R 0 IP:PORT`). After consent the kernel mints a **narrow `NetGrant`** (that host/port only, 10 minutes, 64 MiB) which also brings the NIC up (it stays inert otherwise); the grant lives as long as the socket. Denied/unconsented connects fail with EACCES (13) / WSAEACCES (10013); unreachable (loopback/multicast are never grantable) ENETUNREACH; refused/timeouts map to ECONNREFUSED/ETIMEDOUT. Programs without a console are denied. `ForeignState.prog_name/prog_hash` are now set for every foreign program.
* **Shell:** `perms net <program> <a.b.c.d:port> allow|deny`; `perms` lists network rules (`net IP:PORT ALLOWED|DENIED`). Syscall 37 op 3 sets a network rule; op 0 record is now **80 bytes** (rec[58] = 1 for network rules, ip at 60..64, port u16 at 64..66, rec[56] bit0 = allowed). `perm::set_net/resolve_net/remove_entry/parse_dest`.
* **deloxy-de v5: Permissions manager** (`Kind::Perms`, start menu): lists every stored rule (program, files/network destination, ALLOWED/DENIED), Revoke / Allow / Deny / Refresh, Delete key, live refresh. Menu now has 11 entries (Permissions after Settings). Tests: `tools/ui-test.py` 78 checks (rules created by typing shell commands via QEMU `sendkey`, then managed in the GUI).
* **Tests:** `tools/compat-test.py` (41 checks) now starts the mock HTTP server and gives the VM a NIC: Winsock program with a stored allow rule, Linux socket program through the prompt (no / always / stored / revoke / deny always), real `GET` answered by the host.
* **Not done:** DNS/UDP, listening sockets (servers), TLS, `select/epoll` (poll works), IPv6, non-blocking `connect`, `SO_RCVTIMEO`, per-connection bandwidth shaping beyond the 64 MiB grant, a DE dialog for consent (prompts still use the terminal), wildcard network rules (every destination is asked individually).

## 9k. Post-alpha step 9: full network access + custom limits (verified in QEMU)
* **Network rules (`perm::NetRule`):** `dest` = one `ip:port` **or any host**, plus an optional **time limit** (`secs`, 0 = unlimited), **data cap** (`kib`, 0 = unlimited) and an **internet-only** flag (excludes private/LAN ranges). Default for "always (this host)" is still 10 min / 64 MiB; **"full access" = any host, no time limit, no data cap** ("a regular connection", e.g. for a ported chat app).
* **Where you set it:** (1) the connect prompt now offers `[o]nce [a]lways (this host) [f]ull access (any host, no limits) [n]o [d]eny always`; (2) the shell: `perms net <program> <ip:port|any> allow|deny [time=30s|10m|2h|unlimited] [data=500K|64M|2G|unlimited] [nolan]`; (3) the **Permissions manager** (buttons *Full* = any host/no limits, *Limits* = cycle presets unlimited / 1 h + 1 GiB / 10 min + 64 MiB / 5 min + 10 MiB, plus Allow/Deny/Revoke). `perms` lists rules, e.g. `app 1a2b.. net ANY HOST (internet only) limit: 1800 s, 2097152 KiB ALLOWED` or `... net ANY HOST no limits ALLOWED`.
* **Rule resolution:** an exact-destination rule beats the any-host rule (so a deny for one host overrides full access, and an allow punches through an internet-only rule); with no rule the user is asked. **Limits are per program run, not per connection:** `ForeignState.net_grants` keeps one live grant per rule scope, reused by every socket of that run, so opening more connections cannot dodge the time/data budget.
* **Kernel (`net/grant.rs`, `net/mod.rs`):** `NetGrant::any(proto, public_only, duration_ms, bytes_max, now)` (0 = unlimited) and `net::issue_any_grant`; `covers()` for any-host grants still refuses this-net/loopback/multicast/broadcast and, when internet-only, RFC1918 + link-local + CGNAT (`grant::forbidden/private`). Normal `NetGrant::new` keeps its 1 h / 1 GiB ceilings (used by the updater and one-host rules). Full access also lets a program reach the local network unless `nolan`/internet-only is set: the prompt wording says "any host".
* **Persistence:** `perms.db` network lines: `NAME HASH R 0 DEST [T<secs>] [K<KiB>] [P]` (old lines without limits load with the old defaults). Syscall 37 op 3 now takes a pointer to `{ip[4], port u16, allow u8, flags u8 (bit0 any, bit1 internet-only), secs u32, kib u32}`; the op 0 record carries flags@66, secs@68, kib@72 (80 bytes).
* **Tests:** kernel selftest `test_net_grants_any` (unlimited/expiry/data cap/revoke/forbidden + LAN ranges); `compat-test` 57 checks (full access, any destination reachable, internet-only blocks LAN, exact rule overrides, `f` at the prompt); `store-test` (limits survive a reboot); `ui-test` 81 checks (Full and Limits buttons).
* **Still missing for a real chat-app port:** DNS (hostnames), UDP (voice), TLS, listening sockets, `select/epoll`, non-blocking connect. The permission side is ready for them (UDP/DNS would need their own grants and a rule scope).

## 10. Misc commands
Rebuild hello_native.elf (sandbox flags):
`RUSTFLAGS="-Clink-arg=-T<abs>/user/elf.ld -Crelocation-model=static -Ccode-model=small -Clink-arg=-no-pie -Clink-arg=-zmax-page-size=4096 -Clinker=ld.lld -Clinker-flavor=ld.lld" cargo build --release --target x86_64-unknown-none` in `user/poc/native`
(plus the `-Zbuild-std` flags from section 6 when using the apt compiler), then copy `target/.../hello-native` to `user/blobs/hello_native.elf`.
Debug a kernel panic: the panic handler prints return addresses; resolve with `addr2line -f -e <kernel-elf> <addr>`.
Verified screenshots of the desktop and boot console: `docs/screenshots/`.

## 11. Prompt to paste into the new chat
See `docs/NEXT_CHAT_PROMPT.md`.
