# Research note (Nov 2026): GPUs, games, DeloxyStore, and "a really good, optimized, usable OS"

Written after step 29. **Effort scale** (one unit = one working session of the kind recorded in HANDOFF section 9): **S** = 1, **M** = 2-4, **L** = 5-10, **XL** = more than a person-year or not realistic without hardware access and a team.
**What can be verified here:** this sandbox has QEMU (TCG, no KVM) only. Anything that needs real silicon (GPU, Wi-Fi, NVMe on a real SSD, laptop power management, audio codecs) can be *written* here but not *tested*; I mark those "blind". Facts about third-party projects below come from the sources listed at the end; where I rely on general knowledge instead, I say so.

## 1. GPU drivers

**Today:** a firmware-provided linear framebuffer (Limine/GOP), software compositing in the kernel-side window manager (deloxy-de). No GPU command submission, no mode setting, no vsync. Linux programs cannot reach the framebuffer at all (only `/dev/null`, `/dev/zero`, `/dev/urandom` exist).

| Tier | What | Verdict | Effort | Verifiable here |
|---|---|---|---|---|
| 0 | Keep the firmware framebuffer; make software rendering fast (SSE2/AVX2 blits, dirty-rectangle compositing, no full-screen redraws, double buffering) | **Do this first.** Biggest visible win per line of code | S-M | yes (timings under TCG are only relative) |
| 1 | **virtio-gpu 2D** (resource create / attach backing / transfer-to-host / flush, cursor queue, runtime resolution change via EDID/display info) | **Feasible.** The device is small and documented (QEMU docs; the Rust `virtio-drivers` crate has a reference GPU driver of a few hundred lines) | S-M | **yes** (QEMU `-device virtio-gpu-pci`) |
| 2 | virtio-gpu **3D** (virgl/Venus) | Needs a guest Mesa driver stack and a host with a GPU; Mesa on a non-Linux kernel needs a DRM-like kernel interface (GEM/PRIME, syncobj, ioctls) that Deloxy does not have | XL | no (needs host GPU passthrough support) |
| 3 | **Intel display-only** (mode setting, planes, hot-plug) for one or two generations | Intel publishes the programmer's reference manuals (PRM volumes, e.g. on x.org/01.org and in the "Graphics for Linux" developer reference). Display engines differ per generation; also needs VBT parsing and GuC/HuC firmware only for render, not for scan-out. Doable *per generation*, risky without the hardware | L per generation | **no, blind** |
| 4 | Intel/AMD **3D rendering** (command streamers, shader compiler) | The shader compiler is the wall: it lives in Mesa (NIR + vendor backends, hundreds of thousands of lines). A from-scratch compiler for even one ISA is a project of its own | XL | no |
| 5 | **AMD** | ISA documents (RDNA 1/2/3/3.5) are public on GPUOpen, but the hardware bring-up (firmware for PSP/SMU/SDMA, AtomBIOS, display core, memory manager) is documented mostly by the Linux amdgpu source, which is huge | XL | no |
| 6 | **NVIDIA** | No public programming documentation. Since Turing the GPU is driven through the signed GSP firmware; NVIDIA's open kernel modules and the Linux `nova` driver exist, but as of the sources below nova is still early and the firmware is a signed binary blob. | not realistic | no |

**Conclusion:** hardware-accelerated 3D drivers are *not* a realistic goal for Deloxy now, and I would not promise them. What is realistic and valuable: (0) fast software compositing, (1) virtio-gpu 2D for VMs (also gives resizable windows and no tearing there), (3) optionally Intel display-only mode setting when someone can test on hardware, and later a **software 3D path** (e.g. a small software rasteriser for games; a port of Mesa's software rasteriser is XL because of LLVM/dependencies, a purpose-built 2.5D/Quake-class rasteriser is M).

## 2. Games and "simple game ports"

**Missing platform pieces (verified in the code):** no framebuffer or window API for Linux programs, no input devices for them (only the console byte stream), no audio driver at all, no `/dev/input`. So *no* graphical game can run today, regardless of how portable its source is.

| Step | What | Effort | Verifiable here |
|---|---|---|---|
| G1 | `/dev/fb0` for Linux programs: `FBIOGET_VSCREENINFO/FSCREENINFO`, `mmap` of a surface (a window of deloxy-de, or the whole screen in a "full-screen" mode) | M | yes |
| G2 | Input for Linux programs: key and mouse events (`/dev/input/event*` or a raw tty mode + mouse reports) | S-M | yes (QEMU keyboard/mouse) |
| G3 | **DOOM** via *doomgeneric* (GPL-2; it only needs a few platform callbacks: init, draw frame, sleep, tick count, key polling, plus a WAD file; the shareware `doom1.wad` is freely redistributable). It already has a Linux framebuffer platform, so G1+G2 are nearly all it needs | S after G1/G2 | yes |
| G4 | Audio: Intel HDA output (QEMU `intel-hda` + `hda-duplex`) or `virtio-snd`; mixer; `/dev/dsp`-style or ALSA-lite interface | M-L | in QEMU yes; real codecs blind |
| G5 | Terminal games (nethack-class, curses): needs `termios` modes (raw, no-echo, window size), `ncurses`-compatible terminfo. Some of this exists (TIOCGWINSZ, TCGETS stub); a real line discipline is S-M | S-M | yes |
| G6 | **SDL2** backend (software renderer, input, timers, later audio): unlocks hundreds of open-source 2D games (the "simple ports" in bulk) | L | yes |
| G7 | Native in-house deloxy-de games (Snake, Tetris, Minesweeper, Solitaire): no new platform work, good demos of the app model | S each | yes |
| G8 | 3D games (Quake-class software renderers, OpenGL titles) | Quake software: M after G1-G4; OpenGL: needs a software GL (XL) | partly |

Licensing note: DOOM/Quake engine sources are GPL; game data must be the shareware data or user-supplied.

## 3. "DeloxyStore"

In this repository "the store" is the **persistent filesystem** (docs/HANDOFF.md 9b, 9q). There is no application store yet. Both meanings need work for a usable OS, so both are covered.

### 3a. The filesystem (what it still lacks to be a daily-driver FS)
Present: crash-safe copy-on-write-style commits, hierarchical tree, directories, symlinks, rename, atomic replace, resource quotas per app permission, virtio-blk/AHCI.
Missing, in a sensible order:
1. **Journal/transactions across multiple files** and `fsync`/`sync` semantics (S-M); **`fsck`/scrub** that verifies checksums of all extents and reports (S-M).
2. **Hard links, `statfs`, permissions/ownership model** (Deloxy has no users; per-app grants cover this, but programs expect mode bits) (S-M).
3. **Performance:** read-ahead, a page cache with write-back, large-file extents growing in place, directory indexing (M-L). Today most file I/O copies whole files (`Data::Buf`).
4. **Drivers for real storage:** NVMe (M, testable in QEMU `-device nvme`), USB mass storage (M, QEMU `usb-storage`), SATA already (AHCI).
5. **Encryption at rest** (XChaCha20-Poly1305 or AES-GCM per block/extent, key from passphrase via a memory-hard KDF; unlocking at boot) (M-L). Matches the project's security goal; needs a key-management design first.
6. **Snapshots** (cheap with copy-on-write, M) and **TRIM/discard**, quotas per directory (S-M).
7. **Interop:** read-only FAT32/exFAT/ext4 so USB sticks and dual-boot disks are usable (M each).

### 3b. An application store / package manager
Deloxy already has the right ingredients: an **Ed25519 update system with a rollback floor** (kernel updater), a **per-application permission model** (files, network destinations, resource limits, audit log) and atomic rename in the filesystem. A design that uses them:
1. **Package format:** a tar-like archive with a signed manifest (id, version, files + hashes, requested permissions, entry point, ABI = native / Linux / Windows). (S)
2. **Repository metadata in the style of TUF** (root, targets, snapshot, timestamp roles; expiry; rollback and freeze protection) served as static files over HTTPS. The kernel updater already implements signature and rollback checks for the OS image; the package side reuses them. (M)
3. **Installer:** unpack to `/apps/<id>/<version>`, verify every hash, create the permission entry *from the manifest after the user approves it*, switch the `current` link atomically with rename, keep the previous version for rollback. (M)
4. **CLI first (`dpkg`-like), then a GUI "Store" app** in deloxy-de with search, install, update, permission review. (M + M)
5. **Content:** a store is only as good as what is in it. Realistic first catalogue: the bundled utilities (busybox applets), terminal tools, games from section 2, and compiled open-source apps. Building packages reproducibly needs a documented cross-build recipe per app. (ongoing)
6. **Needs:** an HTTPS client library in user space (OpenSSL runs as a static Linux program today; a native client or a small Rust TLS stack would be better) and DNS/DHCP robustness testing on real networks.
Verdict: **CLI package manager + signed repository: feasible, M-L, fully testable in QEMU.** A polished store with a large catalogue is a long-running effort, not a feature.

## 4. What else stands between Deloxy and "good, optimized, usable"

Ordered by impact (my judgement):
1. **Real-hardware validation.** Everything so far was verified in QEMU only. Firmware quirks, ACPI, interrupt routing, PCI/USB hubs, storage and network cards will break things. This is the single largest risk and cannot be done in this sandbox. *Recommendation:* get a small matrix of machines (one Intel laptop, one AMD desktop) and a serial/USB debug path, and run `tools/test-all.sh` equivalents there.
2. **SMP (multi-core).** The kernel is single-CPU and several designs lean on that (syscalls run with interrupts masked, spawn-time wiring, lock ordering). Needs per-CPU data, TLB shootdowns, per-CPU run queues, an audit of every lock. L-XL. Mandatory for "optimized".
3. **Input and hardware breadth:** USB hubs/composite devices, touchpads (I2C-HID), NVMe, USB storage, audio, Wi-Fi (very hard: firmware per chipset, 802.11 stack, WPA2/3 supplicant; USB Ethernet and virtio first), suspend/resume and battery (ACPI). Each is M-XL.
4. **Graphics speed and quality:** damage-tracked compositing, vsync, font rendering and Unicode shaping, HiDPI, window animations without full redraws (section 1 tier 0).
5. **Application coverage:** a browser is the make-or-break application. Realistic candidates: NetSurf (small, has a framebuffer front end; M-L on top of the Linux layer) for basic pages; Servo/Firefox/Chromium need threads, `epoll`, `mmap` semantics, GPU or software GL and hundreds more syscalls (XL, and depends on the Linux layer's maturity). A terminal emulator, text editor, file manager (exists), media player, and an office suite are other expectations.
6. **Developer story:** a self-hosted toolchain would mean porting a C compiler and linker; `tcc` or `chibicc` are small enough to be M each.
7. **Security hardening:** third-party review of the register-restoring paths (SECURITY.md), fuzzing the syscall layer, KASLR, stack protector, a formal threat model, and supply-chain hygiene (signed releases, reproducible builds).
8. **Windows/Linux compatibility depth:** keep testing real programs (the busybox run in step 27 found a real `sendfile` bug in minutes: more real programs = more bugs found).

## 5. Roadmap items added (see ROADMAP.md "Strategic")
S1 virtio-gpu 2D + resizable display, S2 fast software compositing, S3 `/dev/fb0` + input for Linux programs, S4 DOOM via doomgeneric, S5 audio (HDA/virtio-snd), S6 SDL2 backend, S7 package manager + signed repository, S8 NVMe + USB storage, S9 filesystem journal/fsck/encryption/snapshots, S10 SMP, S11 browser (NetSurf first), S12 hardware test matrix.

## Sources consulted
- Intel graphics documentation: Intel "Graphics for Linux" developer reference (intel.com/content/www/us/en/docs/graphics-for-linux/developer-reference/), Intel PRM volumes hosted at x.org/docs/intel/ (e.g. DG1), and the Phoronix/PCPer reports on Intel publishing Haswell and Ivy Bridge programming documentation.
- AMD: GPUOpen "AMD GPU architecture programming documentation" (gpuopen.com/amd-isa-documentation), RDNA 1/2/3/3.5 ISA guides, machine-readable ISA.
- NVIDIA: Phoronix coverage of the Rust "Nova" Linux driver (initial submission for Linux 6.15; later status and the LPC 2026 talk) and of NVIDIA's work toward an upstream kernel driver.
- virtio-gpu: QEMU documentation (qemu.org/docs/master/system/devices/virtio/virtio-gpu.html), the `virtio-drivers` Rust crate (gpu module).
- doomgeneric (github.com/ozkl/doomgeneric and forks, including hobby-OS ports such as LemonDOOM): portable DOOM with a minimal platform interface.
- OSDev forum threads on hardware-accelerated graphics in hobby operating systems (for the general difficulty assessment).
