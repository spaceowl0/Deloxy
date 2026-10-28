# Building offline
Dependencies are vendored (`vendor/`, Cargo.lock pinned). Nothing is downloaded.
Nightly toolchain with target x86_64-unknown-none installed (see rust-toolchain.toml):
    cargo build            # -> target/x86_64-unknown-none/debug/deloxy-core
Run (needs qemu, xorriso, and a Limine v8 binary release with `make` run once):
    LIMINE_DIR=/path/to/limine tools/qemu-test.sh
Note: M1 was verified with rustc 1.75 + RUSTC_BOOTSTRAP=1 + x86_64 crate pinned to 0.15.1 in Cargo.lock.
Status (all verified in QEMU, BIOS, 256 MiB):
  M1   boot, serial, GDT/IDT, frame allocator
  M1.5 IrqMutex, own boot stack, backtraces, isa-debug-exit test harness
  M2   VMM (NX/WP), kernel heap, guard-paged stacks
  M3   ACPI MADT, LAPIC timer (PIT-calibrated, 1 kHz), preemptive round-robin scheduler,
       SYSCALL/SYSRET, ring 3, user address spaces, fault containment, 11 syscalls
  M4   capability table (generation-checked handles, rights, attenuation, cascade revoke),
       lockless SPSC ring (shared verbatim with user space), shared-memory channels,
       futex, audit_log! stream, 19 syscalls, Rust ring-3 test program (user/utest)
  M5   framebuffer + mirrored boot console, PS/2 keyboard/mouse (IOAPIC-routed), compositor with
       damage tracking/decorations/taskbar/cursor, wm-protocol over channels, 3 ring-3 desktop clients
       (user/de), SYS_STAT; end-to-end UI test (tools/ui-test.py: QEMU monitor input + screendump pixel checks)
  M6   ELF64 + PE32+ loaders (strict W^X, bounds-checked), Linux x86-64 syscall layer, Win32/kernel32 shim (35 functions),
       Console capability for foreign stdout, FS/GS bases per thread, 10,000-case loader fuzz test
Test builds:  cargo build --features selftest   (all tests; QEMU exit status 33 = pass)
              cargo build --features test-pf    (also proves the guard-page #PF path)
Known limits: single CPU (syscall stack is a global, no GS/SWAPGS yet); syscalls run with
interrupts off; SMAP not enabled (user memory is only touched via the HHDM, never directly);
M4 deferrals: capability transfer over channels, user-side shm_create/chan_create (needs a factory capability), futex timeouts, per-CPU audit rings; killed-while-blocked threads may leak their process (not the frames of tests).
Ring-3 test programs: user/blobs/*.asm (nasm) with committed .bin outputs.

User programs: tools/build-user.sh rebuilds user/blobs/utest.bin from user/utest (committed .bin means it is only needed when editing).

UI test: build the ISO (tools/qemu-test.sh creates one), then  python3 tools/ui-test.py <iso> <outdir>
(needs qemu; Pillow optional for PNG output). Screenshots from a verified run: docs/screenshots/.
M5 deferrals: external window-manager client (policy is built into the compositor), client-created buffers
(need a factory capability), GPU acceleration (software renderer only), USB input, text terminal app.
Font: DejaVu Sans Mono rasterised by tools/gen_font.py (Bitstream Vera licence, see NOTICE).
