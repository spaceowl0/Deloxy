# Deloxy 0.1.0-alpha

A from-scratch x86-64 kernel in Rust (`#![no_std]`), booted by Limine (BIOS + UEFI). **Alpha: it is a research kernel, not a daily-driver OS.**

What it has: preemptive multitasking and ring 3, capability security (no ambient authority), zero-copy shared-memory IPC, a lockless audit stream,
a graphical desktop (**deloxy-de**, with an on-screen terminal), loaders for native ELF, Linux ELF and Windows PE programs, a read-only initramfs,
a shell (**deloxy-sh**), a stats monitor, and **air-gapped-by-default networking**: the NIC stays reset and silent until you explicitly grant
time-boxed access to one host and port, every frame goes through a default-deny firewall, and a pull-only updater (**deloxy-upd**) accepts only
Ed25519-signed manifests. Read `docs/KNOWN_ISSUES.md` and `docs/SECURITY.md` before trusting any of it.

## Try it
```
qemu-system-x86_64 -M q35 -m 512M -cdrom deloxy-0.1.0-alpha.iso -serial stdio          # desktop window + shell on the serial console
qemu-system-x86_64 -M q35 -m 512M -cdrom deloxy-0.1.0-alpha.iso -display none -serial stdio   # headless: just the shell
```
At the `deloxy-sh>` prompt: `help`, `ls`, `run hello_win.exe`, `run hello_linux.elf`, `run monitor.elf 3 500`, `ps`, `caps`, `audit`, `poweroff`.
Persistent storage: add `-drive file=disk.img,if=none,id=d0,format=raw -device virtio-blk-pci,drive=d0` (e.g. `truncate -s 64M disk.img`), run `format` once in the shell, then `save`, `cp`, `rm`, `df`; files survive power-off, and `ls`/`cat`/`run` see them.
Desktop: start menu, desktop icons, Settings (dark/light, 8 accents, 4 wallpapers, taskbar top/bottom, rounded/square corners, 12/24 h clock). Customize from the shell too: `save de.conf theme=light accent=orange taskbar=top` (hot-reloaded, persisted on the store disk).
Files app, calendar and shortcuts (Alt+Tab, Alt+F4, Super, Ctrl+Alt+T): see HANDOFF 9e. Custom wallpaper: `save de.conf wallpaper=file:sample-wall.ppm` (any P6 PPM in the store works too).
Run it: `dist/deloxy.iso` boots in QEMU (`tools/run-qemu.sh dist/deloxy.iso`). Threads: `run linux_threads.elf` (pthreads) and `run win_threads.exe` (CreateThread).
Security: foreign programs ask before touching files or connecting to a host (Permissions manager in the start menu, `perms` in the shell) (`perms` lists/changes decisions); Task Manager, notifications and a right-click menu are in the desktop.
Compatibility (interactive too: `run linux_stdin.elf`, `run win_k32.exe`): `run linux_glibc.elf` (static glibc program) and `run win_msvcrt.exe` (MinGW C program) are real compiler output running unmodified.
In the graphical window the **terminal** is the focused window: type there. Add `-netdev user,id=n0 -device virtio-net-pci,netdev=n0` to give the VM a NIC,
and run `python3 tools/mock-update-server.py serve` on the host, then `upd check` in the shell: it asks for consent, grants 60 s of access to 10.0.2.2:8777, verifies the
signature, and drops the network again. (The compiled-in update key is a public TEST key, see SECURITY.md.)

## Build
Needs the pinned nightly in `rust-toolchain.toml` (+ `rust-src`), `qemu-system-x86`, `xorriso`, `python3`, a C compiler (and `ovmf` for UEFI tests). Dependencies are vendored (`vendor/`, offline).
```
tools/make-release.sh      # -> dist/deloxy-0.1.0-alpha.iso, deloxy-core-0.1.0-alpha.elf, SHA256SUMS
tools/test-all.sh          # full QEMU suite: selftest (BIOS/UEFI/NIC/disk), page-fault proof, desktop UI, network+updater, shell and persistent store (BIOS/UEFI)
```
Honesty note: everything here was developed and tested in a sandbox with the distro's rustc 1.75 and the workarounds in `tools/dev-container/` (see `docs/HANDOFF.md`);
the pinned-nightly path is the intended one but has not been run by the author. No real hardware has been tested.

Docs: `docs/HANDOFF.md` (architecture + state) - `docs/ABI.md` (syscalls, capabilities) - `docs/SECURITY.md` - `docs/KNOWN_ISSUES.md` - `docs/ROADMAP.md` - `BUILD-OFFLINE.md`
