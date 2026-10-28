@echo off
rem Run the Deloxy ISO in QEMU on Windows (install QEMU from https://www.qemu.org/download/#windows first).
rem usage: run-qemu.bat [deloxy.iso]      (disks: see the comment block in run-qemu.sh)
set ISO=%1
if "%ISO%"=="" set ISO=deloxy.iso
rem Intel e1000 NIC + USB keyboard/tablet on an xHCI controller (use virtio-net-pci instead of e1000 if you prefer)
qemu-system-x86_64 -M q35 -cpu max -device virtio-rng-pci -m 512M -cdrom %ISO% -serial stdio -netdev user,id=n0 -device e1000,netdev=n0 -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 -device usb-tablet,bus=xhci.0
