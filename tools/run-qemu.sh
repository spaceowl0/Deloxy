#!/bin/bash
# Run the Deloxy ISO in QEMU.
# (uses -cpu max + virtio-rng-pci so the kernel RNG is seeded from hardware; see docs/HANDOFF.md 9m)
# usage: tools/run-qemu.sh [deloxy.iso] [--uefi] [--disk disk.img] [--no-net] [--e1000] [--ahci] [--usb]
#   --disk creates a 64 MiB persistent store disk if the file does not exist (format it once with `format` in the shell)
#   --e1000 uses an Intel e1000 NIC instead of virtio-net;  --ahci puts the disk on an AHCI/SATA controller
#   --usb adds an xHCI controller with a USB keyboard and tablet (absolute pointer: no mouse grabbing needed)
ISO="${1:-deloxy.iso}"; shift 2>/dev/null
UEFI=0; DISK=""; NET=1; NIC=virtio-net-pci; AHCI=0; USB=0
while [ $# -gt 0 ]; do case "$1" in --uefi) UEFI=1;; --disk) DISK="$2"; shift;; --no-net) NET=0;; --e1000) NIC=e1000;; --ahci) AHCI=1;; --usb) USB=1;; esac; shift; done
ARGS=(-M q35 -cpu max -device virtio-rng-pci -m 512M -cdrom "$ISO" -serial stdio -device isa-debug-exit,iobase=0xf4,iosize=0x04)
[ "$NET" = 1 ] && ARGS+=(-netdev user,id=n0 -device $NIC,netdev=n0)
if [ -n "$DISK" ]; then
  [ -f "$DISK" ] || { truncate -s 64M "$DISK"; echo "created $DISK (run 'format' in the shell once)"; }
  ARGS+=(-drive file="$DISK",if=none,id=d0,format=raw)
  if [ "$AHCI" = 1 ]; then ARGS+=(-device ich9-ahci,id=ahci -device ide-hd,drive=d0,bus=ahci.0); else ARGS+=(-device virtio-blk-pci,drive=d0); fi
fi
[ "$USB" = 1 ] && ARGS+=(-device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 -device usb-tablet,bus=xhci.0)
if [ "$UEFI" = 1 ]; then
  for f in /usr/share/ovmf/OVMF.fd /usr/share/OVMF/OVMF.fd /usr/share/qemu/OVMF.fd /opt/homebrew/share/qemu/edk2-x86_64-code.fd; do [ -f "$f" ] && ARGS+=(-bios "$f") && break; done
fi
exec qemu-system-x86_64 "${ARGS[@]}"
