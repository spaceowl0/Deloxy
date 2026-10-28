#!/bin/bash
# usage: run-test.sh <kernel-elf> [seconds]
set -e
K=$1; T=${2:-6}
rm -rf /tmp/iso && mkdir -p /tmp/iso/boot/limine /tmp/iso/EFI/BOOT
cp "$K" /tmp/iso/boot/deloxy-core
cp /home/claude/deloxy-core/limine.conf /tmp/iso/boot/limine/
cp /home/claude/limine-bin/limine-bios.sys /home/claude/limine-bin/limine-bios-cd.bin /home/claude/limine-bin/limine-uefi-cd.bin /tmp/iso/boot/limine/
cp /home/claude/limine-bin/BOOTX64.EFI /tmp/iso/EFI/BOOT/
xorriso -as mkisofs -R -r -J -b boot/limine/limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table -hfsplus -apm-block-size 2048 --efi-boot boot/limine/limine-uefi-cd.bin -efi-boot-part --efi-boot-image --protective-msdos-label /tmp/iso -o /tmp/deloxy.iso 2>/dev/null
/home/claude/limine-bin/limine bios-install /tmp/deloxy.iso >/dev/null 2>&1
rm -f /tmp/serial.log
timeout $T qemu-system-x86_64 -M q35 -m 256M -cdrom /tmp/deloxy.iso -serial file:/tmp/serial.log -display none -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 ${QEMU_EXTRA} || true
cat /tmp/serial.log | sed 's/\x1b\[[0-9;]*m//g'
