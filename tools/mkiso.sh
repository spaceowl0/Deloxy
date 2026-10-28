#!/bin/bash
# Build a bootable (BIOS + UEFI) Deloxy ISO from a kernel ELF.
#   tools/mkiso.sh <kernel-elf> <out.iso>
# Needs: xorriso, python3, a C compiler (to build Limine's host tool from third_party/limine/limine.c).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
K="${1:?usage: mkiso.sh <kernel-elf> <out.iso>}"; OUT="${2:?usage: mkiso.sh <kernel-elf> <out.iso>}"
L="$ROOT/third_party/limine"
TOOL="${TMPDIR:-/tmp}/deloxy-limine-tool"
[ -x "$TOOL" ] || ${CC:-cc} -O2 -o "$TOOL" "$L/limine.c"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
mkdir -p "$W/boot/limine" "$W/EFI/BOOT"
cp "$K" "$W/boot/deloxy-core"
python3 "$ROOT/tools/mkinitramfs.py" "$W/boot/initramfs.tar" >/dev/null
# ROOTFS_DIR: a directory tree that becomes the read-only hierarchical root filesystem (second boot module); empty if unset
python3 "$ROOT/tools/mkrootfs.py" "$W/boot/rootfs.tar" "${ROOTFS_DIR:-$ROOT/user/rootfs-test}" >/dev/null
cp "$ROOT/limine.conf" "$L/limine-bios.sys" "$L/limine-bios-cd.bin" "$L/limine-uefi-cd.bin" "$W/boot/limine/"
cp "$L/BOOTX64.EFI" "$W/EFI/BOOT/"
# SOURCE_DATE_EPOCH keeps the ISO layout reproducible apart from xorriso's own timestamps.
xorriso -as mkisofs -R -r -J -b boot/limine/limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table \
  -hfsplus -apm-block-size 2048 --efi-boot boot/limine/limine-uefi-cd.bin -efi-boot-part --efi-boot-image \
  --protective-msdos-label "$W" -o "$OUT" 2>/dev/null
"$TOOL" bios-install "$OUT" >/dev/null 2>&1
echo "wrote $OUT ($(du -h "$OUT" | cut -f1))"
