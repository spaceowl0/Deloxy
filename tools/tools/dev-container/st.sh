#!/bin/bash
# usage: st.sh <kernel-elf> [secs] ; prints serial log tail and QEMU exit status (33=pass)
K=$1; T=${2:-90}; shift 2
bash /home/claude/deloxy-core/tools/dev-container/mkiso.sh "$K" /tmp/st.iso
rm -f /tmp/st.log
timeout $T qemu-system-x86_64 -M q35 -m 256M -cdrom /tmp/st.iso -serial file:/tmp/st.log -display none -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 "$@"
echo "QEMU_RC=$?"
