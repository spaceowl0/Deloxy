#!/bin/bash
# Full Deloxy test suite (all in QEMU). Exit status 0 = everything passed.
#   tools/test-all.sh            needs: rust (see rust-toolchain.toml), qemu-system-x86, xorriso, python3, cc, OVMF (optional)
# Phases: selftest (BIOS, with/without NIC, with a virtio-blk disk, UEFI) | test-pf | desktop UI | net/updater end-to-end |
#         shell end-to-end (BIOS, UEFI) | persistent store end-to-end across 3 boots (BIOS, UEFI) | compat: real glibc ELF + mingw PE programs (BIOS, UEFI)
source "$(dirname "$0")/lib-build.sh"
OUT="${OUT:-/tmp/deloxy-test}"; mkdir -p "$OUT"
OVMF=""; for f in /usr/share/ovmf/OVMF.fd /usr/share/OVMF/OVMF.fd /usr/share/qemu/OVMF.fd; do [ -f "$f" ] && OVMF="$f" && break; done
FAILS=0; RESULTS=()
phase() { # name status
  if [ "$2" = 0 ]; then RESULTS+=("PASS  $1"); else RESULTS+=("FAIL  $1"); FAILS=$((FAILS+1)); fi
  echo "== $([ "$2" = 0 ] && echo PASS || echo FAIL): $1"
}
selftest() { # name iso extra-qemu-args...
  local name="$1" iso="$2"; shift 2
  rm -f "$OUT/st.log"
  timeout 240 qemu-system-x86_64 -M q35 -m 256M -cdrom "$iso" -serial file:"$OUT/st.log" -display none -no-reboot \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 "$@"
  local rc=$?
  [ $rc = 33 ] || { echo "-- last log lines:"; sed 's/\x1b\[[0-9;]*m//g' "$OUT/st.log" | tail -5; }
  [ $rc = 33 ]; phase "$name (qemu status $rc)" $?
}
NIC=(-netdev user,id=n0 -device virtio-net-pci,netdev=n0)

build_kernel selftest || exit 2
tools/mkiso.sh "$KERNEL" "$OUT/selftest.iso" >/dev/null || exit 2
selftest "selftest, BIOS, no NIC" "$OUT/selftest.iso"
selftest "selftest, BIOS, virtio-net" "$OUT/selftest.iso" "${NIC[@]}"
rm -f "$OUT/scratch.img"; truncate -s 16M "$OUT/scratch.img"
selftest "selftest, BIOS, virtio-blk store + NIC" "$OUT/selftest.iso" "${NIC[@]}" -drive file="$OUT/scratch.img",if=none,id=d0,format=raw -device virtio-blk-pci,drive=d0
if [ -n "$OVMF" ]; then selftest "selftest, UEFI (OVMF)" "$OUT/selftest.iso" -bios "$OVMF"; else echo "-- OVMF not found: UEFI phases skipped"; RESULTS+=("SKIP  UEFI phases (no OVMF)"); fi

build_kernel test-pf || exit 2
tools/mkiso.sh "$KERNEL" "$OUT/testpf.iso" >/dev/null && selftest "selftest + guard-page #PF proof" "$OUT/testpf.iso"

build_kernel net-test || exit 2
tools/mkiso.sh "$KERNEL" "$OUT/nettest.iso" >/dev/null
python3 tools/net-test.py "$OUT/nettest.iso" "$OUT/nt" | grep -v '^served' | tail -4; phase "net/updater end-to-end (kernel-driven)" ${PIPESTATUS[0]}

build_kernel "" || exit 2
tools/mkiso.sh "$KERNEL" "$OUT/normal.iso" >/dev/null
python3 tools/ui-test.py "$OUT/normal.iso" "$OUT/ui" | tail -3; phase "desktop UI + terminal" ${PIPESTATUS[0]}
python3 tools/shell-test.py "$OUT/normal.iso" "$OUT/sh" | grep -v '^served' | tail -3; phase "shell end-to-end, BIOS" ${PIPESTATUS[0]}
if [ -n "$OVMF" ]; then python3 tools/shell-test.py "$OUT/normal.iso" "$OUT/sh-uefi" --uefi "$OVMF" | grep -v '^served' | tail -3; phase "shell end-to-end, UEFI" ${PIPESTATUS[0]}; fi
python3 tools/store-test.py "$OUT/normal.iso" "$OUT/store" | grep -v '^served' | tail -3; phase "persistent store end-to-end (3 boots), BIOS" ${PIPESTATUS[0]}
if [ -n "$OVMF" ]; then python3 tools/store-test.py "$OUT/normal.iso" "$OUT/store-uefi" --uefi "$OVMF" | grep -v '^served' | tail -3; phase "persistent store end-to-end (3 boots), UEFI" ${PIPESTATUS[0]}; fi
python3 tools/pfs-test.py "$OUT/normal.iso" "$OUT/pfs" | grep -v '^PASS' | tail -3; phase "persistent folders + DLLs + CPU-fault signals (2 boots)" ${PIPESTATUS[0]}
rm -f "$OUT/files.img"; truncate -s 64M "$OUT/files.img"
DISK="$OUT/files.img" python3 tools/runone.py "$OUT/normal.iso" "~format" "yes" "mkdir /home" "mkdir /home/docs" "save /home/note.txt hello-from-home" "save /home/docs/deep.txt deepfile" "save top.txt toplevel" >/dev/null
python3 tools/files-test.py "$OUT/normal.iso" "$OUT/files.img" "$OUT/files" | grep -v '^PASS' | tail -3; phase "Files app folder browsing (GUI, store disk)" ${PIPESTATUS[0]}
python3 tools/compat-test.py "$OUT/normal.iso" "$OUT/compat" | tail -3; phase "compat: glibc ELF + mingw PE, BIOS" ${PIPESTATUS[0]}
if [ -n "$OVMF" ]; then python3 tools/compat-test.py "$OUT/normal.iso" "$OUT/compat-uefi" --uefi "$OVMF" | tail -3; phase "compat: glibc ELF + mingw PE, UEFI" ${PIPESTATUS[0]}; fi

echo; echo "=========== summary ==========="; printf '%s\n' "${RESULTS[@]}"
[ $FAILS = 0 ] && echo "ALL PASSED" || echo "$FAILS PHASE(S) FAILED"
exit $FAILS
