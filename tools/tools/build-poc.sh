#!/bin/bash
# Rebuild the proof-of-concept programs into user/blobs/ (outputs are committed):
#   hello_native.elf  - Rust, Deloxy ABI          (needs Rust + ld.lld/objcopy, see build-user.sh)
#   hello_linux.elf   - C, static, no libc        (needs gcc)
#   hello_linux_pie.elf - same, static-pie        (needs gcc)
#   hello_win.exe     - C, PE32+, kernel32 only   (needs gcc-mingw-w64-x86-64)
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
B="$ROOT/user/blobs"
gcc -O1 -static -nostdlib -fno-pie -no-pie -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables \
    -Wl,-z,max-page-size=4096 -Wl,-z,noseparate-code -Wl,--build-id=none "$ROOT/user/poc/hello_linux.c" -o "$B/hello_linux.elf"
gcc -O1 -nostdlib -fPIE -static-pie -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables \
    -Wl,-z,max-page-size=4096 -Wl,--build-id=none "$ROOT/user/poc/hello_linux.c" -o "$B/hello_linux_pie.elf" || echo "static-pie build failed (optional)"
x86_64-w64-mingw32-gcc -O1 -ffreestanding -nostdlib -fno-stack-protector -Wl,--subsystem,console -Wl,-e,mainCRTStartup \
    "$ROOT/user/poc/hello_win.c" -lkernel32 -o "$B/hello_win.exe"
ls -l "$B"/hello_*
# hello_native.elf is built from user/poc/native with `-T user/elf.ld` (see BUILD-OFFLINE.md); the committed ELF is the artifact.
