#!/bin/bash
# Rebuild the test programs added in post-alpha steps 19-24 into user/blobs/ (the outputs are committed).
# Needs: gcc (static glibc: libc6-dev + glibc static libs), x86_64-w64-mingw32-gcc (gcc-mingw-w64-x86-64).
# The older programs (linux_sig, linux_threads, win_k32, ...) were built the same way: `gcc -O1 -static [-pthread]` for
# Linux and `x86_64-w64-mingw32-gcc -O1` for Windows; see docs/HANDOFF.md for the per-program notes.
# After adding a program here also add it to BLOBS in tools/mkinitramfs.py and bump the file count in tools/shell-test.py.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
P="$ROOT/user/poc"; B="$ROOT/user/blobs"
gcc -O1 -static          "$P/linux_async.c" -o "$B/linux_async.elf"   # asynchronous signal delivery (step 19)
x86_64-w64-mingw32-gcc -O1 "$P/win_seh.c"   -o "$B/win_seh.exe"       # Windows vectored exceptions (step 20)
gcc -O1 -static -pthread "$P/linux_futex.c" -o "$B/linux_futex.elf"   # interruptible futex, per-thread masks (step 21)
gcc -O1 -static -pthread "$P/linux_tsig.c"  -o "$B/linux_tsig.elf"    # thread-directed signals (step 22)
gcc -O1 -static          "$P/linux_tty.c"   -o "$B/linux_tty.elf"     # interruptible console reads (step 23)
gcc -O1 -static          "$P/linux_jobs.c"  -o "$B/linux_jobs.elf"    # process groups / job control (step 24)
x86_64-w64-mingw32-gcc -O1 "$P/win_unwind.c" -o "$B/win_unwind.exe"   # .pdata unwinder primitives (step 25)
x86_64-w64-mingw32-gcc -O1 "$P/win_scope.c"  -o "$B/win_scope.exe"    # __C_specific_handler scope tables (step 25)
x86_64-w64-mingw32-g++ -O1 -static -static-libgcc -static-libstdc++ "$P/win_cpp.cc" -o "$B/win_cpp.exe"   # C++ exceptions (step 25; needs g++-mingw-w64-x86-64)
# the user-mode SEH runtime (ntdll's .pdata walker): exports Rtl{LookupFunctionEntry,VirtualUnwind,UnwindEx,Unwind} and __C_specific_handler
( cd "$ROOT/user/seh" && x86_64-w64-mingw32-gcc -O2 -shared -nostdlib -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,DllMain -o "$B/deloxy_seh.dll" deloxy_seh.c deloxy_seh.def -lkernel32 )
ls -l "$B"/linux_async.elf "$B"/win_seh.exe "$B"/linux_futex.elf "$B"/linux_tsig.elf "$B"/linux_tty.elf "$B"/linux_jobs.elf "$B"/win_unwind.exe "$B"/win_scope.exe "$B"/win_cpp.exe "$B"/deloxy_seh.dll
