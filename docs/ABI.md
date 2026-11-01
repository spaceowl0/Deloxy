# Deloxy native ABI (alpha, unstable)
Entry: `syscall`. RAX = number; args RDI, RSI, RDX, R10, R8, R9; result in RAX, negative = `-errno`. Syscalls run with interrupts disabled.
Every syscall is audited; EPERM/EBADF results are logged as `EV_CAP_DENIED`. A native process is an ELF with the Deloxy PT_NOTE (`.note.deloxy`)
or a flat binary started by the kernel; everything else is a Linux or NT process (own conventions, see HANDOFF.md).

## Startup info page (read-only, at 0x300000, native processes started by `exec::spawn`)
u64 words: `[0]=role [1]=n [2]=side [3..8)=first five capability handles [8]=args_len`, then NUL-separated argv bytes from offset 128 (max 1024).
`cap_list` (29) enumerates all handles, so programs find capabilities by kind instead of by position.

## Syscalls
| nr | name | args | notes |
|---|---|---|---|
| 0 | exit | code | |
| 1 | yield | | |
| 2 | sleep_ms | ms | |
| 3 | write_debug | ptr, len | ambient serial output (<= 512 bytes); kept for bring-up programs |
| 4/5 | mmap_anon / munmap | len / addr,len | |
| 6/7 | thread_spawn / thread_exit | entry, stack_top | |
| 8 | time_now_ms | | |
| 9/10 | getpid / gettid | | |
| 11 | cap_drop | h | dropping the last reference to a NetGrant switches the NIC off |
| 12/13 | cap_derive / cap_info | h, rights / h | derive can only remove rights |
| 14 | shm_map | h | |
| 15/16 | futex_wait / futex_wake | addr,expected / addr,n | no timeouts |
| 17/18 | port_in / port_out | h, port[, val] | needs `IoPort` cap covering the port |
| 19 | audit_read | h, buf, max | `AuditStream` cap; 64-byte `AuditEvent`s |
| 20 | stat | buf: `SysStats` | `reserved` = net_tx<<32 \| net_rx (frames, saturating) |
| 21 | tty_read | h, buf, max, timeout_ms | `Tty` READ; blocks until >=1 byte; timeout `u64::MAX` = forever, 0 bytes on timeout |
| 22 | tty_write | h, buf, len<=512 | `Tty` WRITE |
| 23 | fs_list | dir, index, buf, max | `Dir` READ; returns `size<<8 \| name_len`, -ENOENT at end |
| 24 | fs_open | dir, name, len | `Dir` READ -> `File` handle (READ+EXEC); flat names only |
| 25 | file_read | f, off, buf, len<=4096 | 0 at EOF; accepts `File` and `StoreFile` |
| 26 | proc_spawn | spawn, file, args, args_len, errbuf, errmax | `Spawn` EXEC + `File` EXEC -> `Proc` handle; -8 (ENOEXEC) + message on a bad image |
| 27 | proc_wait | proc, out_ptr | writes the i64 exit code |
| 28 | proc_list | sys, index, buf | `Sys` READ; 64-byte records (pid, threads, abi, exited, name) |
| 29 | cap_list | index, buf | 16-byte records (handle, kind, rights) of the caller's own table |
| 30 | net_grant | admin, ip, port, secs<=3600, bytes | `NetAdmin` GRANT -> `Net` handle (TCP, /32, one port) |
| 31 | upd | net, req_ptr | 256-byte in/out request; see `src/sys/sysx.rs` |
| 32 | power | h, op (0 off, 1 reboot) | `Power` EXEC |
| 33 | store_list | h, index, buf, max | `Store` READ; returns `size<<8 \| name_len`, -ENOENT at end, -ENODEV if no store is mounted |
| 34 | store_open | h, name, len | `Store` READ -> `StoreFile` handle (READ+EXEC); contents are CRC-checked at open (-EIO if damaged) |
| 35 | store_write | h, name, len, data, dlen<=16 MiB | `Store` WRITE; atomic create/replace of a *flat* name in the store root; -EPERM for `upd.*`, -ENOSPC, -EFBIG, -EINVAL (bad name); use 38 for paths |
| 36 | store_ctl | h, op, name, len, out | op 0 delete (WRITE), 1 stats -> 6 x u64 {total, data, used bytes, files, generation, directories} (READ), 2 format (GRANT, destroys all data) |
| 38 | store_fs | h, op, path, plen, a4, a5 | hierarchical store (paths like `/home/a.txt`, `/store/x`; `upd.*`/`perms.*` protected). op 0 stat -> 32-byte record at a4 {kind u8 (1 file, 2 dir, 3 symlink) @0, mode u16 @2, size u64 @8, mtime u64 @16, inode u32 @24} (READ); 1 readdir(a5 = index) -> 320-byte record at a4 {kind @0, size u64 @8, name @16}, returns name length, -ENOENT past the end (READ); 2 mkdir, 3 rmdir, 4 unlink, 5 rename (a4/a5 = destination ptr/len), 6 symlink (a4/a5 = target ptr/len), 8 chmod (a4 = mode), 10 write (a4/a5 = data ptr/len; create or atomically replace) (all WRITE); 7 readlink -> bytes at a4 (cap a5), 9 read -> bytes at a4 (cap a5), returns the file size (READ) |

## Capability kinds (`cap_info` / `cap_list`)
1 memory, 2 channel, 3 ioport, 4 audit, 5 process-id, 6 console, 7 net-grant, 8 net-admin, 9 dir, 10 file, 11 spawn, 12 tty, 13 sys, 14 power, 15 proc, 16 store, 17 store-file.
Rights bits are defined in `src/cap/mod.rs`. Handles are generation-tagged: a stale or forged handle returns EBADF.
There is **no stable ABI yet**: numbers and struct layouts may change before 1.0.

## Foreign programs and files (deloxy-wltd v2)
`Spawn { console, files }`: when `files` is set, `proc_spawn` gives Linux/NT children `Dir`(READ) and `Store`(READ|WRITE) capabilities (never native children). Linux `open/openat/read/write/lseek/close/stat...` and msvcrt `fopen/fread/fwrite/...` see two namespaces. **Bare names and the root** are the flat view (initramfs files, read-only, searched first, then the files in the root directory of the store). **The persistent tree** is hierarchical and writable: `/store/...` plus `/home /var /opt /srv /root /mnt /data` (the latter only when the read-only root tree has no entry of that name); `mkdir/rmdir/unlink/rename/symlink/readlink/chmod/truncate`, `stat/lstat` (type, mode, size, mtime, inode), `getdents64` (DT_DIR) and `chdir` work there; hard links fail with EPERM; symlink targets are resolved inside the tree (absolute targets start at the store root, a `/store/` prefix is accepted); `chmod` bits are stored and reported but do not gate access (capabilities do). Writes are buffered and committed atomically at close/exit; `upd.*` and `perms.*` at the store root are kernel-owned (EACCES). Win32 paths drop a `C:` drive prefix; `CreateDirectory/RemoveDirectory/MoveFile/FindFirstFile` use the same tree. Errors: ENOENT (missing, or no capability for that space), EACCES (write not permitted / reserved name), EEXIST, ENOTDIR, EISDIR, ENOTEMPTY, ELOOP (> 16 symlink hops), ENOSPC, EMFILE (64 open files), EFBIG (> 16 MiB).

**CPU faults (Linux ABI):** `#DE`, `#UD`, `#GP`, `#PF` raise SIGFPE, SIGILL, SIGSEGV, SIGSEGV with `siginfo` (`si_code`: SEGV_MAPERR/SEGV_ACCERR/FPE_INTDIV/ILL_ILLOPC/SI_KERNEL, `si_addr`). A handler installed with `sigaction` runs on the user stack or on the `sigaltstack` (`SA_ONSTACK`); returning from it restarts the faulting instruction (`rcx`/`r11` are not preserved). SIG_DFL, SIG_IGN, a blocked signal or an unwritable signal frame kill the process (`wait4`: signalled).

**Windows DLLs (NT ABI):** DLL files in the initramfs or the store root are loaded for static imports (by name or ordinal, forwarded exports followed, `DllMain` called with DLL_PROCESS_ATTACH before the program starts) and by `LoadLibraryA/W/ExA/ExW` + `GetProcAddress` + `GetModuleHandle*` + `FreeLibrary` (DLL_PROCESS_DETACH when the reference count drops to zero). No thread notifications, no DLL TLS.

## Permissions (syscall 37, capability kind 18)
`perm(h, op, a2, a3, a4)` with a `Policy` capability: op 0 list (a2 = index, a4 = 64-byte out record: name[40], hash[16], flags@56 (1 R, 2 W), once@57), op 1 set (a2/a3 = program file name, a4 = flags: bit0 R, bit1 W, bit8 once), op 2 revoke (a2/a3 = name), op 3 set network rule (a2/a3 = program file name, a4 = pointer to a 16-byte struct { ip[4], port u16, allow u8, flags u8 (bit0 any host, bit1 internet only), secs u32, kib u32 }; secs/kib 0 = unlimited). READ for list, WRITE for set/revoke. list record is 80 bytes (flags@56, once@57, kind@58 = 1 for network rules, ip@60, port u16 @64, flags@66, secs u32 @68, kib u32 @72). `proc_list` (28) record: pid u64, threads u32, abi u8, exited u8, name[40] at 16, memory KiB u32 at 56.

## Linux ABI additions (steps 18-24)
**Signals.** Handled, unblocked signals are delivered at syscall exit *and* on the 1 kHz timer tick (`signals::deliver_async`): the frame is the usual `rt_sigframe`; for a tick-interrupted thread it also stores the real `rcx`/`r11` and stamps `uc_flags = 0x444C58415359 4E43` so `rt_sigreturn` resumes through a full-register `iretq` (every register and the FXSAVE image come back exactly). Signal masks are **per thread** (`rt_sigprocmask`, `sigsuspend`, `pthread_sigmask`; a new thread inherits its creator's mask); pending is process-wide plus a per-thread set filled by `tkill(200)`/`tgkill(234)`. `kill(pid)` with `pid == 0` addresses the caller's process group, `pid < -1` group `-pid`, `pid == -1` every Linux process the caller may signal (itself, parent, children, same session).
**Interruptible waits** return `-ERESTART` (restarted when the handler has `SA_RESTART`, else `EINTR`): untimed `FUTEX_WAIT`, console `read(0)` (a partly typed line is kept), `wait4`, `accept`, `recv`, pipes; timed `FUTEX_WAIT`, `nanosleep`/`clock_nanosleep` and `connect` return `EINTR` and are never restarted.
**Process groups / sessions:** `getpgrp`(111), `getpgid`(121), `getsid`(124), `setpgid`(109), `setsid`(112). A process started by the shell leads its own group and session; `fork` inherits both. `wait4(pid)`: `> 0` that child, `-1` any, `0` a child of the caller's group, `< -1` group `-pid`; options `WNOHANG`(1), `WUNTRACED`(2) -> status `sig<<8 | 0x7f`, `WCONTINUED`(8) -> status `0xffff`.
**Job control:** SIGSTOP, and SIGTSTP/SIGTTIN/SIGTTOU with default disposition, stop all threads of the process (each parks on its next syscall exit or timer tick); SIGCONT resumes; SIGCHLD goes to the parent on both. Ctrl-C (byte 0x03 on the console) sends SIGINT to the group(s) of the top-level Linux programs attached to the console.
**futex** is also reachable from the Linux layer with `FUTEX_WAIT` (timed and untimed) and `FUTEX_WAKE`; the *native* syscall 15/16 (above) is unchanged.

## NT (Windows) ABI additions (step 20): exceptions
Hardware faults (`#PF/#GP` -> `0xC0000005` with `ExceptionInformation = [0 read | 1 write | 8 exec, address]`, `#DE` -> `0xC0000094`, `#UD` -> `0xC000001D`) and `RaiseException` call, in order, the handlers added with `AddVectoredExceptionHandler(First, fn)` (First != 0 inserts at the front; `RemoveVectoredExceptionHandler`) and then the filter set with `SetUnhandledExceptionFilter`. The handler gets `EXCEPTION_POINTERS*` in `rcx` (record + a 0x4D0-byte `CONTEXT` with all GPRs, rip/rsp/eflags and the FXSAVE image at +0x100) and returns `-1` (resume from the possibly edited CONTEXT), `0` (next handler) or, for the filter, `1` (terminate with the exception code). Handlers return into a stub at thunk page + `0x3D00` that calls the internal shim `__DeloxyExcReturn`. Not implemented: `.pdata`/UNWIND_INFO, `__try/__except`, `RtlUnwind*`, `RtlVirtualUnwind`, `RtlCaptureContext`.

## Files app (deloxy-de)
Browses the hierarchical store: folders first, `..` row, Backspace = up, New folder button, Delete (files/symlinks with unlink, folders with rmdir only when empty); system (initramfs) files are listed at the top level only and are read-only.

### NT exceptions, table-based part (step 25)
Handler chain per exception: vectored handlers (in order) -> the SEH runtime's frame dispatcher (if `deloxy_seh.dll` is loaded) -> `SetUnhandledExceptionFilter`. The runtime is bound into a PE program whenever it imports `RtlLookupFunctionEntry`, `RtlVirtualUnwind`, `RtlUnwindEx`, `RtlUnwind` or `__C_specific_handler`; extra kernel32 shims it relies on: `__DeloxyModuleInfo(pc, out*)`, `__DeloxyRegisterSeh(fn)`, `RtlCaptureContext(ctx)`, `RtlRestoreContext(ctx, rec)`. `DISPATCHER_CONTEXT` is filled with ControlPc, ImageBase, FunctionEntry, EstablisherFrame, TargetIp (unwind only), ContextRecord, LanguageHandler, HandlerData, HistoryTable (always NULL), ScopeIndex. Unwinding out of a handler call lands in the stub at thunk page + 0x3D00, which the runtime treats as a machine frame (continues in the saved exception CONTEXT).
