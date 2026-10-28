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
| 35 | store_write | h, name, len, data, dlen<=4 MiB | `Store` WRITE; atomic create/replace; -EPERM for `upd.*`, -ENOSPC, -EFBIG, -EINVAL (bad name) |
| 36 | store_ctl | h, op, name, len, out | op 0 delete (WRITE), 1 stats -> 5 x u64 {total, data, used bytes, files, generation} (READ), 2 format (GRANT, destroys all data) |

## Capability kinds (`cap_info` / `cap_list`)
1 memory, 2 channel, 3 ioport, 4 audit, 5 process-id, 6 console, 7 net-grant, 8 net-admin, 9 dir, 10 file, 11 spawn, 12 tty, 13 sys, 14 power, 15 proc, 16 store, 17 store-file.
Rights bits are defined in `src/cap/mod.rs`. Handles are generation-tagged: a stale or forged handle returns EBADF.
There is **no stable ABI yet**: numbers and struct layouts may change before 1.0.

## Foreign programs and files (deloxy-wltd v2)
`Spawn { console, files }`: when `files` is set, `proc_spawn` gives Linux/NT children `Dir`(READ) and `Store`(READ|WRITE) capabilities (never native children). Linux `open/openat/read/write/lseek/close/stat...` and msvcrt `fopen/fread/fwrite/...` operate on a flat namespace: initramfs files (read-only, searched first), then the store; `store/NAME` forces the store; writes create/replace store files atomically at close/exit; `upd.*` is not writable. Errors: ENOENT (missing, or no capability for that space), EACCES (write not permitted / reserved name), EMFILE (64 open files), EFBIG (> 4 MiB).

## Permissions (syscall 37, capability kind 18)
`perm(h, op, a2, a3, a4)` with a `Policy` capability: op 0 list (a2 = index, a4 = 64-byte out record: name[40], hash[16], flags@56 (1 R, 2 W), once@57), op 1 set (a2/a3 = program file name, a4 = flags: bit0 R, bit1 W, bit8 once), op 2 revoke (a2/a3 = name), op 3 set network rule (a2/a3 = program file name, a4 = pointer to a 16-byte struct { ip[4], port u16, allow u8, flags u8 (bit0 any host, bit1 internet only), secs u32, kib u32 }; secs/kib 0 = unlimited). READ for list, WRITE for set/revoke. list record is 80 bytes (flags@56, once@57, kind@58 = 1 for network rules, ip@60, port u16 @64, flags@66, secs u32 @68, kib u32 @72). `proc_list` (28) record: pid u64, threads u32, abi u8, exited u8, name[40] at 16, memory KiB u32 at 56.
