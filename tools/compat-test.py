#!/usr/bin/env python3
"""deloxy-wltd end-to-end: real compiler output (static glibc ELF, mingw PE) running on the REAL kernel, with a disk.
usage: tools/compat-test.py <iso> <outdir> [--uefi <OVMF.fd>]      (exit status 0 = pass)"""
import os, re, subprocess, sys, threading, time

ISO, OUT = sys.argv[1], sys.argv[2]
UEFI = sys.argv[sys.argv.index("--uefi") + 1] if "--uefi" in sys.argv else None
os.makedirs(OUT, exist_ok=True)
DISK = os.path.join(OUT, "disk.img")
with open(DISK, "wb") as f:
    f.truncate(16 * 1024 * 1024)
import importlib.util
_spec = importlib.util.spec_from_file_location("srv", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mock-update-server.py"))
_srv = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_srv)
_srv.serve(8777)
results = []
def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + ((" (%s)" % detail) if detail else ""), flush=True)

cmd = ["qemu-system-x86_64", "-M", "q35", "-m", "256M", "-cdrom", ISO, "-display", "none", "-no-reboot", "-serial", "stdio", "-monitor", "none",
       "-drive", "file=%s,if=none,id=d0,format=raw" % DISK, "-device", "virtio-blk-pci,drive=d0",
       "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0"]
if UEFI:
    cmd += ["-bios", UEFI]
q = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
buf = bytearray(); lock = threading.Lock(); mark = [0]
def reader():
    while True:
        b = q.stdout.read(1)
        if not b: return
        with lock: buf.extend(b)
threading.Thread(target=reader, daemon=True).start()
def text():
    with lock: return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", buf.decode("latin1"))
def expect(needle, timeout=30):
    t0 = time.time()
    while time.time() - t0 < timeout:
        t = text(); i = t.find(needle, mark[0])
        if i >= 0:
            seg = t[mark[0]:i + len(needle)]; mark[0] = i + len(needle); return seg
        if q.poll() is not None: break
        time.sleep(0.05)
    return None
def send(s): q.stdin.write(s.encode()); q.stdin.flush()
def run(line, want, name=None, timeout=40, absent=()):
    send(line + "\r")
    seg = expect("deloxy-sh> ", timeout)
    ok = seg is not None and all(w in seg for w in want) and not any(a in seg for a in absent)
    check(name or line, ok, "" if ok else repr((seg or text()[-400:])[-500:]))
    return seg or ""

if expect("deloxy-sh> ", 40) is None:
    check("shell prompt", False, text()[-300:]); sys.exit(1)
send("format\r"); expect("> ", 10); send("yes\r"); expect("deloxy-sh> ", 20)
for prog in ("linux_glibc.elf", "win_msvcrt.exe", "linux_stdin.elf", "win_k32.exe", "linux_threads.elf", "win_threads.exe", "win_sync.exe"):
    send("perms allow %s rw\r" % prog); expect("deloxy-sh> ", 10)

# ---------------- Linux (static glibc, compiled with gcc -static)
run("run linux_glibc.elf", ["glibc hello: argc=1", "1 2 3 5 7 9", "malloc len=99999", "read 40 bytes: Deloxy initramfs (", "size=", "wrote lin-out.txt", "clock ok=1", "[exit 3]"],
    "Linux: static glibc program (printf, qsort, malloc, fopen/fread/fseek, fopen-write, clock_gettime)", absent=["unimplemented", "failed"])
run("cat lin-out.txt", ["written by a Linux program"], "Linux: file written by the program is persisted in the store")
run("df", ["2 file(s)"], "Linux: store has the new file (+ perms.db)")

# ---------------- Windows (mingw-w64, msvcrt.dll imports)
run("run win_msvcrt.exe", ["msvcrt hello: argc=1", "heap works", "fmt: 42 str ff  3.14 Z", "read: Deloxy initramfs (", "[exit 7]"],
    "Windows: mingw C program (msvcrt printf/puts/malloc/fopen/fread)", absent=["cannot start", "failed"])

def run_input(line, prompt, answer, want, name, timeout=40, absent=()):
    send(line + "\r")
    seg = expect(prompt, timeout)
    ok = seg is not None
    if ok:
        send(answer + "\r")
        seg = expect("deloxy-sh> ", timeout)
        ok = seg is not None and all(w in seg for w in want) and not any(a in seg for a in absent)
    check(name, ok, "" if ok else repr((seg or text()[-400:])[-600:]))

# ---------------- v3: interactive stdin, directories, mmap (Linux) and Win32 file API, scanf, qsort, atexit (Windows)
run_input("run linux_stdin.elf", "name? ", "Ada", ["hello, Ada!", "dir: entries>=3=1 readme=1", "mmap: Deloxy ", "len=90", "unlink=0", "[exit 0]"],
          "Linux: interactive stdin (cooked line input), opendir/readdir, mmap of a file, unlink", absent=["mmap failed"])
run_input("run win_k32.exe", "name age? ", "Bob 42", ["scanned 2: Bob (42)", "read back 6: abc123 size=6", "txt files>=2: 1", "strtol=31", "atexit ran", "[exit 5]"],
          "Windows: qsort (user-mode stub), scanf from stdin, CreateFile/ReadFile/WriteFile/FindFirstFile, strtol, atexit at exit", absent=["cannot start", "failed"])
check("Windows: qsort stub (user-mode comparator callbacks) sorted the array", "1 2 4 5 7 8 9 " in text())
run("cat win-out.txt", ["abc123"], "Windows: file written through CreateFile/WriteFile is in the store")

# ---------------- v4: threads
run("run linux_threads.elf", ["counter=40000 sum=1100", "condvar ok=7 main tls=0", "pipe: poll=1 16 bytes: through the pipe", "[exit 0]"],
    "Linux: pthreads (clone/futex): 4 threads + mutex, join values, thread-local storage, condvar, pipe + poll between threads", timeout=90)

run("run win_threads.exe", ["shared=15000 counter=15000 sum=702 main tls=5", "event wait=0", "semaphore wait=0", "semaphore again=0", "semaphore empty=258", "beginthreadex code=77", "[exit 0]"],
    "Windows: CreateThread/_beginthreadex, critical section, Interlocked*, events, semaphores, mutex, WaitForMultipleObjects, per-thread TLS (TlsAlloc and __declspec(thread))", timeout=90)

# ---------------- v5: application permissions (kernel-enforced, asked on first file access)
run("cp linux_glibc.elf g2.elf", ["copied"], "perm: a program copied under a new name has no stored decision")
run("save perms.db hacked", ["reserved"], "perm: perms.db is kernel-owned (programs and the shell cannot overwrite it)")
send("run g2.elf\r"); seg = expect("[d]eny always: ", 40)
check("perm: first file access prompts the user", seg is not None and "g2.elf wants to use files" in seg and "glibc hello" in seg, repr((seg or text()[-300:])[-300:]))
send("n"); seg = expect("deloxy-sh> ", 40) or ""
check("perm: 'no' runs the program without file access", "fopen README.txt failed" in seg and "fopen write failed" in seg and "[exit 3]" in seg, repr(seg[-300:]))
run("perms", ["linux_glibc.elf"], "perm: a one-time 'no' is not stored", absent=["g2.elf"])
send("run g2.elf\r"); expect("[d]eny always: ", 40); send("a"); seg = expect("deloxy-sh> ", 40) or ""
check("perm: 'always' allows file access", "read 40 bytes: Deloxy initramfs (" in seg and "wrote lin-out.txt" in seg, repr(seg[-300:]))
run("perms", ["g2.elf", "read write"], "perm: the decision is listed")
run("run g2.elf", ["read 40 bytes: Deloxy"], "perm: a stored decision does not prompt again", absent=["wants to use files"])
run("perms revoke g2.elf", ["revoked"], "perm: revoke")
send("run g2.elf\r"); expect("[d]eny always: ", 40); send("d"); seg = expect("deloxy-sh> ", 40) or ""
check("perm: 'deny always' is enforced", "fopen README.txt failed" in seg, repr(seg[-200:]))
run("perms", ["g2.elf", "DENIED"], "perm: denial is stored")
run("run g2.elf", ["fopen README.txt failed"], "perm: stored denial does not prompt", absent=["wants to use files"])
run("perms allow g2.elf r", ["file access set to r"], "perm: allow read-only from the shell")
run("run g2.elf", ["read 40 bytes: Deloxy", "fopen write failed"], "perm: read-only grant lets the program read but not write", absent=["wrote lin-out.txt"])
run("cp win_msvcrt.exe g2.elf", ["copied"], "perm: replace the binary under the same name")
send("run g2.elf\r"); seg = expect("[d]eny always: ", 40)
check("perm: a modified binary (different hash) is asked again", seg is not None and "g2.elf wants to use files" in seg)
send("n"); expect("deloxy-sh> ", 40)

run("run win_sync.exe", ["consumer sum=210 hits=21 timeout ok=0 err=1460", "[exit 0]"], "Windows: SRW locks (exclusive/shared) and condition variables (CS-based wait/wake and timeout)", timeout=90)

# ---------------- v6: sockets with per-destination network permissions
run("perms net win_net.exe 10.0.2.2:8777 allow", ["allowed"], "net perm: allow a destination from the shell")
run("run win_net.exe", ["winsock status: HTTP/1.0 404"], "Windows: Winsock (WSAStartup/socket/connect/send/recv) over the kernel TCP stack", timeout=90)
run("perms", ["win_net.exe", "net 10.0.2.2:8777", "ALLOWED"], "net perm: the rule is listed (with its default limits)")
send("run linux_net.elf\r"); seg = expect("[d]eny always: ", 60)
check("net perm: connect asks, naming the destination", seg is not None and "linux_net.elf wants to connect to 10.0.2.2:8777" in seg, repr((seg or text()[-300:])[-300:]))
send("n"); seg = expect("deloxy-sh> ", 40) or ""
check("net perm: 'no' makes connect() fail with EACCES (13)", "connect failed: errno=13" in seg, repr(seg[-200:]))
send("run linux_net.elf\r"); expect("[d]eny always: ", 60); send("a"); seg = expect("deloxy-sh> ", 90) or ""
check("Linux: socket/connect/send/read over the kernel TCP stack after 'always'", "status: HTTP/1.0 404" in seg, repr(seg[-300:]))
run("run linux_net.elf", ["status: HTTP/1.0 404"], "net perm: a stored decision does not prompt again", absent=["wants to connect"], timeout=90)
run("perms revoke linux_net.elf", ["revoked"], "net perm: revoke")
send("run linux_net.elf\r"); expect("[d]eny always: ", 60); send("d"); seg = expect("deloxy-sh> ", 40) or ""
check("net perm: 'deny always' is enforced", "connect failed: errno=13" in seg, repr(seg[-200:]))
run("run linux_net.elf", ["connect failed: errno=13"], "net perm: a stored denial does not prompt", absent=["wants to connect"])

# ---------------- v7: full access ("regular connection"), custom limits, internet-only
run("perms revoke linux_net.elf", ["revoked"], "full access: start clean (an exact deny rule would beat an any-host rule)")
run("perms net linux_net.elf any allow", ["connections allowed to any", "no time limit", "no data limit"], "full access: any host, no time or data limit, set from the shell")
run("perms", ["linux_net.elf", "net ANY HOST no limits ALLOWED"], "full access: listed as ANY HOST / no limits")
run("run linux_net.elf", ["status: HTTP/1.0 404"], "full access: connects without any prompt", absent=["wants to connect"], timeout=90)
run("run linux_net.elf 1", ["connect failed: errno=111"], "full access: ANY destination is reachable (another port gets a real ECONNREFUSED, not a permission error)", absent=["wants to connect"], timeout=90)
run("perms net linux_net.elf any allow nolan time=30m data=2G", ["time limited", "data capped"], "limits: internet-only + 30 minute time limit + 2 GiB data cap")
run("perms", ["linux_net.elf", "net ANY HOST (internet only) limit: 1800 s, 2097152 KiB ALLOWED"], "limits: the custom limits are stored and listed")
run("run linux_net.elf", ["connect failed: errno=13"], "limits: internet-only blocks the private LAN address (EACCES) without prompting", absent=["wants to connect"], timeout=90)
run("perms net linux_net.elf 10.0.2.2:8777 allow", ["connections allowed"], "limits: an exact destination rule overrides the any-host rule")
run("run linux_net.elf", ["status: HTTP/1.0 404"], "limits: the exact rule wins over the internet-only any-host rule", absent=["wants to connect"], timeout=90)
run("perms revoke linux_net.elf", ["revoked"])
run("cp linux_net.elf n2.elf", ["copied"], "full access: a fresh program copy for the prompt path")
send("run n2.elf\r"); seg = expect("[d]eny always: ", 60)
check("full access: the prompt offers [f]ull access (any host, no limits)", seg is not None and "[f]ull access (any host, no limits)" in seg, repr((seg or text()[-300:])[-300:]))
send("f"); seg = expect("deloxy-sh> ", 90) or ""
check("full access: choosing 'f' connects and stores an any-host rule", "status: HTTP/1.0 404" in seg, repr(seg[-300:]))
run("perms", ["n2.elf", "net ANY HOST no limits ALLOWED"], "full access: the prompt choice is stored as ANY HOST / no limits")
run("run n2.elf 1", ["connect failed: errno=111"], "full access: no prompt for a different destination afterwards", absent=["wants to connect"], timeout=90)

# ---------------- v5: resource limits
seg = run("run linux_memhog.elf", ["memory limit reached after", "[exit 0]"], "limits: a runaway allocator is stopped cleanly (ENOMEM), not the kernel")
import re as _re
m = _re.search(r"reached after (\d+) MiB", seg)
check("limits: foreign programs are capped near 128 MiB", m is not None and 100 <= int(m.group(1)) <= 128, m.group(0) if m else "no number")
run("ps", ["KiB]"], "limits: ps shows per-process memory")


# ---- Windows compatibility v2: real heap, GetProcAddress, FLS, SList, wide APIs, time, system info
send("perms allow win_compat2.exe rw\r"); expect("deloxy-sh> ", 10)
run("run win_compat2.exe", ["heap: 800000000 bytes churned OK", "realloc: grow", "calloc: zeroed=1"], "wltd: free() really recycles memory (800 MB churned through 4 KB blocks) and realloc/calloc work", timeout=120)
run("run win_compat2.exe", ["getprocaddress: ok", "getprocaddress missing: null"], "wltd: GetProcAddress resolves real APIs and returns NULL for unknown ones", timeout=120)
run("run win_compat2.exe", ["fls: 0000000000001234", "encode: 0000000000005678", "slist: pop order ok"], "wltd: FLS, EncodePointer, SList (MSVC runtime startup APIs)", timeout=120)
run("run win_compat2.exe", ["cmdlineW: 1", "wcs: cmp=1 len=11 chr=1", "sysinfo: page=4096 cpus=1", "localalloc: ok"], "wltd: wide-character APIs, GetSystemInfo, LocalAlloc", timeout=120)
run("run win_compat2.exe", ["itoa: -12345 ff", "strtok: a b c", "time: 1971-01-01 01:01:01", "mktime: 31539661", "feature: sse2=1", "done"], "wltd: itoa, strtok, gmtime/strftime/mktime, IsProcessorFeaturePresent", timeout=120)

# ---- Linux compatibility v2: eventfd/epoll, blocking pipes, readv, F_DUPFD, statfs
send("perms allow linux_misc.elf rw\r"); expect("deloxy-sh> ", 10)
run("run linux_misc.elf", ["eventfd: epoll=1 data=7 sum=6", "eventfd: empty read -> EAGAIN"], "linux: eventfd counter + epoll readiness + EAGAIN", timeout=120)
run("run linux_misc.elf", ["pipe: blocking read got 9 'late-data'", "pipe: nonblocking empty -> EAGAIN", "pipe: closed writer -> EOF=1"], "linux: empty pipe blocks until a writer thread writes; O_NONBLOCK and EOF semantics", timeout=120)
run("run linux_misc.elf", ["readv: 7 'ab' 'cdefg'", "F_DUPFD: ok", "statfs: ok", "done"], "linux: readv, F_DUPFD, statfs", timeout=120)

# ---- entropy: CSPRNG behind getrandom, /dev/urandom and the Windows RNG APIs
send("perms allow linux_rand.elf rw\r"); expect("deloxy-sh> ", 10)
send("perms allow win_rand.exe rw\r"); expect("deloxy-sh> ", 10)
run("run linux_rand.elf", ["sizes: 65536 65536", "getrandom: ones=0.", "urandom: ones=0.", "differ: yes"], "entropy: getrandom and /dev/urandom pass bit-balance, chi-square and repeat checks", timeout=120, absent=["BAD"])
run("run win_rand.exe", ["bcrypt=0 rtlgenrandom=1 rand_s=0 balance=ok differ=yes"], "entropy: BCryptGenRandom, RtlGenRandom and rand_s work", timeout=120)

# ---- Windows floating point: every line must equal what the same program prints natively (glibc)
send("perms allow win_math.exe rw\r"); expect("deloxy-sh> ", 10)
_exp = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "user", "poc", "win_math.expected")).read().strip().split("\n")
run("run win_math.exe", _exp[:8], "wltd float: libm results (sin/cos/exp/log/pow/atan2/floor/fmod/f32) match native glibc", timeout=120)
run("run win_math.exe", _exp[8:13], "wltd float: printf %f %e %g with width/precision/flags matches native", timeout=120)
run("run win_math.exe", _exp[13:], "wltd float: strtod/atof/sscanf and GetProcAddress'd math through the float trampolines match native", timeout=120)

# ---- dynamic linking: PT_INTERP programs run through the real ld.so + glibc/libstdc++ shipped in the image
send("perms allow dyn_hello.elf rw\r"); expect("deloxy-sh> ", 10)
send("perms allow dyn_cpp.elf rw\r"); expect("deloxy-sh> ", 10)
run("run dyn_hello.elf", ["dyn: dynamic linking works", "sqrt2=1.414214", "[exit 0]"], "dynlink: a dynamically linked glibc program (libc.so.6 + libm.so.6 via ld.so) runs", timeout=120)
run("run dyn_cpp.elf", ["cpp: sorted 1 3 5 7 9 map=5 k9=81", "cpp: caught boom", "cpp: threads total=6000", "cpp: slept 1"], "dynlink: dynamic C++ (libstdc++): STL, exceptions, std::thread/mutex, chrono", timeout=120)

# ---- process model: fork / wait4 / pipes / execve / posix_spawn / popen / kill (plain static glibc)
for _n in ("linux_fork.elf", "dyn_hello.elf", "sh"):
    send("perms allow %s rw\r" % _n); expect("deloxy-sh> ", 10)
seg = run("run linux_fork.elf", ["fork: child=1 reaped=1 exit=7 parent_x=5", "pipe: got 10 'from-child'"], "proc: fork copies memory (child writes are private), wait4 returns the exit status, pipes work between processes", timeout=150)
run("run linux_fork.elf", ["dyn: dynamic linking works", "argc=3", "exec-missing: child exit=42"], "proc: fork+execve runs another image (argv passed), a missing program fails with ENOENT in the child", timeout=150)
run("run linux_fork.elf", ["from-system", "system: rc=0", "popen: 'from-popen'", "many: sum=60"], "proc: system() and popen() (posix_spawn of /bin/sh with a redirected stdout), five children reaped", timeout=150)
run("run linux_fork.elf", ["kill: wnohang=0 signaled=1 sig=9", "echild: -1 ECHILD", "[exit 0]"], "proc: WNOHANG, kill(SIGKILL) reported as a signal death, ECHILD with no children", timeout=150)

# ---- signals and timers
send("perms allow linux_sig.elf rw\r"); expect("deloxy-sh> ", 10)
run("run linux_sig.elf", ["handler: usr1=1 signo=10 info=10", "mask: blocked_pending=1 delivered_while_blocked=0 after_unblock=1"], "signals: handlers (SA_SIGINFO), raise/kill, sigprocmask blocks and unblocks delivery", timeout=150)
run("run linux_sig.elf", ["alarm: pause=-1 errno=EINTR alrm=1", "itimer: ticks>=5 1", "restart: read=4 'late' interrupted_ticks=1 chld=1"], "signals: alarm+pause, periodic setitimer, SA_RESTART restarts a blocked read, SIGCHLD handler runs", timeout=150)
run("run linux_sig.elf", ["sigsuspend: ret=-1 errno=EINTR usr2=1", "sigpipe-ignored: write=-1 errno=EPIPE", "sigpipe-default: signaled=1 sig=13"], "signals: sigsuspend, SIGPIPE ignored (EPIPE) and fatal by default", timeout=150)
run("run linux_sig.elf", ["abort: signaled=1 sig=6", "term-busy-loop: sig=15", "sigtimedwait: got=1", "posix-timer: fired=1", "done"], "signals: SIGABRT, SIGTERM kills a busy loop, sigtimedwait, POSIX timers", timeout=150)

# ---- asynchronous signal delivery (handlers run while the program spins in user mode; registers survive)
run("run linux_async.elf", ["async-timer: handled=1 registers-intact=1", "async-kill: handled=1 registers-intact=1", "async-blocked: delivered_while_blocked=0 after_unblock=1", "async-repeat: handler_runs>=5 1", "done"], "signals: handled signals interrupt a user-mode spin loop (timer + kill from a child), rax/rcx/r11/xmm survive, blocked stays pending", timeout=150)

# ---- Windows exception dispatch (vectored handlers, CONTEXT editing, RaiseException, unhandled-exception filter)
run("run win_seh.exe", ["ud2: hits=1 regs=1 sse=1", "av: hits=1 write-info=1 retried-store=1", "div0: hits=1 quotient=10", "raise: hits=1 code=e0000001 n=2 info=aaaa,bbbb after-return-ok=1", "order: FL", "filter-continue: hits=1", "done"], "Windows: vectored exception handlers resume faults (#UD/#PF/#DE) via CONTEXT edits, RaiseException params, handler order, unhandled filter", timeout=120)
run("run win_seh.exe die", ["filter: dying", "[exit 3221225477]"], "Windows: filter returning EXECUTE_HANDLER ends the process with the exception code (0xC0000005)", timeout=120)

# ---- futex waits are interruptible; signal masks are per thread
run("run linux_futex.elf", ["untimed: ret=-1 errno=EINTR handled=1", "restart: ret=-1 errno=EAGAIN handled=1", "timed: ret=-1 errno=EINTR quick=1 handled=1", "timeout: ret=-1 errno=ETIMEDOUT", "wake: woke=1 thread_ok=1", "thread-signal: handler_ran=1 thread_ok=1", "done"], "futex: FUTEX_WAIT interrupted by signals (EINTR / SA_RESTART restart / timed), wake still works, a finished thread no longer blocks the process's signals", timeout=150)

# ---- thread-directed signals (tgkill / pthread_kill), per-thread masks
run("run linux_tsig.elf", ["futex-thread: handled=1 on_worker=1", "spin-thread: handled=1 on_worker=1", "self: handled=1 on_main=1", "blocked: early=0 late=1 on_worker=1", "process-signal: handled=100 on_worker=1", "checks: bad_tid=ESRCH sig0=0 bad_tgid=ESRCH", "done"], "signals: pthread_kill/tgkill reach exactly the named thread (futex wait, user-mode spin, blocked->unblocked), process signals go to a thread that accepts them", timeout=150)

# ---- blocking console reads are interruptible; a partly typed line survives SA_RESTART interruptions
send("run linux_tty.elf\r")
seg = expect("sig\r", 30)
ok0 = seg is not None
import time as _t
if ok0:
    send("A"); _t.sleep(0.25); send("d"); _t.sleep(0.25); send("a"); _t.sleep(0.25); send("\r")
seg = expect("deloxy-sh> ", 30) if ok0 else None
check("tty: console read interrupted by a signal (EINTR; SA_RESTART restarts, typed-so-far line survives)", seg is not None and "tty1: ret=-1 errno=EINTR handled=1" in text() and "tty2: got='Ada' interrupted_several_times=1" in text(), "" if seg is not None else repr(text()[-300:]))

# ---- process groups, sessions, job control; Ctrl-C reaches the foreground program
run("run linux_jobs.elf", ["ids: pgrp_is_pid=1 sid_is_pid=1 setsid_leader=EPERM", "child-group: own=1 same_as_parent=0", "group-setup: setpgid=0,0 pgids_equal=1", "group-kill: kill=0 reaped=2 by_sigterm=2 echild_after=yes", "wait-pgid0: got_child=1 status=7", "kill0: ret=0", "stop-cont: running_before=1 stopped=1 silent_while_stopped=1 continued=1 running_after=1", "tstp-spinner: stopped=1 sig=20", "spinner-killed: 1", "done"], "job control: setpgid/getpgid/setsid, kill(-pgrp), waitpid(-pgrp/0), SIGSTOP/SIGTSTP stop (also a user-mode spinner), SIGCONT, WUNTRACED/WCONTINUED", timeout=150)
send("run linux_jobs.elf spin\r")
seg = expect("spinning", 30)
if seg is not None:
    time.sleep(0.5); send("\x03")
seg2 = expect("deloxy-sh> ", 20) if seg is not None else None
check("console: Ctrl-C interrupts the running Linux program (^C echoed, program ends, shell prompt returns)", seg2 is not None and "^C" in seg2, repr((seg2 or text()[-300:])[-300:]))

# ---- filesystem: working directory, hierarchical read-only tree, symlinks, /tmp, *at() calls, error codes
send("perms allow linux_fs.elf rw\r"); expect("deloxy-sh> ", 10)
run("run linux_fs.elf", ["cwd0: /", "rootfs: read 34 'hello from the rootfs'", "symlink-file: 'hello'", "symlink-dir: 'deep file'", "readlink: 9 'hello.txt'", "usrmerge: 'libdata'"], "fs: read-only tree: files, directories, symlinks (file and directory), readlink, usr-merge aliases", timeout=150)
run("run linux_fs.elf", ["readdir: /usr/share/test has", "hello.txt=1, sub is dir=1", "root-listing: usr=1 tmp=1", "write-rootfs: EROFS"], "fs: readdir/getdents types, the root listing shows the tree and /tmp, the tree is read-only (EROFS)", timeout=150)
run("run linux_fs.elf", ["mkdir: 0 again=EEXIST nested-noparent=ENOENT", "chdir: 0 cwd=/tmp/d1 bad=ENOTDIR", "tmpfile: relative write -> absolute read 8 'tmp data'", "openat: 'tmp' fstatat=1"], "fs: /tmp mkdir/chdir/getcwd, relative paths against the working directory, openat/fstatat with a dirfd", timeout=150)
run("run linux_fs.elf", ["rename: 0 old-gone=1 new-ok=1 rmdir-nonempty=ENOTEMPTY", "unlink: 0 rmdir: 0 gone=1", "relative-rootfs: 'hello' dotdot=ok", "missing: ENOENT", "big: size=100000", "done"], "fs: rename/unlink/rmdir (ENOTEMPTY), '..' handling, ENOENT, 100 KB tmp file", timeout=150)
send("poweroff\r")
try: rc = q.wait(timeout=20)
except subprocess.TimeoutExpired: rc = None
check("poweroff terminates the VM", rc is not None)
if q.poll() is None: q.kill()
open(os.path.join(OUT, "compat.log"), "w").write(text())
n = sum(results); print("\n%d/%d checks passed" % (n, len(results)))
sys.exit(0 if n == len(results) else 1)
