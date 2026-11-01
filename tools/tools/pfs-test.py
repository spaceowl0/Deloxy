#!/usr/bin/env python3
"""Persistent hierarchical filesystem, Windows DLL loading and CPU-fault signals, end to end on the real kernel:
two QEMU boots sharing one raw disk.
  boot 1: format, run the Linux test program `linux_pfs.elf w` (mkdir/create/append/truncate/chmod/symlink/rename/rmdir/
          errno checks under /home and /store, a 1 MiB file), plus the native shell's folder commands
  boot 2: the same tree after a power cycle (`linux_pfs.elf r` verifies content, modes, links, then deletes it all);
          df must show an empty directory tree afterwards
usage: tools/pfs-test.py <iso> <outdir>      (exit status 0 = pass)"""
import os, re, subprocess, sys, threading, time

ISO, OUT = sys.argv[1], sys.argv[2]
os.makedirs(OUT, exist_ok=True)
DISK = os.path.join(OUT, "pfs-disk.img")
with open(DISK, "wb") as f:
    f.truncate(64 * 1024 * 1024)
results = []
def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + ((" (%s)" % detail) if detail else ""), flush=True)

class Boot:
    def __init__(self, tag):
        self.tag = tag
        cmd = ["qemu-system-x86_64", "-M", "q35", "-m", "256M", "-cdrom", ISO, "-display", "none", "-no-reboot", "-serial", "stdio", "-monitor", "none",
               "-drive", "file=%s,if=none,id=d0,format=raw" % DISK, "-device", "virtio-blk-pci,drive=d0"]
        self.q = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.buf = bytearray(); self.lock = threading.Lock(); self.mark = 0
        threading.Thread(target=self._reader, daemon=True).start()
        if self.expect("deloxy-sh> ", 60) is None:
            check("%s: shell prompt" % tag, False, self.text()[-300:]); raise SystemExit(1)
    def _reader(self):
        while True:
            b = self.q.stdout.read(1)
            if not b: return
            with self.lock: self.buf.extend(b)
    def text(self):
        with self.lock: return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", self.buf.decode("latin1"))
    def expect(self, needle, timeout=30):
        t0 = time.time()
        while time.time() - t0 < timeout:
            t = self.text(); i = t.find(needle, self.mark)
            if i >= 0:
                seg = t[self.mark:i + len(needle)]; self.mark = i + len(needle); return seg
            if self.q.poll() is not None: break
            time.sleep(0.05)
        return None
    def send(self, s): self.q.stdin.write(s.encode()); self.q.stdin.flush()
    def run(self, line, want, name=None, timeout=60, absent=()):
        self.send(line + "\r")
        seg = self.expect("deloxy-sh> ", timeout)
        ok = seg is not None and all(w in seg for w in want) and not any(a in seg for a in absent)
        check("%s: %s" % (self.tag, name or line), ok, "" if ok else repr((seg or self.text()[-400:])[-700:]))
        return seg or ""
    def poweroff(self):
        self.send("poweroff\r")
        try: self.q.wait(timeout=30)
        except subprocess.TimeoutExpired: self.q.kill()

b = Boot("boot1")
b.send("format\r"); b.expect("> ", 10); b.send("yes\r"); b.expect("deloxy-sh> ", 20)
b.run("perms allow linux_pfs.elf rw", [], "grant linux_pfs.elf read/write store access", 20)
seg = b.run("run linux_pfs.elf w", ["PFS-W OK"], "Linux program: full POSIX tour of the persistent tree", 240, absent=("FAIL ",))
for line in seg.splitlines():
    if line.startswith("FAIL "): print("   ", line)
b.run("run dllapp.exe", ["DLL-TEST OK"], "Windows: static + dynamic DLL loading (imports, forwarders, ordinals, DllMain, reload)", 120, absent=("FAIL ",))
b.run("run linux_crash.elf", ["CRASH-TEST OK"], "Linux: SIGSEGV/SIGFPE/SIGILL handlers, sigaltstack, default actions via waitpid", 120, absent=("FAIL ",))
b.run("perms allow win_pfs.exe rw", [], "grant win_pfs.exe read/write store access", 20)
b.run("run win_pfs.exe", ["WIN-PFS OK"], "Windows: CreateDirectory/CreateFile/FindFirstFile/MoveFile/RemoveDirectory on C:\\srv", 120, absent=("FAIL ",))
b.run("tree /", ["home/", "user/", "docs/", "notes.txt", "rel-link", "big.bin"], "shell tree shows what the Linux program made")
b.run("stat /home/user/docs/notes.txt", ["file 755 size 10"], "shell stat: mode and size from the Linux program")
b.run("cat /srv/winw/a.txt", ["windows wrote this"], "shell reads what the Windows program wrote")
b.run("mkdir /opt", [], "shell mkdir")
b.run("save /opt/hello.txt from the shell", ["saved 14 bytes"], "shell save into a folder")
b.run("ln -s /opt/hello.txt /opt/alias", [], "shell ln -s")
b.run("cat /opt/alias", ["from the shell"], "shell cat through a symlink")
b.run("rm /home/user/docs", ["is a directory"], "rm refuses directories")
b.run("mkdir /upd.x", ["not permitted"], "kernel-owned names are protected from the shell too")
b.poweroff()

b = Boot("boot2")
seg = b.run("run linux_pfs.elf r", ["PFS-R OK"], "Linux program after reboot: contents, modes, links, 1 MiB pattern; then deletes it", 240, absent=("FAIL ",))
for line in seg.splitlines():
    if line.startswith("FAIL "): print("   ", line)
b.run("cat /opt/alias", ["from the shell"], "shell-made folder and symlink survived the reboot")
b.run("cat /srv/winw/a.txt", ["windows wrote this"], "Windows-made folder and file survived the reboot")
b.run("df", ["3 dir(s)", "4 file(s)"], "df: /opt, /srv, /srv/winw and their files, plus perms.db")
b.run("ls /", ["opt/", "srv/"], "root listing of the store")
b.poweroff()
n = sum(results); print("\n%d/%d checks passed" % (n, len(results)))
sys.exit(0 if n == len(results) else 1)
