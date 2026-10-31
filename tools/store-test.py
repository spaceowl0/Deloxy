#!/usr/bin/env python3
"""End-to-end persistence test on the REAL (non-selftest) kernel: three QEMU boots sharing one raw disk image.
  boot 1: blank disk -> 'unformatted' behaviour, explicit format (with confirmation), save/cp/rm/df, persisted update staging
  boot 2: everything survived a power-off; reserved `upd.*` names are protected; persisted rollback floor rejects the
          already-staged version after reboot; a program stored on disk still runs
  boot 3: a bit flipped on the raw disk inside a stored file is detected (checksum), not silently returned
usage: tools/store-test.py <iso> <outdir> [--uefi <OVMF.fd>]      (exit status 0 = pass)"""
import importlib.util, os, re, struct, subprocess, sys, threading, time

ISO, OUT = sys.argv[1], sys.argv[2]
UEFI = sys.argv[sys.argv.index("--uefi") + 1] if "--uefi" in sys.argv else None
os.makedirs(OUT, exist_ok=True)
DISK = os.path.join(OUT, "disk.img")
with open(DISK, "wb") as f:
    f.truncate(16 * 1024 * 1024)
here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("srv", os.path.join(here, "mock-update-server.py"))
srv = importlib.util.module_from_spec(spec); spec.loader.exec_module(srv)
srv.serve(8777)

results = []
def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + ((" (%s)" % detail) if detail else ""), flush=True)

class Boot:
    def __init__(self, tag):
        self.tag = tag
        cmd = ["qemu-system-x86_64", "-M", "q35", "-m", "256M", "-cdrom", ISO, "-display", "none", "-no-reboot", "-serial", "stdio", "-monitor", "none",
               "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
               "-drive", "file=%s,if=none,id=d0,format=raw" % DISK, "-device", "virtio-blk-pci,drive=d0"]
        if UEFI:
            cmd += ["-bios", UEFI]
        self.q = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.buf = bytearray(); self.lock = threading.Lock(); self.mark = 0
        threading.Thread(target=self._reader, daemon=True).start()
        if self.expect("deloxy-sh> ", 40) is None:
            check("%s: shell prompt" % tag, False, self.text()[-300:])
            raise SystemExit(1)
    def _reader(self):
        while True:
            b = self.q.stdout.read(1)
            if not b:
                return
            with self.lock:
                self.buf.extend(b)
    def text(self):
        with self.lock:
            return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", self.buf.decode("latin1"))
    def expect(self, needle, timeout=30):
        t0 = time.time()
        while time.time() - t0 < timeout:
            t = self.text(); i = t.find(needle, self.mark)
            if i >= 0:
                seg = t[self.mark:i + len(needle)]; self.mark = i + len(needle)
                return seg
            if self.q.poll() is not None:
                break
            time.sleep(0.05)
        return None
    def send(self, s):
        self.q.stdin.write(s.encode()); self.q.stdin.flush()
    def run(self, line, want, name=None, timeout=30, absent=()):
        self.send(line + "\r")
        seg = self.expect("deloxy-sh> ", timeout)
        ok = seg is not None and all(w in seg for w in want) and not any(a in seg for a in absent)
        check("%s: %s" % (self.tag, name or line), ok, "" if ok else repr((seg or self.text()[-300:])[-300:]))
        return seg or ""
    def wait_text(self, sub, timeout=8):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if sub in self.text():
                return True
            time.sleep(0.1)
        return False
    def boot_log_has(self, s):
        return s in self.text()
    def poweroff(self):
        self.send("poweroff\r")
        try:
            rc = self.q.wait(timeout=20)
        except subprocess.TimeoutExpired:
            rc = None
        check("%s: poweroff terminates the VM" % self.tag, rc is not None, "rc=%s" % rc)
        if self.q.poll() is None:
            self.q.kill()
        open(os.path.join(OUT, "%s.log" % self.tag), "w").write(self.text())

# ------------------------------------------------------------------ boot 1: blank disk
b = Boot("boot1")
check("boot1: blank disk is detected but NOT auto-formatted", b.boot_log_has("disk has no DeloxyStore"))
b.run("df", ["no store disk"], "df on an unformatted disk says so")
b.run("save a.txt x", ["no store disk"], "writing before format is refused")
b.send("format\r"); seg = b.expect("> ", 10) or ""
check("boot1: format asks for confirmation", "ERASES" in seg)
b.send("no\r"); seg = b.expect("deloxy-sh> ", 10) or ""
check("boot1: answering 'no' cancels and writes nothing", "cancelled" in seg)
b.run("df", ["no store disk"], "disk still blank after cancel")
b.send("format\r"); b.expect("> ", 10); b.send("yes\r"); seg = b.expect("deloxy-sh> ", 20) or ""
check("boot1: format with 'yes'", "store formatted" in seg, repr(seg[-100:]))
b.run("df", ["0 file(s)", "generation 1"], "fresh store is empty")
b.run("save notes.txt hello persistent world", ["saved 22 bytes"])
b.run("cp hello_linux.elf prog.elf", ["copied"], "copy an initramfs program into the store")
b.run("save tmp.txt scratch", ["saved"])
b.run("rm tmp.txt", ["removed tmp.txt"])
b.run("rm tmp.txt", ["not found"], "removing twice reports not found")
b.run("save bad/name x", ["not found"], "a path whose folder does not exist is refused (paths are hierarchical now)")
b.run("save bad:name x", ["invalid"], "names with illegal characters are rejected")
b.run("save upd.floor 9.9.9", ["reserved"], "user cannot forge the update floor")
b.run("perms net hello_win.exe any allow nolan time=30m data=2G", ["connections allowed"], "boot1: a full-access rule with custom limits")
b.run("perms net hello_linux.elf 10.0.2.2:8777 deny", ["connections denied"], "boot1: a denied destination rule")
b.run("ls", ["notes.txt", "prog.elf", "[store]"], "ls shows initramfs + store")
b.run("cat notes.txt", ["hello persistent world"])
b.run("run prog.elf", ["Hello from Linux ELF", "[exit 0]"], "run a program from the store")
b.send("upd stage 10.0.2.2 8777 /ok\r"); b.expect("Allow? [y/N] ", 15); b.send("y\r")
seg = b.expect("deloxy-sh> ", 60) or ""
check("boot1: upd stage saves the verified update to disk", "upd: OK: staged 0.1.1 in RAM and saved to the store" in seg, repr(seg[-200:]))
b.run("ls", ["upd.pending", "upd.floor", "upd.0.1.1.deloxy-core.bin"], "persisted update files are listed")
b.run("cat upd.floor", ["0.1.1"], "rollback floor file")
b.poweroff()

# ------------------------------------------------------------------ boot 2: power cycle
b = Boot("boot2")
check("boot2: store mounted from disk", b.boot_log_has("store: mounted, generation"))
check("boot2: persisted update re-verified at boot", b.boot_log_has("pending update 0.1.1 verified on disk"))
check("boot2: rollback floor loaded at boot", b.boot_log_has("persistent rollback floor 0.1.1"))
b.run("perms", ["hello_win.exe", "net ANY HOST (internet only) limit: 1800 s, 2097152 KiB ALLOWED", "hello_linux.elf", "net 10.0.2.2:8777", "DENIED"], "boot2: network rules (scope, limits, decision) survived the power cycle")
b.run("cat notes.txt", ["hello persistent world"], "file survived power-off")
b.run("ls", ["prog.elf", "upd.0.1.1.initramfs.tar"], "all files present after reboot", absent=["tmp.txt"])
b.run("run prog.elf", ["Hello from Linux ELF", "[exit 0]"], "stored program still runs after reboot")
b.run("rm upd.pending", ["reserved"], "user cannot delete the update record")
b.send("upd check 10.0.2.2 8777 /ok\r"); b.expect("Allow? [y/N] ", 15); b.send("y\r")
seg = b.expect("deloxy-sh> ", 60) or ""
check("boot2: persisted floor rejects the already-staged version after reboot (code 10 NotNewer)", "REJECTED (code 10)" in seg and "NotNewer" in seg, repr(seg[-200:]))
b.run("save notes.txt second boot edit", ["saved"], "replace a file")
b.run("df", ["generation"], "df")
b.run("save de.conf theme=light accent=orange taskbar=top corners=square", ["saved"], "customise the desktop from the shell (de.conf)")
check("boot2: desktop hot-reloads de.conf", b.wait_text("[deloxy-de] theme: theme=light accent=orange wallpaper=midnight taskbar=top corners=square clock=24"), b.text()[-200:])
b.poweroff()

# ------------------------------------------------------------------ boot 3: bit rot on the raw disk
raw = bytearray(open(DISK, "rb").read())
# locate the stored copy of the ELF by its magic after the data start (sector 65) and flip one byte of its payload
data_start = 65 * 512
pos = raw.find(b"\x7fELF", data_start)
if pos < 0:
    check("boot3: found prog.elf on the raw disk", False)
else:
    raw[pos + 100] ^= 0xFF
    open(DISK, "wb").write(raw)
b = Boot("boot3")
check("boot3: customised theme restored from the store at boot", b.wait_text("[deloxy-de] theme: theme=light accent=orange wallpaper=midnight taskbar=top corners=square clock=24"), b.text()[-200:])
b.run("cat notes.txt", ["second boot edit"], "intact files still readable")
b.run("cat prog.elf", ["I/O error or checksum mismatch"], "flipped bit detected, corrupt data is not returned")
b.run("run prog.elf", ["checksum mismatch"], "corrupt program is not executed", absent=["Hello from Linux ELF"])
b.poweroff()

n = sum(results)
print("\n%d/%d checks passed" % (n, len(results)))
sys.exit(0 if n == len(results) else 1)
