#!/usr/bin/env python3
"""CPython 3.12 + `file` on Deloxy (needs the FULL iso from tools/mkfull-iso.sh): the standard-library workout must print
exactly what host Python prints, and `file` must classify files like the native tool.  usage: py-test.py <full.iso>"""
import os, subprocess, sys, time, threading, re
iso = sys.argv[1]; here = os.path.dirname(os.path.abspath(__file__)); root = os.path.join(here, "..")
expected = open(os.path.join(root, "user", "rootfs-test", "usr", "share", "test", "pytest1.expected")).read().strip().split("\n")
q = subprocess.Popen(["qemu-system-x86_64", "-M", "q35", "-m", "768M", "-cdrom", iso, "-display", "none", "-no-reboot", "-serial", "stdio", "-vga", "std"],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
buf = b""
def reader():
    global buf
    while True:
        c = os.read(q.stdout.fileno(), 65536)
        if not c: break
        buf += c
threading.Thread(target=reader, daemon=True).start()
def text(): return buf.decode(errors="replace").replace("\r", "")
def wait(n, t):
    t0 = time.time()
    while time.time() - t0 < t:
        if text().count("deloxy-sh> ") >= n: return True
        time.sleep(0.1)
    return False
def send(s): q.stdin.write((s + "\r").encode()); q.stdin.flush()
results = []
def check(name, ok, detail=""):
    results.append(bool(ok)); print(("PASS " if ok else "FAIL ") + name + ("" if ok else " (%s)" % detail)); sys.stdout.flush()
n = 1
if not wait(1, 90): print("no shell"); sys.exit(2)
def run(cmd, timeout=120):
    global n
    start = len(buf); send(cmd); n += 1; ok = wait(n, timeout)
    got = buf[start:].decode(errors="replace").replace("\r", "")
    lines = [l for l in got.split("\n")[1:] if not re.match(r"^\x1b\[|\[(INFO|WARN|DEBUG|ERROR) *\]|\[user pid|deloxy-sh>|\[exit", l) and l.strip() != ""]
    return ok, lines
for prog in ("python3", "file"):
    send("perms allow %s rw" % prog); n += 1; wait(n, 15)
ok, lines = run("run python3 -c print(6*7)")
check("python: -c print(6*7)", ok and lines == ["42"], lines)
ok, lines = run("run python3 /usr/share/test/pytest1.py", 240)
check("python: the standard-library workout prints exactly what host Python prints (%d lines)" % len(expected), ok and lines == expected, [(a, b) for a, b in zip(lines, expected) if a != b][:3] or lines[-3:])
ok, lines = run("run python3 -c import-fail")
check("python: a SyntaxError-free but failing program reports an error and exits non-zero", ok and any("Error" in l for l in lines), lines)
for path, host in (("/usr/share/test/hello.txt", "/usr/share/test/hello.txt"), ("/bin/python3", "/bin/python3"), ("/usr/lib/python3.12/os.py", "/usr/lib/python3.12/os.py")):
    ok, lines = run("run file " + path)
    exp = subprocess.run(["file", "-L", host], capture_output=True, text=True).stdout.strip()
    check("file: %s classified like the native tool" % path, ok and lines == [exp], (lines, exp))
try: send("poweroff")
except Exception: pass
time.sleep(1); q.kill()
print("\n%d/%d checks passed" % (sum(results), len(results))); sys.exit(0 if all(results) else 1)
