#!/usr/bin/env python3
"""Measured Linux compatibility: run stock distribution tools (dynamically linked, from the host) inside Deloxy and compare
their output with the native output.  usage: corpus-test.py <corpus.iso> <host-data-dir> <tools.json>
Each tool is copied to the guest as u_<name>; its libraries ship in the image; data files live in <host-data-dir>."""
import json, os, subprocess, sys, time, re
iso, ddir, spec = sys.argv[1], sys.argv[2], sys.argv[3]
tools = json.load(open(spec))
import threading
def run_one(name, args, timeout=60, extra=()):
    q = subprocess.Popen(["qemu-system-x86_64", "-M", "q35", "-m", "768M", "-cdrom", iso, "-display", "none", "-no-reboot", "-serial", "stdio", "-vga", "std"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
    st = {"buf": b""}
    def reader():
        while True:
            try: c = os.read(q.stdout.fileno(), 65536)
            except Exception: break
            if not c: break
            st["buf"] += c
    threading.Thread(target=reader, daemon=True).start()
    def text(): return st["buf"].decode(errors="replace").replace("\r", "")
    def wait_prompt(n, t):
        t0 = time.time()
        while time.time() - t0 < t:
            if text().count("deloxy-sh> ") >= n: return True
            time.sleep(0.1)
        return False
    def send(x):
        q.stdin.write((x + "\r").encode()); q.stdin.flush()
    try:
        if not wait_prompt(1, 90): return False, "no shell", None
        prog = "u_" + name
        names = [prog] + list(extra)
        for k, nm in enumerate(names):
            send("perms allow %s rw" % nm); wait_prompt(2 + k, 15)
        start = len(st["buf"])
        send(("run %s %s" % (prog, args)).strip())
        okp = wait_prompt(2 + len(names), timeout)
        got = st["buf"][start:].decode(errors="replace").replace("\r", "")
        lines = [l for l in got.split("\n") if not re.match(r"^\x1b\[|\[(INFO|WARN|DEBUG|ERROR) *\]|\[user pid|deloxy-sh>", l) and "[INFO" not in l and "[WARN" not in l]
        code = None; out_lines = []
        for l in lines[1:]:
            m = re.match(r"^(.*?)\[exit (-?\d+)\]$", l)
            if m:
                code = int(m.group(2))
                if m.group(1): out_lines.append(m.group(1))
                continue
            out_lines.append(l)
        out = "\n".join(out_lines).strip("\n").replace("u_" + name, name)
        return okp, out, code
    finally:
        try: q.kill()
        except Exception: pass
results = []
for ent in tools:
    name, args = ent[0], ent[1]
    okp, out, code = run_one(name, args, extra=(ent[2] if len(ent) > 2 else ()))
    p = subprocess.run([name] + (args.split() if args else []), cwd=ddir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", timeout=30)
    exp = p.stdout.strip("\n")
    ok = okp and out == exp and code == p.returncode
    results.append((name, args, ok, out[:200], exp[:200], code, p.returncode))
    print(("PASS " if ok else "FAIL ") + name + " " + args + ("" if ok else "   got=%r exp=%r code=%s/%s%s" % (out[:140], exp[:100], code, p.returncode, "" if okp else " HUNG")))
    sys.stdout.flush()
n = sum(1 for r in results if r[2])
print("\nCORPUS: %d/%d invocations reproduce native output (%.0f%%)" % (n, len(results), 100.0 * n / max(1, len(results))))
json.dump(results, open("/tmp/corpus-results.json", "w"))
