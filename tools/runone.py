#!/usr/bin/env python3
"""Boot an ISO, run shell command(s) and print the output: tools/runone.py <iso> "<cmd>" ["<cmd2>" ...]  (optional env DISK=<img>)"""
import os, re, subprocess, sys, threading, time
iso, cmds = sys.argv[1], sys.argv[2:]
cmd = ["qemu-system-x86_64", "-M", "q35", "-m", "256M", "-cdrom", iso, "-display", "none", "-no-reboot", "-serial", "stdio", "-monitor", "none"]
if os.environ.get("DISK"):
    cmd += ["-drive", "file=%s,if=none,id=d0,format=raw" % os.environ["DISK"], "-device", "virtio-blk-pci,drive=d0"]
if os.environ.get("NET"):
    cmd += ["-netdev", "user,id=n0", "-device", os.environ.get("NETDEV", "virtio-net-pci") + ",netdev=n0"]
if os.environ.get("AHCI"):
    cmd += ["-drive", "file=" + os.environ["AHCI"] + ",if=none,id=d0,format=raw", "-device", "ich9-ahci,id=ahci", "-device", "ide-hd,drive=d0,bus=ahci.0"]
cmd += os.environ.get("EXTRA", "").split()
q = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
buf = bytearray()
threading.Thread(target=lambda: [buf.extend(q.stdout.read(1)) or None for _ in iter(int, 1)], daemon=True).start()
def text(): return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", bytes(buf).decode("latin1"))
def wait(n, t=60):
    t0 = time.time()
    while time.time() - t0 < t and text().count("deloxy-sh> ") < n and q.poll() is None: time.sleep(0.1)
wait(1)
n = 1  # a command prefixed with "~" is sent without waiting for a new prompt (e.g. "format" asks for confirmation first)
for c in cmds:
    if c.startswith("@"):
        time.sleep(float(c[1:])); continue  # "@5" = just wait 5 s
    nw = c.startswith("~"); c = c.lstrip("~")
    q.stdin.write((c + "\r").encode()); q.stdin.flush(); time.sleep(0.5)
    if not nw: n += 1; wait(n)
q.kill()
t = text(); print((t if os.environ.get("FULL") else t[t.find("deloxy-sh> "):]).replace("\r", ""))
