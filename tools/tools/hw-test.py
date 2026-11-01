#!/usr/bin/env python3
"""Driver tests on the real kernel: Intel e1000 NIC, xHCI + USB HID (keyboard typed with PS/2 disabled; absolute tablet),
AHCI/SATA persistence. usage: hw-test.py deloxy.iso   (needs qemu-system-x86_64, PIL)"""
import os, socket, subprocess, sys, time, json, tempfile, threading, importlib.util
iso = sys.argv[1]
os.environ["FULL"] = "1"
results = []
def check(name, ok, detail=""):
    results.append(bool(ok)); print(("PASS " if ok else "FAIL ") + name + ("" if ok else " (%s)" % detail)); sys.stdout.flush()
def boot(extra, log, machine="q35", secs=30, qmp=None):
    for f in (qmp,):
        if f and os.path.exists(f): os.unlink(f)
    a = ["qemu-system-x86_64", "-M", machine, "-m", "256M", "-cdrom", iso, "-display", "none", "-no-reboot", "-serial", "file:" + log, "-vga", "std"] + extra
    if qmp: a += ["-qmp", "unix:%s,server,nowait" % qmp]
    p = subprocess.Popen(a, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(secs); return p
def qmp_client(path):
    s = socket.socket(socket.AF_UNIX); s.connect(path); s.settimeout(2); s.recv(4096)
    def q(o):
        s.sendall((json.dumps(o) + "\n").encode()); time.sleep(0.4)
        try: return s.recv(65536).decode()
        except Exception: return ""
    q({"execute": "qmp_capabilities"}); return q
def serial_shell(extra, cmds, log, timeout=120):
    """Drive the shell over the serial console (same approach as tools/runone.py)."""
    env = dict(os.environ); out = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "runone.py"), iso] + cmds, env=env, capture_output=True, text=True, timeout=timeout)
    return out.stdout

# ---- e1000: DHCP + a TCP request through the firewall
spec = importlib.util.spec_from_file_location("srv", os.path.join(os.path.dirname(__file__), "mock-update-server.py")); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.serve(8777)
env = dict(os.environ, NET="1", NETDEV="e1000")
os.environ.update(env)
out = serial_shell(None, ["perms allow linux_net.elf rw", "perms net linux_net.elf 10.0.2.2:8777 allow", "run linux_net.elf"], None)
check("e1000: probed, DHCP lease obtained", "Intel e1000 found" in out and "DHCP lease 10.0.2.15" in out, out[-400:])
check("e1000: TCP request works through the firewall", "status: HTTP/1.0 404" in out, out[-400:])
os.environ.pop("NET"); os.environ.pop("NETDEV")

# ---- USB: keyboard with PS/2 disabled, tablet absolute pointer
log = tempfile.mktemp(); qp = tempfile.mktemp()
p = boot(["-device", "qemu-xhci,id=x", "-device", "usb-kbd,bus=x.0", "-device", "usb-tablet,bus=x.0"], log, machine="pc,i8042=off", qmp=qp)
try:
    t = open(log, errors="replace").read()
    check("USB: xHCI controller initialised", "xHCI up" in t, t[-300:])
    check("USB: keyboard and tablet enumerated", "-> keyboard" in t and "-> tablet" in t, t[-300:])
    q = qmp_client(qp)
    for k in ("h", "e", "l", "p", "ret"):
        q({"execute": "send-key", "arguments": {"keys": [{"type": "qcode", "data": k}]}})
    q({"execute": "input-send-event", "arguments": {"events": [{"type": "abs", "data": {"axis": "x", "value": 8192}}, {"type": "abs", "data": {"axis": "y", "value": 24576}}]}})
    time.sleep(1.5)
    ppm = tempfile.mktemp(suffix=".ppm"); q({"execute": "screendump", "arguments": {"filename": ppm}}); time.sleep(1.5)
    from PIL import Image
    im = Image.open(ppm).convert("RGB")
    # the typed command ran: the terminal shows the help text (a bright text line right under the prompt)
    t = open(log, errors="replace").read()
    px = im.load(); W, H = im.size
    # white-ish cursor pixels near (320,600)?
    near = sum(1 for x in range(310, 335) for y in range(595, 625) if sum(px[x, y]) > 700)
    check("USB: absolute tablet moved the cursor to the expected spot", near > 10, "bright pixels near target: %d" % near)
    term = sum(1 for x in range(630, 1250, 3) for y in range(380, 420, 2) if px[x, y][0] > 150 and px[x, y][1] > 150)
    check("USB: keystrokes typed on the USB keyboard reached the shell (PS/2 disabled)", term > 40, "text pixels: %d" % term)
finally:
    p.kill(); p.wait()

# ---- AHCI persistence
img = tempfile.mktemp(); open(img, "wb").truncate(64 << 20)
os.environ["AHCI"] = img
out = serial_shell(None, ["~format", "yes", "save note hello-from-sata", "poweroff"], None)
check("AHCI: SATA disk probed and formatted", "AHCI/SATA found" in out, out[-300:])
out = serial_shell(None, ["cat note", "poweroff"], None)
check("AHCI: data persisted across a reboot", "hello-from-sata" in out, out[-300:])
# ---- entropy: reported quality, and different output on every boot
def sample(extra):
    os.environ["EXTRA"] = extra
    o = serial_shell(None, ["perms allow linux_rand.elf rw", "run linux_rand.elf"], None)
    import re
    m = re.search(r"sample:([0-9a-f]{16})", o); return o, (m.group(1) if m else None)
o1, s1 = sample(""); o2, s2 = sample("")
check("entropy: weak (timing-only) seeding is reported as WEAK, not hidden", "WEAK" in o1, o1[-200:])
check("entropy: two boots give different random output", s1 and s2 and s1 != s2, (s1, s2))
o3, s3 = sample("-cpu max -device virtio-rng-pci")
check("entropy: hardware RNG + virtio-rng are used and reported strong", "virtio-rng + jitter: strong" in o3 or "virtio-rng device found" in o3 and "strong" in o3, o3[-300:])
os.environ["EXTRA"] = ""
print("\n%d/%d checks passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
