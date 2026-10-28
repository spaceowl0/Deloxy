#!/usr/bin/env python3
"""End-to-end shell test on the REAL (non-selftest) kernel: boots the ISO in QEMU, drives deloxy-sh over the
serial console, and checks the network packet capture.
  * `upd` consent: answering 'n' sends zero packets; answering 'y' brings the NIC up for the update check,
  * all signed-update scenarios are reachable from the shell (/ok, /tampered, /wrongkey, /replay, /badhash),
  * after the command the NIC is silent again; poweroff stops QEMU.
usage: tools/shell-test.py <iso> <outdir> [--uefi <OVMF.fd>]      (exit status 0 = pass)"""
import importlib.util, os, re, struct, subprocess, sys, threading, time, queue

ISO, OUT = sys.argv[1], sys.argv[2]
UEFI = sys.argv[sys.argv.index("--uefi") + 1] if "--uefi" in sys.argv else None
os.makedirs(OUT, exist_ok=True)
PCAP = os.path.join(OUT, "shell-net.pcap")
if os.path.exists(PCAP):
    os.remove(PCAP)
here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("srv", os.path.join(here, "mock-update-server.py"))
srv = importlib.util.module_from_spec(spec); spec.loader.exec_module(srv)
srv.serve(8777)

cmd = ["qemu-system-x86_64", "-M", "q35", "-m", "256M", "-cdrom", ISO, "-display", "none", "-no-reboot", "-serial", "stdio", "-monitor", "none",
       "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0", "-object", "filter-dump,id=f0,netdev=n0,file=" + PCAP]
if UEFI:
    cmd += ["-bios", UEFI]
q = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
buf = bytearray()
lock = threading.Lock()
def reader():
    while True:
        b = q.stdout.read(1)
        if not b:
            return
        with lock:
            buf.extend(b)
threading.Thread(target=reader, daemon=True).start()

results = []
def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + ((" (%s)" % detail) if detail else ""), flush=True)

def text():
    with lock:
        return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", buf.decode("latin1"))

mark = 0
def expect(needle, timeout=30):
    """Wait for needle after the last match; returns the text up to and including it (or None)."""
    global mark
    t0 = time.time()
    while time.time() - t0 < timeout:
        t = text()
        i = t.find(needle, mark)
        if i >= 0:
            seg = t[mark:i + len(needle)]
            mark = i + len(needle)
            return seg
        if q.poll() is not None:
            break
        time.sleep(0.05)
    return None

def send(s):
    q.stdin.write(s.encode()); q.stdin.flush()

def run(line, want, timeout=30, name=None):
    send(line + "\r")
    seg = expect("deloxy-sh> ", timeout)
    ok = seg is not None and all(w in seg for w in want)
    check(name or ("shell: " + line), ok, "" if ok else repr((seg or text()[-300:])[-300:]))
    return seg or ""

def npackets():
    try:
        d = open(PCAP, "rb").read()
    except FileNotFoundError:
        return 0
    n, off = 0, 24
    while off + 16 <= len(d):
        incl = struct.unpack_from("<I", d, off + 8)[0]
        if off + 16 + incl > len(d):
            break
        n += 1; off += 16 + incl
    return n

BASE = 0
try:
    check("boots to the deloxy-sh prompt on the serial console", expect("deloxy-sh> ", 90) is not None)
    # Under UEFI the OVMF firmware itself does a network boot attempt (IPv6 ND + PXE DHCP) before Deloxy runs;
    # count only what appears from the moment the kernel is up and the shell is waiting for input.
    time.sleep(1.0)
    BASE = npackets()
    if UEFI:
        print("note: %d packets sent by the UEFI firmware before the kernel started are excluded" % BASE)
    check("kernel loaded the initramfs module", "initramfs: 18 file(s)" in text())
    run("help", ["builtins:", "upd check"])
    run("ls", ["deloxy-sh.elf", "hello_win.exe", "monitor.elf"])
    run("run hello_win.exe", ["Hello from Windows PE", "[exit 0]"])
    run("run hello_linux.elf", ["Hello from Linux ELF", "[exit 0]"])
    run("run monitor.elf", ["deloxy-monitor sample 1/1", "network       tx 0 frames"], name="monitor shows tx 0 frames before any grant")
    check("no packets on the wire after boot + commands", npackets() == BASE, "%d new" % (npackets() - BASE))

    send("upd check\r")
    check("upd asks for consent", expect("Allow? [y/N] ", 10) is not None)
    send("n\r")
    seg = expect("deloxy-sh> ", 10) or ""
    check("refusal: 'denied: no grant issued'", "denied: no grant issued" in seg)
    time.sleep(1.0)
    check("refusal: still zero packets", npackets() == BASE, "%d new" % (npackets() - BASE))

    def upd(args, want, name):
        send("upd %s\r" % args)
        expect("Allow? [y/N] ", 10)
        send("y\r")
        seg = expect("deloxy-sh> ", 60) or ""
        check(name, all(w in seg for w in want), repr(seg[-200:]))
    upd("check", ["upd: OK: update available: 0.1.1 (2 artifacts)"], "upd check (valid signed manifest) accepted")
    n1 = npackets()
    check("update check generated real traffic", n1 - BASE > 10, "%d packets" % (n1 - BASE))
    upd("check 10.0.2.2 8777 /tampered", ["REJECTED (code 8)", "BadSignature"], "tampered manifest rejected")
    upd("check 10.0.2.2 8777 /wrongkey", ["REJECTED (code 7)", "UnknownKey"], "wrong-key manifest rejected")
    upd("check 10.0.2.2 8777 /forged", ["REJECTED (code 8)"], "forged key-id manifest rejected")
    upd("check 10.0.2.2 8777 /replay", ["REJECTED (code 10)", "NotNewer"], "replayed (older) manifest rejected")
    upd("check 10.0.2.2 8777 /belowmin", ["REJECTED (code 11)", "BelowMinVersion"], "min_version violation rejected")
    upd("stage 10.0.2.2 8777 /ok", ["upd: OK: staged 0.1.1 in RAM"], "upd stage downloads + verifies artifacts")
    upd("check 10.0.2.2 8777 /ok", ["REJECTED (code 10)"], "re-offering the staged version is a replay")
    upd("stage 10.0.2.2 8777 /badhash", ["REJECTED (code 13)", "ArtifactHash"], "artifact with wrong hash rejected")
    time.sleep(1.0)
    n2 = npackets()
    time.sleep(2.5)
    check("NIC silent again after the grant is dropped", npackets() == n2, "%d -> %d" % (n2, npackets()))
    seg = run("audit 8", ["SEQ"], name="shell: audit shows events")
    run("caps", ["tty", "dir", "spawn", "net-admin"], name="shell: caps lists the shell's authority")
    send("poweroff\r")
    try:
        rc = q.wait(timeout=20)
    except subprocess.TimeoutExpired:
        rc = None
    check("poweroff terminates the VM", rc is not None, "rc=%s" % rc)
finally:
    if q.poll() is None:
        q.kill()
    open(os.path.join(OUT, "shell-serial.log"), "w").write(text())

n = sum(results)
print("\n%d/%d checks passed" % (n, len(results)))
sys.exit(0 if n == len(results) else 1)
