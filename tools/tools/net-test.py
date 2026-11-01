#!/usr/bin/env python3
"""End-to-end network/updater test. Boots a `--features net-test` kernel ISO in QEMU with a virtio-net NIC,
serves tools/mock-update-server.py on the host, and checks the packet capture (-object filter-dump):
  A) while no NetGrant exists the capture contains ZERO packets,
  B) with a grant only DHCP/ARP and TCP to the granted host:port appear, and the updater scenarios pass,
  C) after the grant is dropped the NIC goes silent again.
usage: tools/net-test.py <iso> <outdir>      (exit status 0 = pass)"""
import importlib.util, os, re, struct, subprocess, sys, time

ISO, OUT = sys.argv[1], sys.argv[2]
os.makedirs(OUT, exist_ok=True)
SERIAL, PCAP = os.path.join(OUT, "serial.log"), os.path.join(OUT, "net.pcap")
for f in (SERIAL, PCAP):
    if os.path.exists(f):
        os.remove(f)
here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("srv", os.path.join(here, "mock-update-server.py"))
srv = importlib.util.module_from_spec(spec); spec.loader.exec_module(srv)
PORT = 8777
server = srv.serve(PORT)

qemu = subprocess.Popen(["qemu-system-x86_64", "-M", "q35", "-m", "256M", "-cdrom", ISO, "-serial", "file:" + SERIAL, "-display", "none", "-no-reboot",
                         "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
                         "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
                         "-object", "filter-dump,id=f0,netdev=n0,file=" + PCAP])
results = []

def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + ((" (%s)" % detail) if detail else ""), flush=True)

def log():
    try:
        return re.sub(r"\x1b\[[0-9;]*m", "", open(SERIAL, errors="replace").read())
    except FileNotFoundError:
        return ""

def wait_for(text, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if text in log():
            return True
        if qemu.poll() is not None and text not in log():
            return False
        time.sleep(0.1)
    return False

def packets():
    try:
        d = open(PCAP, "rb").read()
    except FileNotFoundError:
        return []
    out, off = [], 24
    while off + 16 <= len(d):
        incl = struct.unpack_from("<I", d, off + 8)[0]
        if off + 16 + incl > len(d):
            break
        out.append(d[off + 16: off + 16 + incl])
        off += 16 + incl
    return out

def classify(f):
    et = struct.unpack_from(">H", f, 12)[0]
    if et == 0x0806:
        return "arp"
    if et == 0x0800:
        ihl = (f[14] & 15) * 4
        proto, l4 = f[23], 14 + ihl
        src, dst = ".".join(map(str, f[26:30])), ".".join(map(str, f[30:34]))
        if proto == 17:
            sp, dp = struct.unpack_from(">HH", f, l4)
            return "dhcp" if {sp, dp} == {67, 68} else "udp %s:%d>%s:%d" % (src, sp, dst, dp)
        if proto == 6:
            sp, dp = struct.unpack_from(">HH", f, l4)
            ok = {src, dst} == {"10.0.2.15", "10.0.2.2"} and PORT in (sp, dp)
            return "tcp-granted" if ok else "tcp %s:%d>%s:%d" % (src, sp, dst, dp)
        return "ip proto %d %s>%s" % (proto, src, dst)
    return "ethertype %04x" % et

try:
    check("phase A reached (no grant)", wait_for("NETTEST: PHASE A DONE", 120))
    time.sleep(0.5)
    pa = packets()
    check("ZERO packets on the wire while no grant exists", len(pa) == 0, "%d packets" % len(pa))
    check("phase B passed (grant, DHCP, signed updates)", wait_for("NETTEST: PHASE B DONE", 120))
    for line in ("valid signed manifest accepted", "/tampered rejected: BadSignature", "/wrongkey rejected: UnknownKey", "/forged rejected: BadSignature",
                 "/replay rejected: NotNewer", "/belowmin rejected: BelowMinVersion", "/malformed rejected: ManifestFormat", "update staged; tampered artifact rejected"):
        check("kernel log: " + line, ("NETTEST: " + line) in log())
    pb = packets()
    kinds = {}
    for f in pb:
        k = classify(f)
        kinds[k] = kinds.get(k, 0) + 1
    check("only DHCP/ARP/granted-TCP traffic appeared", set(kinds) <= {"arp", "dhcp", "tcp-granted"}, str(kinds))
    check("DHCP and granted TCP were actually used", kinds.get("dhcp", 0) >= 2 and kinds.get("tcp-granted", 0) >= 10, str(kinds))
    check("phase C: NIC disabled again", wait_for("NETTEST: PHASE C DONE", 60))
    pc = packets()
    time.sleep(1.0)
    check("no packets after the grant was dropped", len(packets()) == len(pc), "%d -> %d" % (len(pc), len(packets())))
    try:
        rc = qemu.wait(timeout=30)
    except subprocess.TimeoutExpired:
        rc = None
    check("selftest + net-test exit status 33", rc == 33, "rc=%s" % rc)
finally:
    if qemu.poll() is None:
        qemu.kill()
    open(os.path.join(OUT, "serial.clean.log"), "w").write(log())

n = sum(results)
print("\n%d/%d checks passed" % (n, len(results)))
sys.exit(0 if n == len(results) else 1)
