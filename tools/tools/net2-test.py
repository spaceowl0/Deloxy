#!/usr/bin/env python3
"""network v2 end-to-end (DNS, UDP, listen/accept, epoll/select, Winsock) on the real kernel.
Original doc: deloxy-wltd end-to-end: real compiler output (static glibc ELF, mingw PE) running on the REAL kernel, with a disk.
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
import socket as _so
def _udp_echo():
    s = _so.socket(_so.AF_INET, _so.SOCK_DGRAM); s.bind(("0.0.0.0", 9999))
    while True:
        d, a = s.recvfrom(2048); s.sendto(b"echo:" + d, a)
threading.Thread(target=_udp_echo, daemon=True).start()
# Hermetic DNS: QEMU's user-mode network forwards guest DNS queries to the HOST's nameserver, so this test needs one that
# knows mock.deloxy.test. Needs root (binds 127.0.0.1:53 and temporarily rewrites /etc/resolv.conf; restored at exit).
import struct, atexit
def _dns_mock():
    s = _so.socket(_so.AF_INET, _so.SOCK_DGRAM); s.bind(("127.0.0.1", 53))
    while True:
        d, a = s.recvfrom(512)
        i = 12
        while d[i]: i += d[i] + 1
        q = d[12:i + 5]; name = d[12:i]
        if name == b"\x04mock\x06deloxy\x04test" and d[i + 1:i + 3] == b"\x00\x01":
            r = d[:2] + b"\x81\x80" + d[4:6] + b"\x00\x01\x00\x00\x00\x00" + q + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([10, 0, 2, 2])
        else:
            r = d[:2] + b"\x81\x83" + d[4:6] + b"\x00\x00\x00\x00\x00\x00" + q
        s.sendto(r, a)
_old_rc = open("/etc/resolv.conf").read()
threading.Thread(target=_dns_mock, daemon=True).start()
open("/etc/resolv.conf", "w").write("nameserver 127.0.0.1\n")
atexit.register(lambda: open("/etc/resolv.conf", "w").write(_old_rc))
# TLS server on :8443 with a cert for mock.deloxy.test signed by the test CA (user/poc/tls)
import ssl, http.server
class _H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = b"tls-hello-from-host"; self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
_tlsd = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "user", "poc", "tls")
_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); _ctx.load_cert_chain(os.path.join(_tlsd, "server.pem"), os.path.join(_tlsd, "server.key"))
_httpd = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), _H); _httpd.socket = _ctx.wrap_socket(_httpd.socket, server_side=True)
threading.Thread(target=_httpd.serve_forever, daemon=True).start()
def connect_to(port, msg, out):
    for _ in range(100):
        try:
            c = _so.create_connection(("127.0.0.1", port), timeout=10); c.sendall(msg); out.append(c.recv(300)); c.close(); return
        except Exception as e:
            time.sleep(0.3)
    out.append(b"")
results = []
def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + ((" (%s)" % detail) if detail else ""), flush=True)

cmd = ["qemu-system-x86_64", "-M", "q35", "-m", "256M", "-cdrom", ISO, "-display", "none", "-no-reboot", "-serial", "stdio", "-monitor", "none",
       "-drive", "file=%s,if=none,id=d0,format=raw" % DISK, "-device", "virtio-blk-pci,drive=d0",
       "-netdev", "user,id=n0,hostfwd=tcp:127.0.0.1:17070-:7070,hostfwd=tcp:127.0.0.1:17071-:7071", "-device", "virtio-net-pci,netdev=n0"]
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
for prog in ("linux_net2.elf", "win_net2.exe"):
    send("perms allow %s rw\r" % prog); expect("deloxy-sh> ", 10)

# ---- permission model for the new scopes
run("perms net linux_net2.elf dns allow", ["allowed"], "perm: DNS scope can be allowed from the shell")
run("perms net linux_net2.elf 10.0.2.2:9999 allow", ["allowed"], "perm: UDP destination rule (rules cover TCP and UDP)")
run("perms net linux_net2.elf 10.0.2.2:8777 allow", ["allowed"])
run("perms net linux_net2.elf listen:7070 allow", ["allowed"], "perm: listen scope can be allowed from the shell")
run("perms", ["linux_net2.elf", "net DNS lookups", "net LISTEN port 7070"], "perm: dns and listen rules are listed")

# ---- Linux: stock glibc getaddrinfo (kernel resolver), UDP, epoll, select, server
out = []
send("run linux_net2.elf\r")
seg = expect("listening on 7070", 90)
th = threading.Thread(target=connect_to, args=(17070, b"ping", out)); th.start()
seg2 = expect("deloxy-sh> ", 90) or ""
th.join(30)
allseg = (seg or "") + seg2
check("Linux: glibc getaddrinfo resolves a host name through the kernel resolver", "dns: mock.deloxy.test -> 10.0.2.2" in allseg, repr(allseg[-500:]))
check("Linux: NXDOMAIN is reported as a lookup failure", "dns: nonexistent -> FAIL" in allseg, repr(allseg[-500:]))
check("Linux: UDP sendto/poll/recvfrom round trip", "udp: got 'echo:hello-udp' from port 9999" in allseg, repr(allseg[-500:]))
check("Linux: non-blocking connect returns EINPROGRESS", "nbconnect: ret=-1 errno=EINPROGRESS" in allseg, repr(allseg[-500:]))
check("Linux: epoll reports the connect finished, SO_ERROR=0", "epoll: connect ready=1 so_error=0" in allseg, repr(allseg[-500:]))
check("Linux: epoll read readiness + data", "epoll: read ready=1 status='HTTP/1.0 404" in allseg, repr(allseg[-500:]))
check("Linux: select works on sockets", "select: n=1" in allseg, repr(allseg[-500:]))
check("Linux: listen/accept - a host connection reaches the server through the firewall", "server: got 'ping'" in allseg and out and out[0] == b"pong:ping", repr((allseg[-300:], out)))
check("Linux: the program finished cleanly", "done" in allseg and "[exit 0]" in allseg, repr(allseg[-200:]))

# ---- default deny stays: no listen rule -> bind/listen is refused
run("perms net linux_net2.elf listen:7070 deny", ["denied"], "perm: a stored listen denial")
seg = run("run linux_net2.elf", ["listen failed errno=13"], "perm: denied listen port -> EACCES, the server never starts", timeout=120, absent=["wants to ACCEPT"])

# ---- the prompt wording for servers
run("perms revoke linux_net2.elf", ["revoked"])
run("perms net linux_net2.elf any allow", ["allowed"], "perm: full access allows DNS and connecting")
send("run linux_net2.elf\r"); seg = expect("[d]eny always: ", 120)
check("perm: full access does NOT imply listening - the user is asked for the port", seg is not None and "ACCEPT INCOMING connections on port 7070" in seg, repr((seg or text()[-300:])[-300:]))
pre = seg or ""
send("n"); seg = expect("deloxy-sh> ", 60) or ""
check("perm: answering no makes listen fail", "listen failed errno=13" in seg, repr(seg[-200:]))
both = pre + seg
check("perm: full access made DNS + UDP work without prompts", "dns: mock.deloxy.test -> 10.0.2.2" in both and "udp: got 'echo:hello-udp'" in both and "wants to look up" not in both and "wants to connect" not in both, repr(both[-500:]))

# ---- TLS: a stock static OpenSSL client verifies the server certificate over Deloxy sockets
send("perms allow linux_tls.elf rw\r"); expect("deloxy-sh> ", 10)
run("perms net linux_tls.elf dns allow", ["allowed"])
run("perms net linux_tls.elf 10.0.2.2:8443 allow", ["allowed"])
seg = run("run linux_tls.elf", ["tls: handshake OK TLSv1.3", "tls: response body 'tls-hello-from-host'", "tls: done"], "TLS: OpenSSL (static) completes a TLSv1.3 handshake with certificate + hostname verification and fetches a page", timeout=180)
check("TLS: a wrong host name is rejected", seg is not None and "tls: handshake REJECTED (hostname mismatch)" in seg, repr((seg or "")[-400:]))
check("TLS: an untrusted CA is rejected", seg is not None and "unable to get local issuer certificate" in seg, repr((seg or "")[-400:]))

# ---- dynamic glibc: dlopen + getaddrinfo through the dynamically loaded NSS modules (libnss_files/libnss_dns)
send("perms allow dyn_dl.elf rw\r"); expect("deloxy-sh> ", 10)
run("perms net dyn_dl.elf dns allow", ["allowed"])
run("run dyn_dl.elf", ["dl: dlopen=ok cos(0)=1.0", "dl: missing lib -> NULL", "dl: getaddrinfo -> 10.0.2.2"], "dynlink: dlopen/dlsym work and dynamic getaddrinfo resolves through the kernel resolver", timeout=120)

# ---- Windows
run("perms net win_net2.exe dns allow", ["allowed"])
run("perms net win_net2.exe 10.0.2.2:9999 allow", ["allowed"])
run("perms net win_net2.exe listen:7071 allow", ["allowed"])
out = []
send("run win_net2.exe\r")
seg = expect("win listening on 7071", 90)
th = threading.Thread(target=connect_to, args=(17071, b"hi", out)); th.start()
seg2 = expect("deloxy-sh> ", 90) or ""
th.join(30)
allseg = (seg or "") + seg2
check("Windows: gethostbyname through the kernel resolver", "win dns: gethostbyname -> 10.0.2.2" in allseg, repr(allseg[-500:]))
check("Windows: getaddrinfo", "win dns: getaddrinfo -> 10.0.2.2 port 8777" in allseg, repr(allseg[-500:]))
check("Windows: UDP sendto + select + recvfrom", "win udp: got 'echo:hello-win' from port 9999" in allseg, repr(allseg[-500:]))
check("Windows: bind/listen/WSAPoll/accept - host connection served", "win server: got 'hi'" in allseg and out and out[0] == b"winpong:hi", repr((allseg[-300:], out)))

send("poweroff\r")
q.wait(timeout=20) if q.poll() is None else None
print("\n%d/%d checks passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
