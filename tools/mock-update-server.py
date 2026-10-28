#!/usr/bin/env python3
"""Mock deloxy-upd update server + TEST signing keys. For tests only.

  mock-update-server.py serve [--port 8777]   serve the scenarios below on 0.0.0.0
  mock-update-server.py keys                  print the test public keys (Rust syntax)

Scenarios (URL prefix): /ok (valid, version 0.1.1), /tampered (manifest edited after signing),
/wrongkey (signed by an untrusted key), /forged (untrusted signature claiming the trusted key id),
/replay (validly signed but version 0.6.0), /belowmin (needs >= 0.9.0 installed), /badhash (artifact bytes differ),
/malformed (signed, but not valid manifest JSON).
The TRUSTED test key below is compiled into the alpha kernel (src/upd/keys.rs). It is public and NOT a
release key: before any real release replace it via the key ceremony described in docs/SECURITY.md.
"""
import hashlib, http.server, json, os, sys, threading
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import ed25519_ref as ed

SEED_TRUSTED = hashlib.sha256(b"deloxy-alpha-TEST-key-trusted").digest()
SEED_OTHER = hashlib.sha256(b"deloxy-alpha-TEST-key-untrusted").digest()
PUB_TRUSTED, PUB_OTHER = ed.public_key(SEED_TRUSTED), ed.public_key(SEED_OTHER)


def key_id(pub):
    return hashlib.sha256(pub).digest()[:8].hex()


def artifact(name, size):
    seed = hashlib.sha256(name.encode()).digest()
    return (seed * (size // 32 + 1))[:size]


ARTS = {"deloxy-core.bin": 3000, "initramfs.tar": 5000}


def manifest(version, min_version, bad_hash=None):
    arts = []
    for n, sz in ARTS.items():
        data = artifact(n, sz)
        h = hashlib.sha256(data).hexdigest()
        arts.append({"name": n, "size": sz, "sha256": h, "path": "/artifacts/" + n})
    return json.dumps({"format": 1, "version": version, "min_version": min_version, "created": 1790000000, "artifacts": arts}, separators=(",", ":")).encode()


def sigfile(seed, pub, msg, claim_id=None):
    sig = ed.sign(seed, msg)
    return ("deloxy-sig-v1\nkey_id=%s\nsig=%s\n" % (claim_id or key_id(pub), sig.hex())).encode()


def build():
    s = {}
    m = manifest("0.1.1", "0.1.0")
    s["/ok/manifest.json"], s["/ok/manifest.sig"] = m, sigfile(SEED_TRUSTED, PUB_TRUSTED, m)
    t = m.replace(b'"0.1.1"', b'"0.1.9"')
    s["/tampered/manifest.json"], s["/tampered/manifest.sig"] = t, sigfile(SEED_TRUSTED, PUB_TRUSTED, m)
    s["/wrongkey/manifest.json"], s["/wrongkey/manifest.sig"] = m, sigfile(SEED_OTHER, PUB_OTHER, m)
    s["/forged/manifest.json"], s["/forged/manifest.sig"] = m, sigfile(SEED_OTHER, PUB_OTHER, m, claim_id=key_id(PUB_TRUSTED))
    r = manifest("0.0.9", "0.0.5")
    s["/replay/manifest.json"], s["/replay/manifest.sig"] = r, sigfile(SEED_TRUSTED, PUB_TRUSTED, r)
    b = manifest("0.1.5", "0.9.0")
    s["/belowmin/manifest.json"], s["/belowmin/manifest.sig"] = b, sigfile(SEED_TRUSTED, PUB_TRUSTED, b)
    h = manifest("0.1.2", "0.1.0")
    s["/badhash/manifest.json"], s["/badhash/manifest.sig"] = h, sigfile(SEED_TRUSTED, PUB_TRUSTED, h)
    mal = b'{"format":1,"version":"0.1.3","artifacts":[]'  # truncated JSON, but properly signed
    s["/malformed/manifest.json"], s["/malformed/manifest.sig"] = mal, sigfile(SEED_TRUSTED, PUB_TRUSTED, mal)
    for n, sz in ARTS.items():
        for scen in ("ok", "tampered", "wrongkey", "forged", "replay", "belowmin", "malformed"):
            s["/%s/artifacts/%s" % (scen, n)] = artifact(n, sz)
        s["/badhash/artifacts/" + n] = artifact(n, sz)[:-1] + b"\x00" if n == "initramfs.tar" else artifact(n, sz)
    return s


class H(http.server.BaseHTTPRequestHandler):
    routes = build()
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        body = self.routes.get(self.path)
        if body is None:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        sys.stderr.write("served %s (%d bytes)\n" % (self.path, len(body)))

    def log_message(self, *a):
        pass


def serve(port):
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "keys":
        print("TRUSTED key_id=%s pub=%s" % (key_id(PUB_TRUSTED), PUB_TRUSTED.hex()))
        print("UNTRUSTED key_id=%s pub=%s" % (key_id(PUB_OTHER), PUB_OTHER.hex()))
        print("rust: pub  [%s]" % ", ".join("0x%02x" % b for b in PUB_TRUSTED))
    else:
        port = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 8777
        srv = serve(port)
        print("mock update server on :%d" % port, flush=True)
        threading.Event().wait()
