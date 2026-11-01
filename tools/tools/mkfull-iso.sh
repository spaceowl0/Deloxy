#!/bin/bash
# Build the "full" ISO: the base image plus CPython 3.12 (with a trimmed standard library in the hierarchical root
# filesystem) and the `file` utility with its magic database. The binaries and the stdlib are taken from THIS host, so it
# must be Ubuntu 24.04 (glibc 2.39 / Python 3.12 like the shipped libc in user/blobs).
# usage: tools/mkfull-iso.sh <kernel-elf> <out.iso>
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
K="${1:?kernel elf}"; OUT="${2:?output iso}"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
mkdir -p "$W/root/usr/lib" "$W/root/usr/share/misc" "$W/extra"
cp -r "$ROOT/user/rootfs-test/." "$W/root/"
python3 - "$W" <<'PY'
import os, shutil, subprocess, sys
w = sys.argv[1]; src = "/usr/lib/python3.12"; dst = w + "/root/usr/lib/python3.12"
skip = {"test", "tests", "__pycache__", "idlelib", "tkinter", "turtledemo", "lib2to3", "ensurepip", "pydoc_data", "config-3.12-x86_64-linux-gnu", "site-packages", "dist-packages", "distutils", "unittest"}
for dp, dns, fns in os.walk(src):
    dns[:] = [d for d in dns if d not in skip]
    rel = os.path.relpath(dp, src); os.makedirs(os.path.join(dst, rel), exist_ok=True)
    for f in fns:
        full = os.path.join(dp, f)
        if f.endswith(".pyc") or os.path.islink(full): continue
        shutil.copy(full, os.path.join(dst, rel, f))
shutil.copytree(src + "/unittest", dst + "/unittest", ignore=shutil.ignore_patterns("test", "__pycache__"))
os.makedirs(w + "/root/usr/lib/file", exist_ok=True)
shutil.copy("/usr/lib/file/magic.mgc", w + "/root/usr/lib/file/magic.mgc")
os.symlink("../../lib/file/magic.mgc", w + "/root/usr/share/misc/magic.mgc")
libs = set()
def add(name):
    path = shutil.which(name); shutil.copy(os.path.realpath(path), w + "/extra/" + name); os.chmod(w + "/extra/" + name, 0o755)
    for l in subprocess.run(["ldd", path], capture_output=True, text=True).stdout.split("\n"):
        l = l.strip()
        if "=>" in l and "/" in l.split("=>")[1]: libs.add(l.split("=>")[1].split()[0])
add("python3"); add("file")
for l in libs:
    b = os.path.basename(l)
    if b in ("libc.so.6", "libm.so.6", "libgcc_s.so.1", "libstdc++.so.6"): continue
    if not os.path.exists(w + "/extra/" + b): shutil.copy(os.path.realpath(l), w + "/extra/" + b)
PY
ROOTFS_DIR="$W/root" EXTRA_DIR="$W/extra" bash "$ROOT/tools/mkiso.sh" "$K" "$OUT"
