#!/usr/bin/env python3
"""Pack the initramfs (USTAR, flat, deterministic) shipped as a Limine module.
usage: tools/mkinitramfs.py <out.tar> [extra files...]   (always includes the prebuilt programs in user/blobs)"""
import io, os, sys, tarfile
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
BLOBS = ["sample-wall.ppm", "linux_glibc.elf", "win_msvcrt.exe", "deloxy-sh.elf", "monitor.elf", "hello_native.elf", "hello_linux.elf", "hello_linux_pie.elf", "hello_win.exe", "linux_stdin.elf", "win_k32.exe", "linux_threads.elf", "win_threads.exe", "linux_memhog.elf", "win_sync.exe", "linux_net.elf", "win_net.exe", "linux_net2.elf", "win_net2.exe", "win_compat2.exe", "linux_misc.elf", "linux_rand.elf", "win_rand.exe", "linux_tls.elf", "win_math.exe", "dyn_hello.elf", "ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6", "libgcc_s.so.1", "libstdc++.so.6", "libnss_files.so.2", "libnss_dns.so.2", "dyn_cpp.elf", "dyn_dl.elf", "linux_fork.elf", "sh", "spawn_t.elf", "dup_t.elf", "linux_sig.elf", "linux_fs.elf", "linux_pfs.elf", "linux_crash.elf", "linux_async.elf", "win_seh.exe", "linux_futex.elf", "linux_tsig.elf", "linux_tty.elf", "linux_jobs.elf", "dllapp.exe", "basedll.dll", "mathdll.dll", "dyndll.dll", "baddll.dll", "win_pfs.exe"]
README = b"Deloxy initramfs (read-only). Programs: run <name> from deloxy-sh. Try: run hello_win.exe\n"

def add(tf, name, data):
    ti = tarfile.TarInfo(name)
    ti.size, ti.mtime, ti.mode, ti.uid, ti.gid, ti.uname, ti.gname = len(data), 0, 0o755 if name.endswith((".elf", ".exe")) else 0o644, 0, 0, "", ""
    tf.addfile(ti, io.BytesIO(data))

out = sys.argv[1]
with tarfile.open(out, "w", format=tarfile.USTAR_FORMAT) as tf:
    add(tf, "README.txt", README)
    for b in BLOBS:
        add(tf, b, open(os.path.join(ROOT, "user", "blobs", b), "rb").read())
    for extra in sys.argv[2:]:
        add(tf, os.path.basename(extra), open(extra, "rb").read())
    # EXTRA_DIR: every regular file in that directory is added too (corpus / test builds)
    xd = os.environ.get("EXTRA_DIR")
    for n in (sorted(os.listdir(xd)) if xd else []):
        if os.path.isfile(os.path.join(xd, n)):
            add(tf, n, open(os.path.join(xd, n), "rb").read())
print("wrote %s (%d bytes)" % (out, os.path.getsize(out)))
