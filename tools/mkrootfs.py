#!/usr/bin/env python3
"""Build the read-only hierarchical root filesystem archive (USTAR) from a directory tree.
usage: mkrootfs.py <out.tar> [<source-dir>]
Regular files, directories and symlinks are kept. Paths longer than the USTAR limit (255) and anything else are skipped."""
import os, sys, tarfile
out = sys.argv[1]
src = sys.argv[2] if len(sys.argv) > 2 else None
n = 0; skipped = 0
with tarfile.open(out, "w", format=tarfile.USTAR_FORMAT) as tf:
    if src and os.path.isdir(src):
        for dirpath, dirnames, filenames in os.walk(src):
            dirnames.sort()
            rel = os.path.relpath(dirpath, src)
            # symlinks to directories are listed with the directories by os.walk (and are not descended into)
            for dn in list(dirnames):
                dfull = os.path.join(dirpath, dn)
                if os.path.islink(dfull):
                    dirnames.remove(dn)
                    name = os.path.normpath(os.path.join(rel, dn)); target = os.readlink(dfull)
                    if len(name) > 255 or len(target) > 99: skipped += 1; continue
                    ti = tarfile.TarInfo(name); ti.type = tarfile.SYMTYPE; ti.linkname = target; ti.mtime = 0; tf.addfile(ti); n += 1
            if rel != ".":
                ti = tarfile.TarInfo(rel); ti.type = tarfile.DIRTYPE; ti.mode = 0o755; ti.mtime = 0; tf.addfile(ti)
            for fn in sorted(filenames):
                full = os.path.join(dirpath, fn); name = os.path.normpath(os.path.join(rel, fn))
                if len(name) > 255: skipped += 1; continue
                if os.path.islink(full):
                    ti = tarfile.TarInfo(name); ti.type = tarfile.SYMTYPE; ti.linkname = os.readlink(full); ti.mtime = 0
                    if len(ti.linkname) > 99: skipped += 1; continue
                    tf.addfile(ti); n += 1
                elif os.path.isfile(full):
                    st = os.stat(full); ti = tarfile.TarInfo(name); ti.size = st.st_size; ti.mode = 0o755 if st.st_mode & 0o111 else 0o644; ti.mtime = 0
                    try:
                        with open(full, "rb") as f: tf.addfile(ti, f)
                    except OSError:
                        skipped += 1; continue
                    n += 1
print("rootfs: %d entries, %d skipped -> %s" % (n, skipped, out))
