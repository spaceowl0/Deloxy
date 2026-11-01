#!/bin/bash
# Build the native user programs shipped in the initramfs (ELF, Deloxy ABI) into user/blobs/.
#   tools/build-native.sh            -> user/blobs/deloxy-sh.elf, user/blobs/monitor.elf
# Sandbox (rustc 1.75 from apt): EXTRA_RUSTFLAGS / EXTRA_CARGO_FLAGS add the build-std workarounds, see HANDOFF s6.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
build() { # dir crate outname
  ( cd "$ROOT/user/$1"
    RUSTFLAGS="-Clink-arg=-T$ROOT/user/elf.ld -Crelocation-model=static -Ccode-model=small -Clink-arg=-no-pie -Clink-arg=-zmax-page-size=4096 -Clinker=ld.lld -Clinker-flavor=ld.lld ${EXTRA_RUSTFLAGS}" \
      cargo build --release --target x86_64-unknown-none ${EXTRA_CARGO_FLAGS}
    cp "target/x86_64-unknown-none/release/$2" "$ROOT/user/blobs/$3"
    ls -l "$ROOT/user/blobs/$3" )
}
build sh deloxy-sh deloxy-sh.elf
build monitor deloxy-monitor monitor.elf
