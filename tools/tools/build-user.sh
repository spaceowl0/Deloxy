#!/bin/bash
# Rebuild user/blobs/<crate>.bin from user/<dir> (needs a Rust toolchain with core for x86_64-unknown-none
# and binutils' objcopy). The committed .bin files mean this is only needed when editing user programs.
#   tools/build-user.sh            # rebuilds utest and de
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
build() { # dir crate outname
  cd "$ROOT/user/$1"
  RUSTFLAGS="-Clink-arg=-T$ROOT/user/user.ld -Crelocation-model=static -Ccode-model=small -Clink-arg=-no-pie ${EXTRA_RUSTFLAGS}" \
    cargo build --release --target x86_64-unknown-none ${EXTRA_CARGO_FLAGS}
  objcopy -O binary "target/x86_64-unknown-none/release/$2" "$ROOT/user/blobs/$3.bin"
  ls -l "$ROOT/user/blobs/$3.bin"
}
build utest deloxy-utest utest
build de deloxy-de-apps de
