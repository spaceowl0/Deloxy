#!/bin/bash
# Build dist/deloxy-<version>.iso (+ kernel ELF + SHA256SUMS) from a release kernel.
source "$(dirname "$0")/lib-build.sh"
VER=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)-alpha
D="$ROOT/dist"; mkdir -p "$D"
build_kernel "" || exit 1
cp "$KERNEL" "$D/deloxy-core-$VER.elf"
"$ROOT/tools/mkiso.sh" "$KERNEL" "$D/deloxy-$VER.iso"
(cd "$D" && sha256sum deloxy-$VER.iso deloxy-core-$VER.elf > SHA256SUMS && cat SHA256SUMS)
