#!/bin/bash
# container-only build helper: builds a copy without the vendor source replacement (build-std needs crates.io)
set -e
mkdir -p /home/claude/bld
rm -rf /home/claude/bld; mkdir -p /home/claude/bld; (cd /home/claude/deloxy-core && tar cf - --exclude=./target --exclude=./vendor .) | tar xf - -C /home/claude/bld
python3 - <<'PY'
p='/home/claude/bld/.cargo/config.toml'
s=open(p).read().split('[source.crates-io]')[0]
open(p,'w').write(s)
PY
cd /home/claude/bld
export RUSTC_BOOTSTRAP=1 CARGO_TARGET_DIR=/home/claude/target-shared
export RUSTFLAGS="-Zcrate-attr=feature(c_str_literals) -Clinker=ld.lld -Clinker-flavor=ld.lld -Crelocation-model=static -Ccode-model=kernel -Cforce-frame-pointers=yes"
cargo build --ignore-rust-version -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem --target x86_64-unknown-none "$@" 2>&1 | grep -E "^(error|warning: unused)|-->|Finished|^\s+\||^\s+=" 
