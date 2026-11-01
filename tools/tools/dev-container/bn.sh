#!/bin/bash
# sandbox wrapper: build native ELFs in a vendor-free copy (no source replacement; build-std needs crates.io)
set -e
S=/home/claude/deloxy-core; B=/home/claude/natbld
mkdir -p $B/src/sys $B/tools
rsync -a --exclude target $S/user/ $B/user/ 2>/dev/null || { rm -rf $B/user; cp -r $S/user $B/user; rm -rf $B/user/*/target $B/user/poc/native/target; }
cp $S/src/sys/abi.rs $B/src/sys/; cp $S/tools/build-native.sh $B/tools/
export RUSTC_BOOTSTRAP=1
export EXTRA_RUSTFLAGS="-Zcrate-attr=feature(c_str_literals)"
export EXTRA_CARGO_FLAGS="--ignore-rust-version -Zbuild-std=core,compiler_builtins -Zbuild-std-features=compiler-builtins-mem"
bash $B/tools/build-native.sh 2>&1 | grep -E "^error|Finished|-rwx|-rw-|-->" -A6 | head -60
cp $B/user/blobs/deloxy-sh.elf $B/user/blobs/monitor.elf $S/user/blobs/
ls -l $S/user/blobs/deloxy-sh.elf $S/user/blobs/monitor.elf
