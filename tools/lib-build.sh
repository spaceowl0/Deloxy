# sourced by test-all.sh / make-release.sh. build_kernel <features...>  -> kernel ELF path in $KERNEL
# Real toolchain (pinned nightly in rust-toolchain.toml):  cargo build --release [--features X]
# Sandbox (apt rustc 1.75):  DELOXY_BUILD="bash tools/dev-container/b.sh" DELOXY_TARGET_DIR=/home/claude/target-shared
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${DELOXY_TARGET_DIR:-$ROOT/target}"
build_kernel() {
  local feat="$1"
  local args=(--release)
  [ -n "$feat" ] && args+=(--features "$feat")
  if [ -n "$DELOXY_BUILD" ]; then
    (cd "$ROOT" && $DELOXY_BUILD "${args[@]}") >/tmp/deloxy-build.log 2>&1 || { cat /tmp/deloxy-build.log; return 1; }
  else
    (cd "$ROOT" && cargo build "${args[@]}") || return 1
  fi
  KERNEL="$TARGET_DIR/x86_64-unknown-none/release/deloxy-core"
  [ -f "$KERNEL" ] || { echo "kernel not found at $KERNEL"; return 1; }
}
