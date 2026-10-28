//! Tiny hand-assembled ring-3 programs (sources + nasm output in `user/blobs/`).
//! Position-independent; entry point is offset 0.

pub static HELLO: &[u8] = include_bytes!("../../user/blobs/hello.bin");
pub static NULLPTR: &[u8] = include_bytes!("../../user/blobs/nullptr.bin");
pub static PRIV: &[u8] = include_bytes!("../../user/blobs/priv.bin");
pub static SYSMIX: &[u8] = include_bytes!("../../user/blobs/sysmix.bin");
pub static THREAD: &[u8] = include_bytes!("../../user/blobs/thread.bin");
/// Rust ring-3 test program (roles selected via the info page); source in `user/utest`.
pub static UTEST: &[u8] = include_bytes!("../../user/blobs/utest.bin");
/// Desktop client (roles: 10 anim, 11 diag, 12 bars); source in `user/de`.
pub static DE: &[u8] = include_bytes!("../../user/blobs/de.bin");

// deloxy-wltd proof-of-concept binaries (sources in user/poc, built by tools/build-poc.sh)
pub static HELLO_NATIVE_ELF: &[u8] = include_bytes!("../../user/blobs/hello_native.elf");
pub static HELLO_LINUX_ELF: &[u8] = include_bytes!("../../user/blobs/hello_linux.elf");
pub static HELLO_LINUX_PIE: &[u8] = include_bytes!("../../user/blobs/hello_linux_pie.elf");
pub static HELLO_WIN_EXE: &[u8] = include_bytes!("../../user/blobs/hello_win.exe");

