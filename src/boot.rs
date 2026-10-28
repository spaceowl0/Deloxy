//! Boot stub: own 64 KiB kernel stack (instead of trusting the bootloader's) and
//! a frame-pointer backtrace helper.

use core::arch::global_asm;

pub const BOOT_STACK_SIZE: usize = 64 * 1024;

#[repr(C, align(16))]
pub struct BootStack([u8; BOOT_STACK_SIZE]);

#[no_mangle]
static mut BOOT_STACK: BootStack = BootStack([0; BOOT_STACK_SIZE]);

const _: () = assert!(BOOT_STACK_SIZE == 65536);

global_asm!(
    ".section .text._start,\"ax\"",
    ".global _start",
    "_start:",
    "    lea rsp, [rip + {stack} + 65536]", // == BOOT_STACK_SIZE (asserted below)
    "    xor ebp, ebp",
    "    call {main}",
    "2:  cli",
    "    hlt",
    "    jmp 2b",
    stack = sym BOOT_STACK,
    main = sym crate::kmain,
);

fn boot_stack_range() -> (usize, usize) {
    // SAFETY: only the address of the static is taken; no reference or read.
    let lo = unsafe { core::ptr::addr_of!(BOOT_STACK) } as usize;
    (lo, lo + BOOT_STACK_SIZE)
}

/// Walk the frame-pointer chain starting at `rbp` and log return addresses.
/// Resolve offline with: `addr2line -f -e target/x86_64-unknown-none/debug/deloxy-core <addr>`.
pub fn backtrace(mut rbp: usize) {
    let (lo, hi) = boot_stack_range();
    log::error!("backtrace (frame pointers):");
    for depth in 0..24 {
        if rbp < lo || rbp + 16 > hi || rbp % 8 != 0 {
            break;
        }
        // SAFETY: `rbp..rbp+16` was just bounds-checked to lie inside the boot
        // stack, which is mapped RW for the lifetime of the kernel.
        let (next, ret) = unsafe { (*(rbp as *const usize), *((rbp + 8) as *const usize)) };
        if ret == 0 {
            break;
        }
        log::error!("  #{:<2} {:#018x}", depth, ret);
        if next <= rbp {
            break;
        }
        rbp = next;
    }
}

#[inline(always)]
pub fn current_rbp() -> usize {
    let rbp: usize;
    // SAFETY: reads a register; no memory or flags touched.
    unsafe { core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack, preserves_flags)) };
    rbp
}

/// One past the highest byte of the boot stack (initial RSP of the idle thread).
pub fn boot_stack_top() -> u64 {
    boot_stack_range().1 as u64
}
