//! Kernel context switch and FPU/SSE state handling.

use core::arch::global_asm;

/// FXSAVE area (512 bytes, 16-aligned). The kernel is soft-float; user code may use SSE.
#[repr(C, align(16))]
pub struct FxArea(pub [u8; 512]);

impl FxArea {
    /// Default state after reset: FCW=0x037F, MXCSR=0x1F80.
    pub fn new() -> FxArea {
        let mut a = FxArea([0; 512]);
        a.0[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());
        a.0[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
        a
    }
}

global_asm!(
    ".global switch_context",
    "switch_context:",
    "    push rbx",
    "    push rbp",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    mov [rdi], rsp",
    "    mov rsp, rsi",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbp",
    "    pop rbx",
    "    ret",
);

extern "C" {
    /// Save callee-saved registers on the current stack, store RSP to `*prev_rsp`,
    /// switch to `next_rsp` and restore its callee-saved registers.
    ///
    /// # Safety
    /// `prev_rsp` must be valid for writes; `next_rsp` must be a stack prepared by
    /// a previous `switch_context` or by `prepare_stack`. Interrupts must be off.
    pub fn switch_context(prev_rsp: *mut u64, next_rsp: u64);
}

/// Build the initial stack of a new thread so the first `switch_context` into it
/// "returns" into `entry`. Returns the value to store as the thread's saved RSP.
///
/// # Safety
/// `top` must be the 16-byte aligned end of a mapped, writable, unused stack of
/// at least 128 bytes.
pub unsafe fn prepare_stack(top: u64, entry: extern "C" fn() -> !) -> u64 {
    let p = top as *mut u64;
    p.sub(1).write(0); // fake return address: keeps rsp % 16 == 8 at entry, like after a call
    p.sub(2).write(entry as usize as u64);
    for i in 3..=8 {
        p.sub(i).write(0); // rbx, rbp, r12..r15
    }
    top - 64
}

#[inline]
pub unsafe fn fx_save(area: *mut FxArea) {
    core::arch::asm!("fxsave64 [{}]", in(reg) area, options(nostack));
}

#[inline]
pub unsafe fn fx_restore(area: *const FxArea) {
    core::arch::asm!("fxrstor64 [{}]", in(reg) area, options(nostack));
}

/// Allow user code to use x87/SSE: CR0.MP=1, EM=0, CR4.OSFXSR=1, OSXMMEXCPT=1.
pub fn enable_fpu() {
    use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};
    // SAFETY: standard FPU/SSE enabling; the kernel itself never executes SSE.
    unsafe {
        Cr0::update(|f| {
            f.remove(Cr0Flags::EMULATE_COPROCESSOR);
            f.insert(Cr0Flags::MONITOR_COPROCESSOR);
        });
        Cr4::update(|f| f.insert(Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE));
    }
}
