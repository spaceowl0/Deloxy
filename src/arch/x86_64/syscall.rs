//! SYSCALL/SYSRET entry (BSP only), ring-3 entry, and the register frame.
//!
//! Single-CPU design: the kernel stack for the next syscall lives in a global
//! (`SYSCALL_KERNEL_RSP`) updated on every context switch, so no SWAPGS/GS-relative
//! addressing is needed. When SMP arrives this becomes a per-CPU (GS) slot.

use core::arch::global_asm;
use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::registers::model_specific::{Efer, EferFlags, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;
use x86_64::VirtAddr;

#[no_mangle]
static SYSCALL_KERNEL_RSP: AtomicU64 = AtomicU64::new(0);
#[no_mangle]
static SYSCALL_USER_RSP: AtomicU64 = AtomicU64::new(0);

pub fn set_kernel_rsp(top: u64) {
    SYSCALL_KERNEL_RSP.store(top, Ordering::Relaxed);
}

/// Register state saved on syscall entry (lowest address first). `rax` doubles
/// as the syscall number on entry and the return value on exit.
#[repr(C)]
pub struct SyscallFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r9: u64,
    pub r8: u64,
    pub r10: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rax: u64,
    pub rip: u64,    // saved RCX
    pub rflags: u64, // saved R11
    pub rsp: u64,    // user stack pointer
}

global_asm!(
    ".global syscall_entry",
    "syscall_entry:",
    "    mov [rip + {user_rsp}], rsp",
    "    mov rsp, [rip + {kernel_rsp}]",
    "    push qword ptr [rip + {user_rsp}]",
    "    push r11",
    "    push rcx",
    "    push rax",
    "    push rdi",
    "    push rsi",
    "    push rdx",
    "    push r10",
    "    push r8",
    "    push r9",
    "    push rbx",
    "    push rbp",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    mov rdi, rsp",
    "    cld",
    "    call {dispatch}",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbp",
    "    pop rbx",
    "    pop r9",
    "    pop r8",
    "    pop r10",
    "    pop rdx",
    "    pop rsi",
    "    pop rdi",
    "    pop rax",
    "    pop rcx",
    "    pop r11",
    "    pop rsp",
    "    sysretq",
    user_rsp = sym SYSCALL_USER_RSP,
    kernel_rsp = sym SYSCALL_KERNEL_RSP,
    dispatch = sym crate::sys::dispatch::syscall_dispatch,
);

extern "C" {
    fn syscall_entry();
}

/// Program EFER.SCE, STAR, LSTAR and SFMASK.
pub fn init() {
    let s = super::gdt::selectors();
    Star::write(s.user_code, s.user_data, s.kernel_code, s.kernel_data)
        .expect("GDT layout incompatible with SYSRET");
    LStar::write(VirtAddr::new(syscall_entry as usize as u64));
    SFMask::write(RFlags::INTERRUPT_FLAG | RFlags::DIRECTION_FLAG | RFlags::TRAP_FLAG);
    // SAFETY: enabling SCE only makes the SYSCALL instruction legal; LSTAR/STAR are set above.
    unsafe { Efer::update(|f| f.insert(EferFlags::SYSTEM_CALL_EXTENSIONS)) };
}

/// Drop to ring 3 at `rip` with stack `rsp` (interrupts enabled) and `arg0` in RDI.
/// All other general-purpose registers are zeroed so no kernel values leak. Never returns.
///
/// # Safety
/// `rip`/`rsp` must be valid user addresses in the *currently active* address
/// space, mapped with appropriate permissions.
pub unsafe fn enter_user(rip: u64, rsp: u64, arg0: u64) -> ! {
    let s = super::gdt::selectors();
    core::arch::asm!(
        "push rax",  // SS
        "push rcx",  // RSP
        "push rdx",  // RFLAGS
        "push rsi",  // CS
        "push r8",   // RIP
        "xor eax, eax",
        "xor ecx, ecx",
        "xor edx, edx",
        "xor esi, esi",
        "xor ebx, ebx",
        "xor ebp, ebp",
        "xor r8d, r8d",
        "xor r9d, r9d",
        "xor r10d, r10d",
        "xor r11d, r11d",
        "xor r12d, r12d",
        "xor r13d, r13d",
        "xor r14d, r14d",
        "xor r15d, r15d",
        "iretq",
        in("rax") s.user_data.0 as u64,
        in("rcx") rsp,
        in("rdx") 0x202u64, // IF=1, reserved bit 1
        in("rsi") s.user_code.0 as u64,
        in("r8") rip,
        in("rdi") arg0,
        options(noreturn),
    );
}

/// Full user register set for starting a forked child exactly where its parent made the `fork` syscall.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UserRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r9: u64,
    pub r8: u64,
    pub r10: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rip: u64,
    pub rflags: u64,
    pub rsp: u64,
}

/// Enter user mode with `r`'s registers and `rax = 0` (the child's fork return value).
///
/// # Safety
/// `rip`/`rsp` must be valid user addresses in the currently active address space.
pub unsafe fn enter_user_regs(r: *const UserRegs) -> ! {
    let s = super::gdt::selectors();
    core::arch::asm!(
        "push rcx",                // SS
        "push qword ptr [rax + 112]", // RSP
        "mov rcx, [rax + 104]",
        "or rcx, 0x202",
        "push rcx",                // RFLAGS (IF set)
        "push rdx",                // CS
        "push qword ptr [rax + 96]",  // RIP
        "mov r15, [rax]",
        "mov r14, [rax + 8]",
        "mov r13, [rax + 16]",
        "mov r12, [rax + 24]",
        "mov rbp, [rax + 32]",
        "mov rbx, [rax + 40]",
        "mov r9,  [rax + 48]",
        "mov r8,  [rax + 56]",
        "mov r10, [rax + 64]",
        "mov rsi, [rax + 80]",
        "mov rdi, [rax + 88]",
        "mov rdx, [rax + 72]",
        "xor ecx, ecx",
        "xor r11d, r11d",
        "xor eax, eax",
        "iretq",
        in("rax") r,
        in("rcx") s.user_data.0 as u64,
        in("rdx") s.user_code.0 as u64,
        options(noreturn),
    );
}
