//! IDT: CPU exceptions (fatal in ring 0, process-killing in ring 3), LAPIC timer, spurious.

use spin::Lazy;
use x86_64::registers::control::{Cr2, Cr3};
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use x86_64::PrivilegeLevel;

use super::gdt::DOUBLE_FAULT_IST_INDEX;
use crate::sys::errno::{EXIT_FAULT_DE, EXIT_FAULT_GP, EXIT_FAULT_PF, EXIT_FAULT_UD};

pub const TIMER_VECTOR: u8 = 0x20;
pub const KBD_VECTOR: u8 = 0x21;
pub const MOUSE_VECTOR: u8 = 0x2C;
pub const SPURIOUS_VECTOR: u8 = 0xFF;

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    // SAFETY: the stubs below preserve the CPU's exception frame exactly (kernel-mode faults jump to the
    // original x86-interrupt handlers) and end in `iretq`, as an IDT entry requires.
    unsafe {
        idt.divide_error.set_handler_addr(x86_64::VirtAddr::new(trap_de as usize as u64));
        idt.invalid_opcode.set_handler_addr(x86_64::VirtAddr::new(trap_ud as usize as u64));
        idt.page_fault.set_handler_addr(x86_64::VirtAddr::new(trap_pf as usize as u64));
        idt.general_protection_fault.set_handler_addr(x86_64::VirtAddr::new(trap_gp as usize as u64));
        idt[TIMER_VECTOR].set_handler_addr(x86_64::VirtAddr::new(timer_entry as usize as u64));
    }
    // SAFETY: IST index 0 is populated with a valid, dedicated stack in the
    // TSS (see gdt.rs) before the IDT is loaded.
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(DOUBLE_FAULT_IST_INDEX);
    }
    idt[KBD_VECTOR].set_handler_fn(kbd_handler);
    idt[MOUSE_VECTOR].set_handler_fn(mouse_handler);
    idt[SPURIOUS_VECTOR].set_handler_fn(spurious_handler);
    idt
});

/// Load the IDT. `gdt::init()` must have run first (IST stack + kernel CS).
pub fn init() {
    IDT.load();
}

fn from_user(frame: &InterruptStackFrame) -> bool {
    frame.code_segment.rpl() == PrivilegeLevel::Ring3
}

/// Common fatal path: never returns.
fn fatal(name: &str, frame: &InterruptStackFrame, error_code: Option<u64>) -> ! {
    // SAFETY: we are about to halt this CPU forever, so the interrupted code
    // that might hold the serial lock will never run again.
    unsafe { crate::drivers::serial::force_unlock() };

    log::error!("==== CPU EXCEPTION: {} ====", name);
    if let Some(code) = error_code {
        log::error!("error code : {:#x}", code);
    }
    log::error!("RIP        : {:#018x}", frame.instruction_pointer.as_u64());
    log::error!("RSP        : {:#018x}", frame.stack_pointer.as_u64());
    log::error!("CS         : {:#06x}", frame.code_segment.0);
    log::error!("SS         : {:#06x}", frame.stack_segment.0);
    log::error!("RFLAGS     : {:#018x}", frame.cpu_flags.bits());
    let (cr3, _) = Cr3::read_raw();
    log::error!("CR3        : {:#018x}", cr3.start_address().as_u64());
    log::error!("System halted.");
    #[cfg(feature = "selftest")]
    super::qemu_exit(0x11);
    #[cfg(not(feature = "selftest"))]
    super::hlt_loop()
}

/// A fault raised by user code that nobody handles: kill only the offending process.
pub(crate) fn user_fault_at(what: &str, rip: u64, rsp: u64, detail: u64, code: i64) -> ! {
    let (pid, tid) = crate::task::current_ids();
    log::warn!("user fault in process '{}' rsp {:#x}", crate::task::current_process().name, rsp);
    log::warn!("user fault: {} in pid {} tid {} at rip {:#x} (detail {:#x}) - killing process", what, pid, tid, rip, detail);
    crate::audit_log!(crate::audit::EV_FAULT, 0, 0, rip, detail, code);
    crate::task::kill_current_process(code)
}

fn user_fault(what: &str, frame: &InterruptStackFrame, detail: u64, code: i64) -> ! {
    user_fault_at(what, frame.instruction_pointer.as_u64(), frame.stack_pointer.as_u64(), detail, code)
}

/// Registers of a user-mode fault, saved by the trap stubs (lowest address first).
#[repr(C)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

// Entry stubs for #DE (0), #UD (6), #GP (13), #PF (14). A fault from ring 0 jumps straight to the original handler
// (the CPU frame is untouched); a fault from ring 3 saves every register and calls `rust_trap`, which may rewrite
// the frame to resume in a signal handler. The five-word hardware frame plus error code plus vector plus 15
// registers leaves rsp 16-byte aligned at the call.
core::arch::global_asm!(
    ".global trap_de",
    "trap_de:",
    "    test byte ptr [rsp + 8], 3",
    "    jz {de_k}",
    "    push 0",
    "    push 0",
    "    jmp trap_common",
    ".global trap_ud",
    "trap_ud:",
    "    test byte ptr [rsp + 8], 3",
    "    jz {ud_k}",
    "    push 0",
    "    push 6",
    "    jmp trap_common",
    ".global trap_gp",
    "trap_gp:",
    "    test byte ptr [rsp + 16], 3",
    "    jz {gp_k}",
    "    push 13",
    "    jmp trap_common",
    ".global trap_pf",
    "trap_pf:",
    "    test byte ptr [rsp + 16], 3",
    "    jz {pf_k}",
    "    push 14",
    "trap_common:",
    "    push rax",
    "    push rbx",
    "    push rcx",
    "    push rdx",
    "    push rsi",
    "    push rdi",
    "    push rbp",
    "    push r8",
    "    push r9",
    "    push r10",
    "    push r11",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    mov rdi, rsp",
    "    cld",
    "    call {rust}",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop r11",
    "    pop r10",
    "    pop r9",
    "    pop r8",
    "    pop rbp",
    "    pop rdi",
    "    pop rsi",
    "    pop rdx",
    "    pop rcx",
    "    pop rbx",
    "    pop rax",
    "    add rsp, 16",
    "    iretq",
    de_k = sym divide_error_handler,
    ud_k = sym invalid_opcode_handler,
    gp_k = sym general_protection_handler,
    pf_k = sym page_fault_handler,
    rust = sym rust_trap,
);

// LAPIC timer entry. From ring 0: the original `x86-interrupt` handler runs untouched. From ring 3: every register is
// saved so `rust_timer` can run the tick/scheduler and then deliver a pending *handled* signal to the interrupted code
// (asynchronous delivery: a process spinning in user mode no longer has to wait for its next syscall).
core::arch::global_asm!(
    ".global timer_entry",
    "timer_entry:",
    "    test byte ptr [rsp + 8], 3",
    "    jz {timer_k}",
    "    push 0",
    "    push 0x20",
    "    push rax",
    "    push rbx",
    "    push rcx",
    "    push rdx",
    "    push rsi",
    "    push rdi",
    "    push rbp",
    "    push r8",
    "    push r9",
    "    push r10",
    "    push r11",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    mov rdi, rsp",
    "    cld",
    "    call {rust}",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop r11",
    "    pop r10",
    "    pop r9",
    "    pop r8",
    "    pop rbp",
    "    pop rdi",
    "    pop rsi",
    "    pop rdx",
    "    pop rcx",
    "    pop rbx",
    "    pop rax",
    "    add rsp, 16",
    "    iretq",
    // iret_trapframe(rdi = *const TrapFrame) -> !: resume user mode with exactly these registers (used by rt_sigreturn
    // for frames that were built from an asynchronous interruption, where rcx/r11 must survive).
    ".global iret_trapframe",
    "iret_trapframe:",
    "    mov rsp, rdi",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop r11",
    "    pop r10",
    "    pop r9",
    "    pop r8",
    "    pop rbp",
    "    pop rdi",
    "    pop rsi",
    "    pop rdx",
    "    pop rcx",
    "    pop rbx",
    "    pop rax",
    "    add rsp, 16",
    "    iretq",
    timer_k = sym timer_handler,
    rust = sym rust_timer,
);

extern "C" {
    fn timer_entry();
    pub fn iret_trapframe(tf: *const TrapFrame) -> !;
    fn trap_de();
    fn trap_ud();
    fn trap_gp();
    fn trap_pf();
}

/// Ring-3 fault. Linux processes get SIGFPE/SIGILL/SIGSEGV delivered to their handler when they installed one
/// (and the signal is not blocked); everything else, and unhandled signals, kill the process as before.
extern "C" fn rust_trap(tf: &mut TrapFrame) {
    use crate::sys::errno::EXIT_FAULT_PF;
    let (name, sig, code, addr, exit) = match tf.vector {
        0 => ("divide error (#DE)", 8u64, 1i32, tf.rip, EXIT_FAULT_DE),
        6 => ("invalid opcode (#UD)", 4, 1, tf.rip, EXIT_FAULT_UD),
        13 => ("general protection (#GP)", 11, 0x80, 0, EXIT_FAULT_GP),
        _ => {
            let cr2 = Cr2::read_raw();
            // SEGV_ACCERR when the page was present (protection violation), SEGV_MAPERR when it was not mapped
            ("page fault (#PF)", 11, if tf.error & 1 != 0 { 2 } else { 1 }, cr2, EXIT_FAULT_PF)
        }
    };
    let detail = if tf.vector == 14 { addr } else { tf.error };
    let p = crate::task::current_process();
    if p.abi() == crate::abi::AbiKind::Linux && crate::abi::signals::deliver_fault(&p, sig, tf, code, addr) {
        return;
    }
    if p.abi() == crate::abi::AbiKind::Nt && crate::abi::win_exc::deliver_fault(&p, tf, addr, exit) {
        return;
    }
    user_fault_at(name, tf.rip, tf.rsp, detail, exit)
}

extern "x86-interrupt" fn divide_error_handler(frame: InterruptStackFrame) {
    if from_user(&frame) {
        user_fault("divide error (#DE)", &frame, 0, EXIT_FAULT_DE);
    }
    fatal("Divide Error (#DE)", &frame, None)
}

extern "x86-interrupt" fn invalid_opcode_handler(frame: InterruptStackFrame) {
    if from_user(&frame) {
        user_fault("invalid opcode (#UD)", &frame, 0, EXIT_FAULT_UD);
    }
    fatal("Invalid Opcode (#UD)", &frame, None)
}

extern "x86-interrupt" fn page_fault_handler(frame: InterruptStackFrame, error_code: PageFaultErrorCode) {
    let cr2 = Cr2::read_raw();
    if from_user(&frame) {
        user_fault("page fault (#PF)", &frame, cr2, EXIT_FAULT_PF);
    }
    // SAFETY: fatal path, see `fatal`.
    unsafe { crate::drivers::serial::force_unlock() };
    log::error!("PAGE FAULT at address {:#018x}", cr2);
    log::error!("flags      : {:?}", error_code);
    #[cfg(feature = "test-pf")]
    if cr2 == crate::selftest::TEST_PF_ADDR.load(core::sync::atomic::Ordering::SeqCst) {
        log::info!("SELFTEST PF OK (guard page fault caught, cr2={:#x})", cr2);
        super::qemu_exit(0x10);
    }
    fatal("Page Fault (#PF)", &frame, Some(error_code.bits()))
}

extern "x86-interrupt" fn double_fault_handler(frame: InterruptStackFrame, error_code: u64) -> ! {
    fatal("Double Fault (#DF)", &frame, Some(error_code))
}

extern "x86-interrupt" fn general_protection_handler(frame: InterruptStackFrame, error_code: u64) {
    if from_user(&frame) {
        user_fault("general protection (#GP)", &frame, error_code, EXIT_FAULT_GP);
    }
    fatal("General Protection Fault (#GP)", &frame, Some(error_code))
}

/// Timer interrupt that arrived in ring 3.
extern "C" fn rust_timer(tf: &mut TrapFrame) {
    super::apic::eoi();
    crate::time::tick();
    crate::task::sched::on_tick();
    // the scheduler may have switched away and back: `current_process` is the interrupted thread's process again
    let p = crate::task::current_process();
    if p.abi() == crate::abi::AbiKind::Linux {
        crate::abi::signals::deliver_async(&p, tf);
    }
}

extern "x86-interrupt" fn timer_handler(_frame: InterruptStackFrame) {
    // EOI first: this handler may switch threads and not return for a long time.
    super::apic::eoi();
    crate::time::tick();
    crate::task::sched::on_tick();
}

extern "x86-interrupt" fn spurious_handler(_frame: InterruptStackFrame) {
    // Spurious interrupts must NOT be acknowledged.
}

extern "x86-interrupt" fn kbd_handler(_frame: InterruptStackFrame) {
    crate::drivers::input::ps2::kbd_irq();
    super::apic::eoi();
}

extern "x86-interrupt" fn mouse_handler(_frame: InterruptStackFrame) {
    crate::drivers::input::ps2::mouse_irq();
    super::apic::eoi();
}
