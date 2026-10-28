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
    idt.divide_error.set_handler_fn(divide_error_handler);
    idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
    idt.page_fault.set_handler_fn(page_fault_handler);
    idt.general_protection_fault.set_handler_fn(general_protection_handler);
    // SAFETY: IST index 0 is populated with a valid, dedicated stack in the
    // TSS (see gdt.rs) before the IDT is loaded.
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(DOUBLE_FAULT_IST_INDEX);
    }
    idt[TIMER_VECTOR].set_handler_fn(timer_handler);
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

/// A fault raised by user code: kill only the offending process.
fn user_fault(what: &str, frame: &InterruptStackFrame, detail: u64, code: i64) -> ! {
    let (pid, tid) = crate::task::current_ids();
    log::warn!("user fault in process '{}' rsp {:#x}", crate::task::current_process().name, frame.stack_pointer.as_u64());
    log::warn!(
        "user fault: {} in pid {} tid {} at rip {:#x} (detail {:#x}) - killing process",
        what,
        pid,
        tid,
        frame.instruction_pointer.as_u64(),
        detail
    );
    crate::audit_log!(crate::audit::EV_FAULT, 0, 0, frame.instruction_pointer.as_u64(), detail, code);
    crate::task::kill_current_process(code)
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
