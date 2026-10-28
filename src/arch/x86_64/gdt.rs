//! GDT + TSS. Layout is dictated by SYSCALL/SYSRET arithmetic:
//! null, kcode 0x08, kdata 0x10, udata 0x18, ucode 0x20, TSS 0x28.
//! IST0 = dedicated double-fault stack; RSP0 is updated on every context switch.

use core::ptr::{addr_of, addr_of_mut};

use spin::Lazy;
use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

/// IST slot (0-based index into `interrupt_stack_table`) used by #DF.
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

const DF_STACK_SIZE: usize = 4096 * 5;

#[repr(align(16))]
struct Stack([u8; DF_STACK_SIZE]);

/// Backing memory for the double-fault stack; only the CPU writes to it.
static mut DOUBLE_FAULT_STACK: Stack = Stack([0; DF_STACK_SIZE]);

/// The one TSS (single CPU). Mutated only with interrupts disabled.
static mut TSS: TaskStateSegment = TaskStateSegment::new();

pub struct Selectors {
    pub kernel_code: SegmentSelector,
    pub kernel_data: SegmentSelector,
    pub user_data: SegmentSelector,
    pub user_code: SegmentSelector,
    tss: SegmentSelector,
}

static GDT: Lazy<(GlobalDescriptorTable, Selectors)> = Lazy::new(|| {
    let mut gdt = GlobalDescriptorTable::new();
    let kernel_code = gdt.append(Descriptor::kernel_code_segment());
    let kernel_data = gdt.append(Descriptor::kernel_data_segment());
    let user_data = gdt.append(Descriptor::user_data_segment());
    let user_code = gdt.append(Descriptor::user_code_segment());
    // SAFETY: TSS is a `static`, so the address stays valid forever; the CPU only
    // reads it through this descriptor after `ltr`.
    #[allow(unused_unsafe)]
    let tss = gdt.append(unsafe { Descriptor::tss_segment_unchecked(addr_of!(TSS)) });
    (gdt, Selectors { kernel_code, kernel_data, user_data, user_code, tss })
});

pub fn selectors() -> &'static Selectors {
    &GDT.1
}

/// Load the GDT, reload segment registers, set up IST0 and load the TSS.
pub fn init() {
    // SAFETY: called once during early boot, before interrupts are enabled and
    // before the TSS is loaded, so nothing else accesses TSS / DOUBLE_FAULT_STACK.
    #[allow(unused_unsafe)]
    unsafe {
        let start = VirtAddr::from_ptr(addr_of!(DOUBLE_FAULT_STACK));
        (*addr_of_mut!(TSS)).interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
            start + DF_STACK_SIZE as u64; // stacks grow down: IST holds the end address
    }
    GDT.0.load();
    // SAFETY: selectors come from the GDT we just loaded (valid 64-bit kernel
    // descriptors and an available TSS). `ltr` runs exactly once.
    unsafe {
        CS::set_reg(GDT.1.kernel_code);
        SS::set_reg(GDT.1.kernel_data);
        DS::set_reg(GDT.1.kernel_data);
        ES::set_reg(GDT.1.kernel_data);
        load_tss(GDT.1.tss);
    }
}

/// Set the stack the CPU switches to on a ring3 -> ring0 interrupt/exception.
pub fn set_kernel_stack(top: u64) {
    // SAFETY: single CPU; callers run with interrupts disabled, so the CPU cannot
    // read RSP0 concurrently. Writing a u64 field of the static TSS.
    #[allow(unused_unsafe)]
    unsafe {
        (*addr_of_mut!(TSS)).privilege_stack_table[0] = VirtAddr::new(top);
    }
}
