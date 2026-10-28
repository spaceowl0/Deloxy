//! Virtual address space layout (x86_64, 4-level paging, 48-bit canonical).
//!
//! ```text
//! 0x0000_0000_0000_0000  null guard (never mapped)
//! 0x0000_0000_0000_1000  USER_START
//! 0x0000_7FFF_FFFF_F000  USER_END (exclusive)      <- last canonical lower-half page
//! ---------------- non-canonical hole ----------------
//! 0xFFFF_8000_0000_0000  HHDM (Limine, all physical RAM)   PML4 256
//! 0xFFFF_C000_0000_0000  kernel heap                       PML4 384
//! 0xFFFF_D000_0000_0000  kernel MMIO (uncached)            PML4 416
//! 0xFFFF_D800_0000_0000  kernel views of shared memory       PML4 432
//! 0xFFFF_E000_0000_0000  kernel thread stacks + guards     PML4 448
//! 0xFFFF_F000_0000_0000  scratch (self-tests)              PML4 480
//! 0xFFFF_FFFF_8000_0000  kernel image                      PML4 511
//! ```

pub const PAGE_SIZE: u64 = 4096;

pub const USER_START: u64 = 0x0000_0000_0000_1000;
pub const USER_END: u64 = 0x0000_7FFF_FFFF_F000;

pub const KERNEL_SPACE_START: u64 = 0xFFFF_8000_0000_0000;
pub const KERNEL_HEAP: u64 = 0xFFFF_C000_0000_0000;
pub const KERNEL_HEAP_MAX: u64 = 1 << 30; // 1 GiB
pub const KERNEL_MMIO: u64 = 0xFFFF_D000_0000_0000;
pub const KERNEL_SHM: u64 = 0xFFFF_D800_0000_0000; // contiguous kernel views of shared memory objects
pub const KERNEL_STACKS: u64 = 0xFFFF_E000_0000_0000;
pub const KERNEL_SCRATCH: u64 = 0xFFFF_F000_0000_0000;
pub const KERNEL_IMAGE: u64 = 0xFFFF_FFFF_8000_0000;

pub const fn is_user_range(start: u64, len: u64) -> bool {
    match start.checked_add(len) {
        Some(end) => start >= USER_START && end <= USER_END,
        None => false,
    }
}
