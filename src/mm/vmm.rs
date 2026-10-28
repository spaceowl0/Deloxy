//! Virtual memory manager: address spaces, page mapping, MMIO and kernel stacks.
//!
//! Rules: nothing in this module may allocate from the kernel heap (the heap
//! grows by calling into here while holding its own lock).

use core::ops::BitOr;
use core::sync::atomic::{AtomicU64, Ordering};

use spin::Once;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr3, Cr3Flags, Cr4, Cr4Flags, Efer, EferFlags};
use x86_64::structures::paging::mapper::{MapToError, MappedFrame, TranslateResult, UnmapError};
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
    Translate,
};
use x86_64::{PhysAddr, VirtAddr};

use super::frame;
use super::layout::*;
use crate::sync::IrqMutex;

// ---------------------------------------------------------------- flags ----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VmFlags(u32);

impl VmFlags {
    pub const NONE: VmFlags = VmFlags(0);
    pub const READ: VmFlags = VmFlags(1);
    pub const WRITE: VmFlags = VmFlags(2);
    pub const EXEC: VmFlags = VmFlags(4);
    pub const USER: VmFlags = VmFlags(8);
    pub const MMIO: VmFlags = VmFlags(16);

    pub const fn contains(self, o: VmFlags) -> bool {
        self.0 & o.0 == o.0
    }

    fn to_pt(self) -> PageTableFlags {
        let mut f = PageTableFlags::PRESENT;
        if self.contains(Self::WRITE) {
            f |= PageTableFlags::WRITABLE;
        }
        if !self.contains(Self::EXEC) {
            f |= PageTableFlags::NO_EXECUTE;
        }
        if self.contains(Self::USER) {
            f |= PageTableFlags::USER_ACCESSIBLE;
        }
        if self.contains(Self::MMIO) {
            f |= PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH;
        }
        f
    }
}

impl BitOr for VmFlags {
    type Output = VmFlags;
    fn bitor(self, o: VmFlags) -> VmFlags {
        VmFlags(self.0 | o.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    NotAligned,
    OutOfRange,
    AlreadyMapped,
    NotMapped,
    OutOfFrames,
}

// ------------------------------------------------------------ globals ------

static HHDM: AtomicU64 = AtomicU64::new(0);
static MMIO_NEXT: AtomicU64 = AtomicU64::new(KERNEL_MMIO);
static SHM_NEXT: AtomicU64 = AtomicU64::new(KERNEL_SHM);
static STACK_NEXT: AtomicU64 = AtomicU64::new(KERNEL_STACKS);
static KERNEL_SPACE: Once<IrqMutex<AddressSpace>> = Once::new();

pub fn hhdm() -> u64 {
    HHDM.load(Ordering::Relaxed)
}

/// Kernel-virtual pointer to a physical address via the HHDM.
pub fn phys_to_virt(p: PhysAddr) -> *mut u8 {
    (hhdm() + p.as_u64()) as *mut u8
}

pub fn zero_frame(f: PhysFrame) {
    // SAFETY: the frame was just handed out by the frame allocator (exclusively
    // ours) and the HHDM maps all RAM read/write.
    unsafe { core::ptr::write_bytes(phys_to_virt(f.start_address()), 0, PAGE_SIZE as usize) };
}

struct KernelFrameAlloc;

// SAFETY: `allocate_frame` only returns frames that the bitmap allocator has
// marked used and never hands the same frame out twice.
unsafe impl FrameAllocator<Size4KiB> for KernelFrameAlloc {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let f = frame::allocate_frame()?;
        zero_frame(f);
        Some(f)
    }
}

// ------------------------------------------------------- address space -----

pub struct AddressSpace {
    pml4: PhysFrame,
}

impl AddressSpace {
    fn table_ptr(&self) -> *mut PageTable {
        phys_to_virt(self.pml4.start_address()) as *mut PageTable
    }

    fn mapper(&mut self) -> OffsetPageTable<'static> {
        // SAFETY: `pml4` is a valid, zero-initialised-or-populated PML4 owned by
        // this AddressSpace; `&mut self` guarantees unique access to it, and the
        // HHDM offset is the one Limine established.
        unsafe { OffsetPageTable::new(&mut *self.table_ptr(), VirtAddr::new(hhdm())) }
    }

    pub fn pml4_frame(&self) -> PhysFrame {
        self.pml4
    }

    /// New address space whose kernel half (PML4 256..512) is shared with the kernel's.
    pub fn new_user() -> Option<AddressSpace> {
        let f = KernelFrameAlloc.allocate_frame()?;
        let ks = kernel_space().lock();
        // SAFETY: both pointers reference valid PML4 pages; `f` is exclusively ours,
        // and the kernel PML4 is only read while the kernel-space lock is held.
        unsafe {
            let src = &*ks.table_ptr();
            let dst = &mut *(phys_to_virt(f.start_address()) as *mut PageTable);
            for i in 256..512 {
                dst[i] = src[i].clone();
            }
        }
        Some(AddressSpace { pml4: f })
    }

    fn check(va: VirtAddr, f: VmFlags) -> Result<(), VmError> {
        let a = va.as_u64();
        if !va.is_aligned(PAGE_SIZE) {
            return Err(VmError::NotAligned);
        }
        let ok = if f.contains(VmFlags::USER) {
            is_user_range(a, PAGE_SIZE)
        } else {
            a >= KERNEL_SPACE_START
        };
        if ok { Ok(()) } else { Err(VmError::OutOfRange) }
    }

    pub fn map(&mut self, va: VirtAddr, pa: PhysFrame, f: VmFlags) -> Result<(), VmError> {
        Self::check(va, f)?;
        let mut parent = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        if f.contains(VmFlags::USER) {
            parent |= PageTableFlags::USER_ACCESSIBLE;
        }
        let page = Page::<Size4KiB>::containing_address(va);
        // SAFETY: mapping a page can change what memory is reachable; callers own
        // the policy (range/flags are validated above, frames come from the allocator).
        let r = unsafe {
            self.mapper()
                .map_to_with_table_flags(page, pa, f.to_pt(), parent, &mut KernelFrameAlloc)
        };
        match r {
            Ok(flush) => {
                flush.flush();
                Ok(())
            }
            Err(MapToError::FrameAllocationFailed) => Err(VmError::OutOfFrames),
            Err(_) => Err(VmError::AlreadyMapped),
        }
    }

    /// Map `pages` fresh zeroed frames at `va`. Rolls back on failure.
    pub fn map_anon(&mut self, va: VirtAddr, pages: usize, f: VmFlags) -> Result<(), VmError> {
        for i in 0..pages {
            let page_va = va + (i as u64) * PAGE_SIZE;
            let res = match KernelFrameAlloc.allocate_frame() {
                None => Err(VmError::OutOfFrames),
                Some(fr) => match self.map(page_va, fr, f) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        frame::deallocate_frame(fr);
                        Err(e)
                    }
                },
            };
            if let Err(e) = res {
                for j in 0..i {
                    let _ = self.unmap_free(va + (j as u64) * PAGE_SIZE);
                }
                return Err(e);
            }
        }
        Ok(())
    }

    /// Unmap one page and return the frame that backed it (caller decides whether to free it).
    pub fn unmap(&mut self, va: VirtAddr) -> Result<PhysFrame, VmError> {
        if !va.is_aligned(PAGE_SIZE) {
            return Err(VmError::NotAligned);
        }
        match self.mapper().unmap(Page::<Size4KiB>::containing_address(va)) {
            Ok((fr, flush)) => {
                flush.flush();
                Ok(fr)
            }
            Err(UnmapError::PageNotMapped) => Err(VmError::NotMapped),
            Err(_) => Err(VmError::NotMapped),
        }
    }

    pub fn unmap_free(&mut self, va: VirtAddr) -> Result<(), VmError> {
        let fr = self.unmap(va)?;
        frame::deallocate_frame(fr);
        Ok(())
    }

    pub fn protect(&mut self, va: VirtAddr, f: VmFlags) -> Result<(), VmError> {
        Self::check(va, f)?;
        // SAFETY: only changes permission bits of an existing leaf mapping.
        let r = unsafe {
            self.mapper()
                .update_flags(Page::<Size4KiB>::containing_address(va), f.to_pt())
        };
        match r {
            Ok(flush) => {
                flush.flush();
                Ok(())
            }
            Err(_) => Err(VmError::NotMapped),
        }
    }

    /// Physical frame and permissions of a mapped user page (None if unmapped).
    pub fn query(&mut self, va: VirtAddr) -> Option<(PhysFrame, VmFlags)> {
        match self.mapper().translate(va) {
            TranslateResult::Mapped { frame, flags, .. } => {
                let fr = match frame {
                    MappedFrame::Size4KiB(f) => f,
                    _ => return None,
                };
                let mut v = VmFlags::READ;
                if flags.contains(PageTableFlags::USER_ACCESSIBLE) {
                    v = v | VmFlags::USER;
                }
                if flags.contains(PageTableFlags::WRITABLE) {
                    v = v | VmFlags::WRITE;
                }
                if !flags.contains(PageTableFlags::NO_EXECUTE) {
                    v = v | VmFlags::EXEC;
                }
                Some((fr, v))
            }
            _ => None,
        }
    }

    pub fn translate(&mut self, va: VirtAddr) -> Option<PhysAddr> {
        self.mapper().translate_addr(va)
    }

    /// Translate a user address, requiring a present, user-accessible page
    /// (and writable if `write`). Returns the physical address of `va`.
    pub fn translate_user(&mut self, va: VirtAddr, write: bool) -> Option<PhysAddr> {
        match self.mapper().translate(va) {
            TranslateResult::Mapped { frame, offset, flags } => {
                if !flags.contains(PageTableFlags::USER_ACCESSIBLE) {
                    return None;
                }
                if write && !flags.contains(PageTableFlags::WRITABLE) {
                    return None;
                }
                Some(frame.start_address() + offset)
            }
            _ => None,
        }
    }

    /// # Safety
    /// The address space must map the currently executing code, stack and all data
    /// the CPU touches next (i.e. contain the shared kernel half).
    pub unsafe fn activate(&self) {
        Cr3::write(self.pml4, Cr3Flags::empty());
    }

    /// Free the page-table frames of the USER half (not the leaf frames they map).
    pub fn destroy(self) {
        // SAFETY: walks tables owned exclusively by this (now consumed) address space.
        unsafe {
            let l4 = &*self.table_ptr();
            for i in 0..256 {
                let e4 = &l4[i];
                if !e4.flags().contains(PageTableFlags::PRESENT) {
                    continue;
                }
                let l3 = &*(phys_to_virt(e4.addr()) as *const PageTable);
                for e3 in l3.iter().filter(|e| e.flags().contains(PageTableFlags::PRESENT)) {
                    if !e3.flags().contains(PageTableFlags::HUGE_PAGE) {
                        let l2 = &*(phys_to_virt(e3.addr()) as *const PageTable);
                        for e2 in l2.iter().filter(|e| e.flags().contains(PageTableFlags::PRESENT)) {
                            if !e2.flags().contains(PageTableFlags::HUGE_PAGE) {
                                frame::deallocate_frame(PhysFrame::containing_address(e2.addr()));
                            }
                        }
                        frame::deallocate_frame(PhysFrame::containing_address(e3.addr()));
                    }
                }
                frame::deallocate_frame(PhysFrame::containing_address(e4.addr()));
            }
        }
        frame::deallocate_frame(self.pml4);
    }
}

pub fn kernel_space() -> &'static IrqMutex<AddressSpace> {
    KERNEL_SPACE.get().expect("vmm not initialised")
}

// ---------------------------------------------------------------- init ------

/// Take over paging: enable NX/WP/SMEP and switch to our own PML4 that shares
/// Limine's kernel-half mappings.
///
/// Must be called once, after `frame::init`.
pub fn init(hhdm_offset: u64, smep: bool) {
    HHDM.store(hhdm_offset, Ordering::Relaxed);

    // SAFETY: setting NXE/WP/SMEP only tightens protections. The current page
    // tables (Limine's) already use NX, and the kernel maps no user pages.
    unsafe {
        Efer::update(|f| f.insert(EferFlags::NO_EXECUTE_ENABLE));
        Cr0::update(|f| f.insert(Cr0Flags::WRITE_PROTECT));
        if smep {
            Cr4::update(|f| f.insert(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION));
        }
    }

    let new = KernelFrameAlloc.allocate_frame().expect("no frame for kernel PML4");
    let (old, _) = Cr3::read();
    // SAFETY: `old` is the live PML4 (reachable via the HHDM), `new` is a fresh frame.
    unsafe {
        let src = &*(phys_to_virt(old.start_address()) as *const PageTable);
        let dst = &mut *(phys_to_virt(new.start_address()) as *mut PageTable);
        for i in 256..512 {
            dst[i] = src[i].clone();
            // Pre-populate every empty kernel-half slot so all future address
            // spaces (which copy these entries) see later kernel mappings.
            if !dst[i].flags().contains(PageTableFlags::PRESENT) {
                let pdpt = KernelFrameAlloc.allocate_frame().expect("no frame for kernel PDPT");
                dst[i].set_frame(pdpt, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
            }
        }
        // SAFETY (switch): the copied upper half maps the kernel image, its stack
        // (.bss), the HHDM and everything Limine gave us; the lower half is dropped.
        Cr3::write(new, Cr3Flags::empty());
    }
    KERNEL_SPACE.call_once(|| IrqMutex::new(AddressSpace { pml4: new }));
}

// -------------------------------------------------- kernel conveniences -----

pub fn kernel_map_anon(va: VirtAddr, pages: usize, f: VmFlags) -> Result<(), VmError> {
    kernel_space().lock().map_anon(va, pages, f)
}

/// Map a device register range uncached; returns a pointer to `phys`.
pub fn map_mmio(phys: u64, len: usize) -> Option<*mut u8> {
    let start = phys & !(PAGE_SIZE - 1);
    let end = (phys + len as u64 + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let pages = (end - start) / PAGE_SIZE;
    let va = MMIO_NEXT.fetch_add((pages + 1) * PAGE_SIZE, Ordering::Relaxed); // +1 guard page
    let mut ks = kernel_space().lock();
    for i in 0..pages {
        let fr = PhysFrame::containing_address(PhysAddr::new(start + i * PAGE_SIZE));
        ks.map(VirtAddr::new(va + i * PAGE_SIZE), fr, VmFlags::WRITE | VmFlags::MMIO).ok()?;
    }
    Some((va + (phys - start)) as *mut u8)
}

/// Give the kernel a virtually contiguous, writable view of a shared-memory object
/// (its frames need not be physically contiguous). The view lives forever (VA is not recycled).
pub fn map_kernel_shared(mem: &crate::ipc::memobj::MemObject) -> Option<*mut u8> {
    let pages = mem.pages() as u64;
    let va = SHM_NEXT.fetch_add((pages + 1) * PAGE_SIZE, Ordering::Relaxed);
    let mut ks = kernel_space().lock();
    for (i, &f) in mem.frames().iter().enumerate() {
        ks.map(VirtAddr::new(va + i as u64 * PAGE_SIZE), f, VmFlags::WRITE).ok()?;
    }
    Some(va as *mut u8)
}

/// A kernel stack with an unmapped guard page below it.
pub struct KernelStack {
    guard: VirtAddr,
    pages: usize,
}

impl KernelStack {
    pub fn new(pages: usize) -> Option<KernelStack> {
        let total = (pages as u64 + 1) * PAGE_SIZE;
        let base = STACK_NEXT.fetch_add(total + PAGE_SIZE, Ordering::Relaxed); // extra gap between stacks
        let guard = VirtAddr::new(base);
        kernel_map_anon(guard + PAGE_SIZE, pages, VmFlags::WRITE).ok()?;
        Some(KernelStack { guard, pages })
    }
    pub fn guard_addr(&self) -> VirtAddr {
        self.guard
    }
    pub fn bottom(&self) -> VirtAddr {
        self.guard + PAGE_SIZE
    }
    /// Initial RSP (16-byte aligned, one past the highest byte).
    pub fn top(&self) -> VirtAddr {
        self.bottom() + (self.pages as u64) * PAGE_SIZE
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        let mut ks = kernel_space().lock();
        for i in 0..self.pages {
            let _ = ks.unmap_free(self.bottom() + (i as u64) * PAGE_SIZE);
        }
    }
}
