//! Kernel heap: size-class free lists (16..2048 B) in front of an address-ordered,
//! coalescing first-fit allocator. Grows on demand by mapping more pages.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use x86_64::VirtAddr;

use super::layout::{KERNEL_HEAP, KERNEL_HEAP_MAX, PAGE_SIZE};
use super::vmm::{self, VmFlags};
use crate::sync::IrqMutex;

const BLOCK_SIZES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];
const GROW_CHUNK: usize = 256 * 1024;
const INITIAL_SIZE: usize = 1024 * 1024;

const fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

#[repr(C)]
struct Hole {
    size: usize,
    next: *mut Hole,
}

struct FreeBlock {
    next: *mut FreeBlock,
}

pub struct Heap {
    classes: [*mut FreeBlock; 8],
    head: *mut Hole, // address-ordered free list of the fallback allocator
    mapped_end: usize,
    mapped: usize,
    used: usize,
    ready: bool,
}

// SAFETY: the raw pointers reference heap memory owned by this struct only; all
// access goes through the IrqMutex in `KernelAllocator`.
unsafe impl Send for Heap {}

impl Heap {
    const fn new() -> Self {
        Heap {
            classes: [ptr::null_mut(); 8],
            head: ptr::null_mut(),
            mapped_end: KERNEL_HEAP as usize,
            mapped: 0,
            used: 0,
            ready: false,
        }
    }

    /// # Safety
    /// `addr..addr+size` must be mapped, unused memory; both multiples of 16, size >= 16.
    unsafe fn add_free_region(&mut self, addr: usize, size: usize) {
        let mut prev: *mut Hole = ptr::null_mut();
        let mut cur = self.head;
        while !cur.is_null() && (cur as usize) < addr {
            prev = cur;
            cur = (*cur).next;
        }
        let node = addr as *mut Hole;
        node.write(Hole { size, next: cur });
        if prev.is_null() {
            self.head = node;
        } else {
            (*prev).next = node;
        }
        if !cur.is_null() && addr + size == cur as usize {
            (*node).size += (*cur).size;
            (*node).next = (*cur).next;
        }
        if !prev.is_null() && prev as usize + (*prev).size == addr {
            (*prev).size += (*node).size;
            (*prev).next = (*node).next;
        }
    }

    unsafe fn fallback_alloc(&mut self, size: usize, align: usize) -> *mut u8 {
        let mut prev: *mut Hole = ptr::null_mut();
        let mut cur = self.head;
        while !cur.is_null() {
            let start = cur as usize;
            let end = start + (*cur).size;
            let next = (*cur).next;
            let a = align_up(start, align);
            if let Some(a_end) = a.checked_add(size) {
                if a_end <= end {
                    if prev.is_null() {
                        self.head = next;
                    } else {
                        (*prev).next = next;
                    }
                    if a > start {
                        self.add_free_region(start, a - start);
                    }
                    if end > a_end {
                        self.add_free_region(a_end, end - a_end);
                    }
                    return a as *mut u8;
                }
            }
            prev = cur;
            cur = next;
        }
        ptr::null_mut()
    }

    fn class_of(layout: &Layout) -> Option<usize> {
        let need = layout.size().max(layout.align());
        BLOCK_SIZES.iter().position(|&s| s >= need)
    }

    unsafe fn alloc(&mut self, layout: Layout) -> *mut u8 {
        match Self::class_of(&layout) {
            Some(i) => {
                let head = self.classes[i];
                if !head.is_null() {
                    self.classes[i] = (*head).next;
                    self.used += BLOCK_SIZES[i];
                    return head as *mut u8;
                }
                let sz = BLOCK_SIZES[i];
                let p = self.fallback_alloc(sz, sz);
                if !p.is_null() {
                    self.used += sz;
                }
                p
            }
            None => {
                let size = align_up(layout.size().max(16), 16);
                let p = self.fallback_alloc(size, layout.align().max(16));
                if !p.is_null() {
                    self.used += size;
                }
                p
            }
        }
    }

    unsafe fn dealloc(&mut self, p: *mut u8, layout: Layout) {
        match Self::class_of(&layout) {
            Some(i) => {
                let b = p as *mut FreeBlock;
                (*b).next = self.classes[i];
                self.classes[i] = b;
                self.used -= BLOCK_SIZES[i];
            }
            None => {
                let size = align_up(layout.size().max(16), 16);
                self.add_free_region(p as usize, size);
                self.used -= size;
            }
        }
    }

    fn grow(&mut self, min: usize) -> bool {
        let bytes = align_up(min.max(GROW_CHUNK), PAGE_SIZE as usize);
        if self.mapped_end + bytes > (KERNEL_HEAP + KERNEL_HEAP_MAX) as usize {
            return false;
        }
        if vmm::kernel_map_anon(VirtAddr::new(self.mapped_end as u64), bytes / PAGE_SIZE as usize, VmFlags::WRITE)
            .is_err()
        {
            return false;
        }
        // SAFETY: the range was just mapped RW, zeroed and is unused.
        unsafe { self.add_free_region(self.mapped_end, bytes) };
        self.mapped_end += bytes;
        self.mapped += bytes;
        true
    }
}

pub struct KernelAllocator(IrqMutex<Heap>);

// SAFETY: all state is behind an interrupt-disabling spinlock; returned blocks
// are unique, correctly sized and aligned to `layout.align()` (fallback aligns to
// max(align,16); size-class blocks are aligned to their own size >= align).
unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut h = self.0.lock();
        if !h.ready {
            return ptr::null_mut();
        }
        let p = h.alloc(layout);
        if !p.is_null() {
            return p;
        }
        let need = layout.size().max(layout.align()) * 2 + 64;
        if h.grow(need) {
            return h.alloc(layout);
        }
        ptr::null_mut()
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        self.0.lock().dealloc(p, layout);
    }
}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator(IrqMutex::new(Heap::new()));

/// Map the initial heap. Requires `vmm::init`.
pub fn init() {
    let mut h = ALLOCATOR.0.lock();
    assert!(h.grow(INITIAL_SIZE), "heap init failed");
    h.ready = true;
}

#[derive(Debug, Clone, Copy)]
pub struct HeapStats {
    pub mapped: usize,
    pub used: usize,
}

pub fn stats() -> HeapStats {
    let h = ALLOCATOR.0.lock();
    HeapStats { mapped: h.mapped, used: h.used }
}
