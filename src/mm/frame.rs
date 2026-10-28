//! Bitmap physical frame allocator (4 KiB frames).
//!
//! Bit = 1 -> frame used/reserved, bit = 0 -> frame free.
//! The bitmap itself lives in the first large-enough usable region above 1 MiB
//! and is accessed through Limine's higher-half direct map (HHDM).

use crate::sync::IrqMutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};
use x86_64::PhysAddr;

pub const FRAME_SIZE: u64 = 4096;
const LOW_MEM_LIMIT: u64 = 0x10_0000; // keep the first 1 MiB untouched

const fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}
const fn align_down(v: u64, a: u64) -> u64 {
    v & !(a - 1)
}

pub struct BitmapFrameAllocator {
    bitmap: &'static mut [u8],
    total_frames: usize,
    free_frames: usize,
    next_hint: usize,
}

impl BitmapFrameAllocator {
    /// Build the allocator from usable `(base, length)` regions.
    ///
    /// # Safety
    /// * `regions` must describe genuinely usable RAM not otherwise in use
    ///   (Limine `USABLE` entries).
    /// * `hhdm_offset` must be the HHDM offset such that `hhdm_offset + phys`
    ///   is a valid, writable virtual mapping for all of `regions`.
    /// * Must be called at most once; nothing else may alias the chosen bitmap.
    pub unsafe fn init<I>(regions: I, hhdm_offset: u64) -> Option<Self>
    where
        I: Iterator<Item = (u64, u64)> + Clone,
    {
        let norm = |(base, len): (u64, u64)| {
            let s = align_up(base, FRAME_SIZE);
            let e = align_down(base.saturating_add(len), FRAME_SIZE);
            (s, e)
        };

        let highest = regions.clone().map(|r| norm(r).1).max()?;
        let total_frames = (highest / FRAME_SIZE) as usize;
        let bitmap_bytes = (total_frames + 7) / 8;
        let bitmap_size = align_up(bitmap_bytes as u64, FRAME_SIZE);

        // Locate a home for the bitmap (above 1 MiB).
        let bitmap_phys = regions.clone().find_map(|r| {
            let (s, e) = norm(r);
            let s = s.max(LOW_MEM_LIMIT);
            (e > s && e - s >= bitmap_size).then_some(s)
        })?;

        // SAFETY: per function contract the HHDM maps this usable region RW,
        // and the region is unused, so a unique &mut slice is sound.
        let bitmap = core::slice::from_raw_parts_mut(
            (hhdm_offset + bitmap_phys) as *mut u8,
            bitmap_bytes,
        );
        bitmap.fill(0xFF); // everything used (also keeps tail padding bits set)

        let mut this = Self {
            bitmap,
            total_frames,
            free_frames: 0,
            next_hint: (LOW_MEM_LIMIT / FRAME_SIZE) as usize,
        };

        for r in regions {
            let (s, e) = norm(r);
            let s = s.max(LOW_MEM_LIMIT);
            let mut a = s;
            while a < e {
                this.clear((a / FRAME_SIZE) as usize);
                this.free_frames += 1;
                a += FRAME_SIZE;
            }
        }

        // Reserve the bitmap's own frames.
        let first = (bitmap_phys / FRAME_SIZE) as usize;
        for f in first..first + (bitmap_size / FRAME_SIZE) as usize {
            if !this.is_used(f) {
                this.set(f);
                this.free_frames -= 1;
            }
        }
        Some(this)
    }

    #[inline]
    fn is_used(&self, f: usize) -> bool {
        self.bitmap[f / 8] & (1 << (f % 8)) != 0
    }
    #[inline]
    fn set(&mut self, f: usize) {
        self.bitmap[f / 8] |= 1 << (f % 8);
    }
    #[inline]
    fn clear(&mut self, f: usize) {
        self.bitmap[f / 8] &= !(1 << (f % 8));
    }

    fn find_free(&self) -> Option<usize> {
        let nbytes = self.bitmap.len();
        let start = self.next_hint / 8;
        for i in 0..nbytes {
            let b = (start + i) % nbytes;
            let v = self.bitmap[b];
            if v == 0xFF {
                continue;
            }
            for bit in 0..8 {
                if v & (1 << bit) == 0 {
                    let f = b * 8 + bit;
                    if f < self.total_frames {
                        return Some(f);
                    }
                }
            }
        }
        None
    }

    pub fn allocate(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let f = self.find_free()?;
        self.set(f);
        self.free_frames -= 1;
        self.next_hint = f + 1;
        Some(PhysFrame::containing_address(PhysAddr::new(
            f as u64 * FRAME_SIZE,
        )))
    }

    /// Allocate `n` physically contiguous frames whose first frame index is a multiple of
    /// `align_frames` (a power of two). Used for DMA rings.
    pub fn allocate_contiguous(&mut self, n: usize, align_frames: usize) -> Option<PhysFrame<Size4KiB>> {
        if n == 0 || align_frames == 0 || !align_frames.is_power_of_two() || n > self.free_frames {
            return None;
        }
        let first_ok = (LOW_MEM_LIMIT / FRAME_SIZE) as usize;
        let mut start = (first_ok + align_frames - 1) & !(align_frames - 1);
        while start.checked_add(n)? <= self.total_frames {
            match (start..start + n).find(|&f| self.is_used(f)) {
                None => {
                    for f in start..start + n {
                        self.set(f);
                    }
                    self.free_frames -= n;
                    return Some(PhysFrame::containing_address(PhysAddr::new(start as u64 * FRAME_SIZE)));
                }
                // Skip past the used frame, keeping alignment.
                Some(used) => start = (used + 1 + align_frames - 1) & !(align_frames - 1),
            }
        }
        None
    }

    /// Free a frame. Returns `false` (and changes nothing) on double free or
    /// out-of-range frames.
    pub fn deallocate(&mut self, frame: PhysFrame<Size4KiB>) -> bool {
        let f = (frame.start_address().as_u64() / FRAME_SIZE) as usize;
        if f >= self.total_frames || !self.is_used(f) {
            return false;
        }
        self.clear(f);
        self.free_frames += 1;
        self.next_hint = self.next_hint.min(f);
        true
    }

    pub fn total_frames(&self) -> usize {
        self.total_frames
    }
    pub fn free_frames(&self) -> usize {
        self.free_frames
    }
    pub fn free_bytes(&self) -> u64 {
        self.free_frames as u64 * FRAME_SIZE
    }
}

pub static FRAME_ALLOCATOR: IrqMutex<Option<BitmapFrameAllocator>> = IrqMutex::new(None);

/// Install the global allocator. See [`BitmapFrameAllocator::init`] for safety.
///
/// # Safety
/// Same contract as [`BitmapFrameAllocator::init`].
pub unsafe fn init<I>(regions: I, hhdm_offset: u64) -> bool
where
    I: Iterator<Item = (u64, u64)> + Clone,
{
    match BitmapFrameAllocator::init(regions, hhdm_offset) {
        Some(a) => {
            *FRAME_ALLOCATOR.lock() = Some(a);
            true
        }
        None => false,
    }
}

pub fn allocate_frame() -> Option<PhysFrame<Size4KiB>> {
    FRAME_ALLOCATOR.lock().as_mut()?.allocate()
}

pub fn deallocate_frame(frame: PhysFrame<Size4KiB>) -> bool {
    FRAME_ALLOCATOR
        .lock()
        .as_mut()
        .map_or(false, |a| a.deallocate(frame))
}

/// `(total_frames, free_frames)`; zeros before init.
pub fn stats() -> (usize, usize) {
    FRAME_ALLOCATOR
        .lock()
        .as_ref()
        .map_or((0, 0), |a| (a.total_frames(), a.free_frames()))
}

/// Allocate `n` physically contiguous frames (see [`BitmapFrameAllocator::allocate_contiguous`]).
pub fn allocate_contiguous(n: usize, align_frames: usize) -> Option<PhysFrame<Size4KiB>> {
    FRAME_ALLOCATOR.lock().as_mut()?.allocate_contiguous(n, align_frames)
}

/// Free `n` frames starting at `first` (all-or-nothing is not guaranteed; returns frames freed).
pub fn deallocate_contiguous(first: PhysFrame<Size4KiB>, n: usize) -> usize {
    let mut ok = 0;
    for i in 0..n as u64 {
        let f = PhysFrame::containing_address(first.start_address() + i * FRAME_SIZE);
        if deallocate_frame(f) {
            ok += 1;
        }
    }
    ok
}
