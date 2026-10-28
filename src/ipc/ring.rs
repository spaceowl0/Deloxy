//! Lock-free single-producer/single-consumer ring buffer.
//!
//! `#![no_std]`-clean and free of `crate::` references: this exact file is also
//! compiled into user-space programs (`#[path]` include), so kernel and user
//! agree on the memory layout of rings that live in shared memory.
//!
//! Layout is `#[repr(C)]` and an all-zero page is a valid empty ring, so a
//! freshly zeroed shared-memory page can be used directly.
//!
//! Indices are free-running `u32`s (wrapping); `N` is a power of two. The
//! producer owns `tail`, the consumer owns `head`; Release stores publish slot
//! contents, Acquire loads consume them.
//!
//! Trust note: when the ring is shared with an untrusted peer, indices are
//! masked before use, so a hostile peer can garble data but not cause
//! out-of-bounds access.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[repr(align(64))]
pub struct Padded<T>(pub T);

#[repr(C)]
pub struct Spsc<T: Copy, const N: usize> {
    head: Padded<AtomicU32>,
    tail: Padded<AtomicU32>,
    dropped: Padded<AtomicU64>,
    buf: [UnsafeCell<MaybeUninit<T>>; N],
}

// SAFETY: with exactly one producer and one consumer, slots are handed over
// with Release/Acquire ordering on the indices; `T: Copy + Send` means no
// drop glue or interior aliasing issues.
unsafe impl<T: Copy + Send, const N: usize> Sync for Spsc<T, N> {}

impl<T: Copy, const N: usize> Spsc<T, N> {
    pub const fn new() -> Self {
        assert!(N.is_power_of_two() && N <= (1 << 31));
        Spsc {
            head: Padded(AtomicU32::new(0)),
            tail: Padded(AtomicU32::new(0)),
            dropped: Padded(AtomicU64::new(0)),
            // SAFETY: an array of `UnsafeCell<MaybeUninit<_>>` needs no initialisation.
            buf: unsafe { MaybeUninit::<[UnsafeCell<MaybeUninit<T>>; N]>::uninit().assume_init() },
        }
    }

    /// Producer side. `None` = ring full (nothing written). `Some(was_empty)`
    /// tells the producer whether the consumer may be sleeping (wake it).
    pub fn try_push(&self, v: T) -> Option<bool> {
        let tail = self.tail.0.load(Ordering::Relaxed);
        let head = self.head.0.load(Ordering::Acquire);
        if tail.wrapping_sub(head) as usize >= N {
            return None;
        }
        // SAFETY: slot `tail & (N-1)` is not visible to the consumer until the
        // Release store below (it lies outside head..tail).
        unsafe { (*self.buf[tail as usize & (N - 1)].get()).write(v) };
        self.tail.0.store(tail.wrapping_add(1), Ordering::Release);
        Some(tail == head)
    }

    /// Non-blocking, lossy producer used by the audit log: counts drops.
    pub fn push_lossy(&self, v: T) -> bool {
        match self.try_push(v) {
            Some(_) => true,
            None => {
                self.dropped.0.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Consumer side. `Some((value, was_full))`; `was_full` means a blocked producer may need a wake-up.
    pub fn try_pop(&self) -> Option<(T, bool)> {
        let head = self.head.0.load(Ordering::Relaxed);
        let tail = self.tail.0.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        // SAFETY: slot `head & (N-1)` was published by the producer's Release
        // store of `tail` (observed with Acquire above) and is not reused until
        // we advance `head` below.
        let v = unsafe { (*self.buf[head as usize & (N - 1)].get()).assume_init_read() };
        self.head.0.store(head.wrapping_add(1), Ordering::Release);
        Some((v, tail.wrapping_sub(head) as usize >= N))
    }

    pub fn pop(&self) -> Option<T> {
        self.try_pop().map(|(v, _)| v)
    }

    pub fn len(&self) -> usize {
        let t = self.tail.0.load(Ordering::Acquire);
        let h = self.head.0.load(Ordering::Acquire);
        t.wrapping_sub(h) as usize
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn dropped(&self) -> u64 {
        self.dropped.0.load(Ordering::Relaxed)
    }
    pub fn head_val(&self) -> u32 {
        self.head.0.load(Ordering::Acquire)
    }
    pub fn tail_val(&self) -> u32 {
        self.tail.0.load(Ordering::Acquire)
    }
    pub fn is_full_at(&self, head: u32) -> bool {
        self.tail.0.load(Ordering::Acquire).wrapping_sub(head) as usize >= N
    }
    /// Address usable as a futex word (consumer sleeps on `tail`).
    pub fn tail_ptr(&self) -> *const u32 {
        self.tail.0.as_ptr() as *const u32
    }
    /// Address usable as a futex word (producer sleeps on `head`).
    pub fn head_ptr(&self) -> *const u32 {
        self.head.0.as_ptr() as *const u32
    }
}
