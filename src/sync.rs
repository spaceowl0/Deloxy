//! Interrupt-safe spinlock.
//!
//! On a single core a plain spinlock deadlocks if an interrupt handler (or a
//! preemptive context switch) tries to take a lock the interrupted code holds.
//! `IrqMutex` disables interrupts while held and restores the previous state
//! when the guard drops.

use core::ops::{Deref, DerefMut};

use spin::{Mutex, MutexGuard};
use x86_64::instructions::interrupts;

pub struct IrqMutex<T> {
    inner: Mutex<T>,
}

pub struct IrqGuard<'a, T> {
    guard: Option<MutexGuard<'a, T>>,
    restore_if: bool,
}

impl<T> IrqMutex<T> {
    pub const fn new(value: T) -> Self {
        Self { inner: Mutex::new(value) }
    }

    pub fn lock(&self) -> IrqGuard<'_, T> {
        let was_enabled = interrupts::are_enabled();
        interrupts::disable();
        IrqGuard { guard: Some(self.inner.lock()), restore_if: was_enabled }
    }

    /// Take the lock if it is free (never spins); for paths that must not block.
    pub fn try_lock(&self) -> Option<IrqGuard<'_, T>> {
        let was_enabled = interrupts::are_enabled();
        interrupts::disable();
        match self.inner.try_lock() {
            Some(g) => Some(IrqGuard { guard: Some(g), restore_if: was_enabled }),
            None => {
                if was_enabled {
                    interrupts::enable();
                }
                None
            }
        }
    }

    /// Forcibly unlock. Only for fatal paths (panic / CPU exception) that never resume.
    ///
    /// # Safety
    /// The caller must guarantee the previous holder can never run again.
    pub unsafe fn force_unlock(&self) {
        self.inner.force_unlock();
    }
}

impl<T> Deref for IrqGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.guard.as_ref().unwrap()
    }
}

impl<T> DerefMut for IrqGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.guard.as_mut().unwrap()
    }
}

impl<T> Drop for IrqGuard<'_, T> {
    fn drop(&mut self) {
        // Release the lock first, then (maybe) re-enable interrupts.
        self.guard.take();
        if self.restore_if {
            interrupts::enable();
        }
    }
}
