//! Shared-memory objects (physical frames that can be mapped into several processes).

use alloc::sync::Arc;
use alloc::vec::Vec;

use x86_64::structures::paging::PhysFrame;

use crate::mm::{frame, vmm};

pub struct MemObject {
    frames: Vec<PhysFrame>,
}

impl MemObject {
    /// Allocate `pages` zeroed frames.
    pub fn new(pages: usize) -> Option<Arc<MemObject>> {
        let mut frames = Vec::with_capacity(pages);
        for _ in 0..pages {
            match frame::allocate_frame() {
                Some(f) => {
                    vmm::zero_frame(f);
                    frames.push(f);
                }
                None => {
                    for f in frames {
                        frame::deallocate_frame(f);
                    }
                    return None;
                }
            }
        }
        Some(Arc::new(MemObject { frames }))
    }

    pub fn frames(&self) -> &[PhysFrame] {
        &self.frames
    }
    pub fn pages(&self) -> usize {
        self.frames.len()
    }
}

impl Drop for MemObject {
    fn drop(&mut self) {
        for &f in &self.frames {
            frame::deallocate_frame(f);
        }
    }
}
