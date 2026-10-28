//! Linear framebuffer (from Limine) and a mirrored boot text console.

pub mod console;

use crate::sync::IrqMutex;

#[derive(Clone, Copy, Debug)]
pub struct FbInfo {
    /// Virtual address (Limine maps the framebuffer in the HHDM).
    pub addr: usize,
    pub width: usize,
    pub height: usize,
    pub pitch: usize,
    pub bpp: u16,
    pub r_shift: u8,
    pub g_shift: u8,
    pub b_shift: u8,
}

static FB: IrqMutex<Option<FbInfo>> = IrqMutex::new(None);

pub fn set(info: FbInfo) {
    *FB.lock() = Some(info);
}

pub fn info() -> Option<FbInfo> {
    *FB.lock()
}

impl FbInfo {
    #[inline]
    pub fn pack(&self, rgb: u32) -> u32 {
        let r = (rgb >> 16) & 0xFF;
        let g = (rgb >> 8) & 0xFF;
        let b = rgb & 0xFF;
        (r << self.r_shift) | (g << self.g_shift) | (b << self.b_shift)
    }

    fn is_xrgb(&self) -> bool {
        self.r_shift == 16 && self.g_shift == 8 && self.b_shift == 0
    }

    /// Copy a rectangle of a `0x00RRGGBB` back buffer to the screen.
    ///
    /// # Safety
    /// `rect` must lie inside both the back buffer (`stride` u32s per row) and the screen.
    pub unsafe fn present(&self, back: &[u32], stride: usize, x: usize, y: usize, w: usize, h: usize) {
        for row in y..y + h {
            let src = back.as_ptr().add(row * stride + x);
            let dst = (self.addr + row * self.pitch + x * 4) as *mut u32;
            if self.is_xrgb() {
                core::ptr::copy_nonoverlapping(src, dst, w);
            } else {
                for i in 0..w {
                    dst.add(i).write(self.pack(*src.add(i)));
                }
            }
        }
    }

    /// Fill a rectangle directly on screen.
    ///
    /// # Safety
    /// `rect` must lie inside the screen.
    pub unsafe fn fill(&self, x: usize, y: usize, w: usize, h: usize, rgb: u32) {
        let c = self.pack(rgb);
        for row in y..y + h {
            let dst = (self.addr + row * self.pitch + x * 4) as *mut u32;
            for i in 0..w {
                dst.add(i).write(c);
            }
        }
    }
}
