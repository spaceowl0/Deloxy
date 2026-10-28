//! Software 2D drawing on XRGB8888 buffers (`0x00RRGGBB`). `no_std`, dependency-free,
//! compiled into both the kernel compositor and user programs.

use super::font::{FONT8X16, GLYPH_H, GLYPH_W};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Rect {
        Rect { x, y, w, h }
    }
    pub const fn right(&self) -> i32 {
        self.x + self.w
    }
    pub const fn bottom(&self) -> i32 {
        self.y + self.h
    }
    pub const fn is_empty(&self) -> bool {
        self.w <= 0 || self.h <= 0
    }
    pub fn intersect(&self, o: &Rect) -> Rect {
        let x = self.x.max(o.x);
        let y = self.y.max(o.y);
        let r = self.right().min(o.right());
        let b = self.bottom().min(o.bottom());
        if r <= x || b <= y {
            Rect::new(0, 0, 0, 0)
        } else {
            Rect::new(x, y, r - x, b - y)
        }
    }
    pub fn union(&self, o: &Rect) -> Rect {
        if self.is_empty() {
            return *o;
        }
        if o.is_empty() {
            return *self;
        }
        let x = self.x.min(o.x);
        let y = self.y.min(o.y);
        let r = self.right().max(o.right());
        let b = self.bottom().max(o.bottom());
        Rect::new(x, y, r - x, b - y)
    }
    pub fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x && py >= self.y && px < self.right() && py < self.bottom()
    }
}

pub const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    ((r as u32) << 16) | ((g as u32) << 8) | b as u32
}

/// Linear mix of two XRGB colours: `t` = 0 -> `a`, 255 -> `b`.
pub const fn mix(a: u32, b: u32, t: u32) -> u32 {
    let t = if t > 255 { 255 } else { t };
    let it = 255 - t;
    let r = (((a >> 16) & 0xFF) * it + ((b >> 16) & 0xFF) * t) / 255;
    let g = (((a >> 8) & 0xFF) * it + ((b >> 8) & 0xFF) * t) / 255;
    let bl = ((a & 0xFF) * it + (b & 0xFF) * t) / 255;
    (r << 16) | (g << 8) | bl
}

fn isqrt(n: u32) -> u32 {
    let mut x = 0u32;
    let mut bit = 1u32 << 30;
    let mut n = n;
    while bit > n {
        bit >>= 2;
    }
    while bit != 0 {
        if n >= x + bit {
            n -= x + bit;
            x = (x >> 1) + bit;
        } else {
            x >>= 1;
        }
        bit >>= 2;
    }
    x
}

/// Horizontal inset (in 1/16 px) of a circular corner of radius `r` at row `i` (0 = outermost row).
fn corner_inset16(r: i32, i: i32) -> i32 {
    if i >= r {
        return 0;
    }
    let dy = r * 16 - (i * 16 + 8);
    let rr = (r * 16) as u32;
    let sq = (rr * rr).saturating_sub((dy * dy) as u32);
    r * 16 - isqrt(sq) as i32
}

pub struct Surface<'a> {
    pub buf: &'a mut [u32],
    pub w: i32,
    pub h: i32,
    pub stride: i32,
    pub clip: Rect,
}

impl<'a> Surface<'a> {
    pub fn new(buf: &'a mut [u32], w: i32, h: i32, stride: i32) -> Surface<'a> {
        debug_assert!(buf.len() >= (stride * h) as usize);
        Surface { buf, w, h, stride, clip: Rect::new(0, 0, w, h) }
    }

    pub fn set_clip(&mut self, r: Rect) {
        self.clip = r.intersect(&Rect::new(0, 0, self.w, self.h));
    }

    pub fn fill_rect(&mut self, r: Rect, color: u32) {
        let r = r.intersect(&self.clip);
        if r.is_empty() {
            return;
        }
        for y in r.y..r.bottom() {
            let row = (y * self.stride) as usize;
            self.buf[row + r.x as usize..row + r.right() as usize].fill(color);
        }
    }

    pub fn put(&mut self, x: i32, y: i32, color: u32) {
        if self.clip.contains(x, y) {
            self.buf[(y * self.stride + x) as usize] = color;
        }
    }

    pub fn rect_outline(&mut self, r: Rect, color: u32) {
        self.fill_rect(Rect::new(r.x, r.y, r.w, 1), color);
        self.fill_rect(Rect::new(r.x, r.bottom() - 1, r.w, 1), color);
        self.fill_rect(Rect::new(r.x, r.y, 1, r.h), color);
        self.fill_rect(Rect::new(r.right() - 1, r.y, 1, r.h), color);
    }

    pub fn draw_char(&mut self, x: i32, y: i32, ch: u8, fg: u32, bg: Option<u32>) {
        let cell = Rect::new(x, y, GLYPH_W as i32, GLYPH_H as i32);
        if cell.intersect(&self.clip).is_empty() {
            return;
        }
        let glyph = if (32..=126).contains(&ch) { &FONT8X16[(ch - 32) as usize] } else { &FONT8X16[(b'?' - 32) as usize] };
        for (row, bits) in glyph.iter().enumerate() {
            let py = y + row as i32;
            for col in 0..GLYPH_W as i32 {
                if bits & (0x80 >> col) != 0 {
                    self.put(x + col, py, fg);
                } else if let Some(b) = bg {
                    self.put(x + col, py, b);
                }
            }
        }
    }

    /// Draw ASCII text; returns the x coordinate after the last glyph.
    pub fn draw_text(&mut self, x: i32, y: i32, text: &[u8], fg: u32, bg: Option<u32>) -> i32 {
        let mut cx = x;
        for &c in text {
            self.draw_char(cx, y, c, fg, bg);
            cx += GLYPH_W as i32;
        }
        cx
    }

    /// Copy `src_rect` of `src` (stride `sstride`) to (dx, dy), clipped to this surface's clip.
    pub fn blit(&mut self, dx: i32, dy: i32, src: &[u32], sw: i32, sh: i32, sstride: i32, src_rect: Rect) {
        let src_rect = src_rect.intersect(&Rect::new(0, 0, sw, sh));
        let dst = Rect::new(dx, dy, src_rect.w, src_rect.h).intersect(&self.clip);
        if dst.is_empty() {
            return;
        }
        let sx0 = src_rect.x + (dst.x - dx);
        let sy0 = src_rect.y + (dst.y - dy);
        for row in 0..dst.h {
            let s = ((sy0 + row) * sstride + sx0) as usize;
            let d = ((dst.y + row) * self.stride + dst.x) as usize;
            self.buf[d..d + dst.w as usize].copy_from_slice(&src[s..s + dst.w as usize]);
        }
    }

    /// Alpha-blend one pixel (`a` 0..=255 = opacity of `color`).
    pub fn blend_px(&mut self, x: i32, y: i32, color: u32, a: u32) {
        if a == 0 || !self.clip.contains(x, y) {
            return;
        }
        let i = (y * self.stride + x) as usize;
        self.buf[i] = if a >= 255 { color } else { mix(self.buf[i], color, a) };
    }

    pub fn fill_rect_alpha(&mut self, r: Rect, color: u32, a: u32) {
        let r = r.intersect(&self.clip);
        if r.is_empty() || a == 0 {
            return;
        }
        for y in r.y..r.bottom() {
            let row = (y * self.stride) as usize;
            for px in &mut self.buf[row + r.x as usize..row + r.right() as usize] {
                *px = if a >= 255 { color } else { mix(*px, color, a) };
            }
        }
    }

    /// Vertical gradient from `top` (first row of `r`) to `bottom` (last row).
    pub fn vgradient(&mut self, r: Rect, top: u32, bottom: u32) {
        let c = r.intersect(&self.clip);
        if c.is_empty() {
            return;
        }
        let den = (r.h - 1).max(1);
        for y in c.y..c.bottom() {
            let t = ((y - r.y) * 255 / den) as u32;
            self.fill_rect(Rect::new(c.x, y, c.w, 1), mix(top, bottom, t));
        }
    }

    fn round_rows(&mut self, r: Rect, radius: i32, color: u32, color2: u32, top: bool, bottom: bool, a: u32) {
        let rad = radius.min(r.w / 2).min(r.h / 2).max(0);
        for i in 0..r.h {
            let y = r.y + i;
            let color = if color == color2 { color } else { mix(color, color2, (i * 255 / (r.h - 1).max(1)) as u32) };
            let from_bottom = r.h - 1 - i;
            let inset16 = if top && i < rad {
                corner_inset16(rad, i)
            } else if bottom && from_bottom < rad {
                corner_inset16(rad, from_bottom)
            } else {
                0
            };
            let full = (inset16 + 15) / 16; // first fully covered column
            let frac = inset16 % 16;
            let x0 = r.x + full;
            self.fill_rect_alpha(Rect::new(x0, y, r.w - 2 * full, 1), color, a);
            if frac != 0 {
                let cov = (a * (16 - frac) as u32) / 16;
                self.blend_px(r.x + full - 1, y, color, cov);
                self.blend_px(r.right() - full, y, color, cov);
            }
        }
    }

    /// Filled rectangle with anti-aliased rounded corners.
    pub fn fill_round(&mut self, r: Rect, radius: i32, color: u32) {
        self.round_rows(r, radius, color, color, true, true, 255);
    }
    /// Only the two top corners are rounded.
    pub fn fill_round_top(&mut self, r: Rect, radius: i32, color: u32) {
        self.round_rows(r, radius, color, color, true, false, 255);
    }
    pub fn fill_round_top_gradient(&mut self, r: Rect, radius: i32, top: u32, bottom: u32) {
        self.round_rows(r, radius, top, bottom, true, false, 255);
    }
    pub fn fill_round_gradient(&mut self, r: Rect, radius: i32, top: u32, bottom: u32) {
        self.round_rows(r, radius, top, bottom, true, true, 255);
    }
    pub fn fill_round_alpha(&mut self, r: Rect, radius: i32, color: u32, a: u32) {
        self.round_rows(r, radius, color, color, true, true, a);
    }

    /// Soft drop shadow around `r` (drawn as nested rings, so it must be painted BEFORE the window itself).
    pub fn shadow(&mut self, r: Rect, spread: i32, dy: i32, strength: u32) {
        for i in 1..=spread {
            let a = strength * ((spread - i + 1) * (spread - i + 1)) as u32 / (spread * spread) as u32;
            let o = Rect::new(r.x - i, r.y - i + dy, r.w + 2 * i, r.h + 2 * i);
            self.fill_rect_alpha(Rect::new(o.x, o.y, o.w, 1), 0, a);
            self.fill_rect_alpha(Rect::new(o.x, o.bottom() - 1, o.w, 1), 0, a);
            self.fill_rect_alpha(Rect::new(o.x, o.y + 1, 1, o.h - 2), 0, a);
            self.fill_rect_alpha(Rect::new(o.right() - 1, o.y + 1, 1, o.h - 2), 0, a);
        }
    }

    pub fn text_width(len: usize) -> i32 {
        len as i32 * GLYPH_W as i32
    }

    /// Text centred in `r` (single line).
    pub fn draw_text_centered(&mut self, r: Rect, text: &[u8], fg: u32) {
        let w = Self::text_width(text.len());
        self.draw_text(r.x + (r.w - w) / 2, r.y + (r.h - GLYPH_H as i32) / 2, text, fg, None);
    }
}
