//! Text console drawn straight onto the framebuffer; mirrors the serial log so the
//! boot banner and kernel messages are visible on screen. Handles the ANSI colour
//! sequences the logger emits. Disabled when the compositor takes over.

use super::{info, FbInfo};
use crate::gfx::font::{FONT8X16, GLYPH_H, GLYPH_W};
use crate::sync::IrqMutex;

const DEFAULT_FG: u32 = 0x00C8C8C8;
const BG: u32 = 0x000A0F14;

struct Console {
    fb: Option<FbInfo>,
    col: usize,
    row: usize,
    cols: usize,
    rows: usize,
    fg: u32,
    esc: u8,      // 0 none, 1 saw ESC, 2 inside CSI
    param: u16,   // current numeric parameter
    enabled: bool,
}

static CONSOLE: IrqMutex<Console> = IrqMutex::new(Console {
    fb: None,
    col: 0,
    row: 0,
    cols: 0,
    rows: 0,
    fg: DEFAULT_FG,
    esc: 0,
    param: 0,
    enabled: false,
});

pub fn init() {
    let Some(fb) = info() else { return };
    let mut c = CONSOLE.lock();
    c.cols = fb.width / GLYPH_W;
    c.rows = fb.height / GLYPH_H;
    c.fb = Some(fb);
    // SAFETY: the rectangle is exactly the screen.
    unsafe { fb.fill(0, 0, fb.width, fb.height, BG) };
    c.enabled = true;
}

/// Stop drawing (the compositor now owns the screen).
pub fn disable() {
    CONSOLE.lock().enabled = false;
}

pub fn write_str(s: &str) {
    let mut c = CONSOLE.lock();
    if !c.enabled {
        return;
    }
    for b in s.bytes() {
        c.put_byte(b);
    }
}

impl Console {
    fn put_byte(&mut self, b: u8) {
        match self.esc {
            1 => {
                self.esc = if b == b'[' { 2 } else { 0 };
                self.param = 0;
                return;
            }
            2 => {
                match b {
                    b'0'..=b'9' => self.param = self.param * 10 + (b - b'0') as u16,
                    b';' => self.param = 0,
                    b'm' => {
                        self.fg = match self.param {
                            31 => 0x00FF5555,
                            32 => 0x0055FF7F,
                            33 => 0x00FFD75F,
                            36 => 0x0055D7FF,
                            90 => 0x00808080,
                            _ => DEFAULT_FG,
                        };
                        self.esc = 0;
                    }
                    _ => self.esc = 0,
                }
                return;
            }
            _ => {}
        }
        match b {
            0x1B => self.esc = 1,
            b'\r' => self.col = 0,
            b'\n' => self.newline(),
            b'\t' => self.col = (self.col + 4) & !3,
            0x20..=0x7E => {
                if self.col >= self.cols {
                    self.newline();
                }
                self.glyph(self.col, self.row, b);
                self.col += 1;
            }
            _ => {}
        }
    }

    fn newline(&mut self) {
        self.col = 0;
        if self.row + 1 >= self.rows {
            self.scroll();
        } else {
            self.row += 1;
        }
    }

    fn scroll(&mut self) {
        let Some(fb) = self.fb else { return };
        let line = GLYPH_H * fb.pitch;
        // SAFETY: both ranges lie inside the framebuffer (rows*GLYPH_H <= height).
        unsafe {
            core::ptr::copy((fb.addr + line) as *const u8, fb.addr as *mut u8, (self.rows - 1) * line);
            fb.fill(0, (self.rows - 1) * GLYPH_H, fb.width, GLYPH_H, BG);
        }
    }

    fn glyph(&self, col: usize, row: usize, ch: u8) {
        let Some(fb) = self.fb else { return };
        let g = &FONT8X16[(ch - 32) as usize];
        let (fgp, bgp) = (fb.pack(self.fg), fb.pack(BG));
        let x0 = col * GLYPH_W;
        let y0 = row * GLYPH_H;
        for (r, bits) in g.iter().enumerate() {
            let dst = (fb.addr + (y0 + r) * fb.pitch + x0 * 4) as *mut u32;
            for c in 0..GLYPH_W {
                // SAFETY: (x0+c, y0+r) is inside the screen because col < cols, row < rows.
                unsafe { dst.add(c).write(if bits & (0x80 >> c) != 0 { fgp } else { bgp }) };
            }
        }
    }
}
