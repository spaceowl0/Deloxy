//! deloxy-de-apps: the built-in clients of the deloxy-de desktop (roles 10 = anim, 11 = diag, 12 = bars).
//! Each instance draws into its shared pixel buffer and talks to the compositor
//! only through the wm-protocol channel.
#![no_std]
#![no_main]

use core::arch::asm;

#[path = "../../../src/gfx/draw.rs"]
mod draw;
#[path = "../../../src/gfx/font.rs"]
mod font;
#[path = "../../../src/ipc/ring.rs"]
mod ring;
#[path = "../../../src/sys/abi.rs"]
mod abi;
#[path = "../../../src/wm/proto.rs"]
mod proto;

use abi::SysStats;
use draw::{rgb, Rect, Surface};
use proto::*;
use ring::Spsc;

type WmRing = Spsc<WmMsg, 32>;

#[repr(C)]
struct InitInfo {
    role: u64,
    n: u64,
    side: u64,
    handles: [u64; 5],
}

const SYS_EXIT: i64 = 0;
const SYS_SLEEP_MS: i64 = 2;
const SYS_WRITE_DEBUG: i64 = 3;
const SYS_TIME_NOW: i64 = 8;
const SYS_SHM_MAP: i64 = 14;
const SYS_STAT: i64 = 20;

#[inline(always)]
unsafe fn sc(nr: i64, a: u64, b: u64, c: u64) -> i64 {
    let ret: i64;
    asm!("syscall",
        inlateout("rax") nr => ret,
        in("rdi") a, in("rsi") b, in("rdx") c,
        lateout("rcx") _, lateout("r11") _,
        options(nostack));
    ret
}

fn exit(code: i64) -> ! {
    unsafe { sc(SYS_EXIT, code as u64, 0, 0) };
    loop {}
}

fn sleep_ms(ms: u64) {
    unsafe { sc(SYS_SLEEP_MS, ms, 0, 0) };
}

fn now_ms() -> u64 {
    unsafe { sc(SYS_TIME_NOW, 0, 0, 0) as u64 }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(255)
}

struct Line {
    b: [u8; 64],
    n: usize,
}

impl Line {
    fn new() -> Line {
        Line { b: [0; 64], n: 0 }
    }
    fn s(&mut self, t: &[u8]) -> &mut Line {
        for &c in t {
            if self.n < 64 {
                self.b[self.n] = c;
                self.n += 1;
            }
        }
        self
    }
    fn u(&mut self, mut v: u64) -> &mut Line {
        let mut tmp = [0u8; 20];
        let mut i = 20;
        if v == 0 {
            i -= 1;
            tmp[i] = b'0';
        }
        while v > 0 {
            i -= 1;
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        let t = tmp;
        self.s(&t[i..])
    }
    fn bytes(&self) -> &[u8] {
        &self.b[..self.n]
    }
}

struct Ctx {
    rx: &'static WmRing, // compositor -> me (ring page 1)
    tx: &'static WmRing, // me -> compositor (ring page 0)
    buf: *mut u32,
    w: i32,
    h: i32,
    focused: bool,
    last_key: u8,
    px: i32,
    py: i32,
    clicks: u32,
    close: bool,
}

impl Ctx {
    fn surface(&self) -> Surface<'static> {
        // SAFETY: `buf` is the mapped shared pixel buffer of w*h u32s, valid for the process lifetime.
        let s = unsafe { core::slice::from_raw_parts_mut(self.buf, (self.w * self.h) as usize) };
        Surface::new(s, self.w, self.h, self.w)
    }

    fn poll(&mut self) {
        while let Some((m, _)) = self.rx.try_pop() {
            match m.kind {
                S_CONFIGURE => self.focused = m.c != 0,
                S_FOCUS => self.focused = m.a != 0,
                S_KEY => {
                    if m.c == 1 && m.a != 0 {
                        self.last_key = m.a as u8;
                    }
                }
                S_POINTER => {
                    self.px = m.a;
                    self.py = m.b;
                    if m.d == 1 {
                        self.clicks += 1;
                    }
                }
                S_CLOSE => self.close = true,
                _ => {}
            }
        }
    }

    fn commit(&self) {
        let _ = self.tx.try_push(WmMsg::new(C_COMMIT, 0, 0, 0, self.w, self.h));
    }

    fn set_title(&self, t: &[u8]) {
        let mut m = WmMsg::new(C_TITLE, 0, 0, 0, 0, 0);
        // SAFETY: `pad` is 40 plain bytes.
        let dst = unsafe { core::slice::from_raw_parts_mut(m.pad.as_mut_ptr() as *mut u8, 40) };
        let n = t.len().min(39);
        dst[..n].copy_from_slice(&t[..n]);
        let _ = self.tx.try_push(m);
    }
}

#[no_mangle]
#[link_section = ".text._start"]
pub unsafe extern "C" fn _start(info: *const InitInfo) -> ! {
    let info = &*info;
    let chan = sc(SYS_SHM_MAP, info.handles[0], 0, 0);
    let pix = sc(SYS_SHM_MAP, info.handles[1], 0, 0);
    if chan < 0 || pix < 0 {
        exit(1);
    }
    let mut ctx = Ctx {
        rx: &*((chan as u64 + 4096) as *const WmRing),
        tx: &*(chan as u64 as *const WmRing),
        buf: pix as *mut u32,
        w: (info.n >> 16) as i32,
        h: (info.n & 0xFFFF) as i32,
        focused: false,
        last_key: 0,
        px: -1,
        py: -1,
        clicks: 0,
        close: false,
    };
    match info.role {
        10 => anim(&mut ctx),
        11 => diag(&mut ctx),
        12 => bars(&mut ctx),
        _ => exit(250),
    }
}

fn anim(ctx: &mut Ctx) -> ! {
    ctx.set_title(b"anim");
    let (mut x, mut y, mut vx, mut vy) = (20i32, 30i32, 4i32, 3i32);
    let mut t: u32 = 0;
    loop {
        ctx.poll();
        if ctx.close {
            exit(0);
        }
        x += vx;
        y += vy;
        if x < 0 || x > ctx.w - 28 {
            vx = -vx;
            x += 2 * vx;
        }
        if y < 20 || y > ctx.h - 28 {
            vy = -vy;
            y += 2 * vy;
        }
        let mut s = ctx.surface();
        s.fill_rect(Rect::new(0, 0, ctx.w, ctx.h), rgb(18, 24, 38));
        for gx in (0..ctx.w).step_by(40) {
            s.fill_rect(Rect::new(gx, 0, 1, ctx.h), rgb(28, 36, 54));
        }
        for gy in (0..ctx.h).step_by(40) {
            s.fill_rect(Rect::new(0, gy, ctx.w, 1), rgb(28, 36, 54));
        }
        let c = rgb((t * 3 & 255) as u8, (128 + (t * 5 & 127)) as u8, (255 - (t * 2 & 255)) as u8);
        s.fill_rect(Rect::new(x, y, 28, 28), c);
        s.rect_outline(Rect::new(x, y, 28, 28), rgb(255, 255, 255));
        let mut l = Line::new();
        l.s(b"frame ").u(t as u64);
        s.draw_text(8, 4, l.bytes(), rgb(200, 210, 225), None);
        ctx.commit();
        t = t.wrapping_add(1);
        sleep_ms(33);
    }
}

fn bars(ctx: &mut Ctx) -> ! {
    ctx.set_title(b"bars");
    const PAL: [u32; 6] = [
        rgb(231, 76, 60),
        rgb(243, 156, 18),
        rgb(241, 196, 15),
        rgb(46, 204, 113),
        rgb(52, 152, 219),
        rgb(155, 89, 182),
    ];
    let mut t: i32 = 0;
    loop {
        ctx.poll();
        if ctx.close {
            exit(0);
        }
        let mut s = ctx.surface();
        s.fill_rect(Rect::new(0, 0, ctx.w, ctx.h), rgb(20, 20, 24));
        let off = (t * 3) % 24;
        for i in 0..(ctx.w / 24 + 2) {
            let col = PAL[((i + t / 8) as usize) % 6];
            s.fill_rect(Rect::new(i * 24 - off, 24, 24, ctx.h - 48), col);
        }
        let mut l = Line::new();
        l.s(b"clicks ").u(ctx.clicks as u64);
        s.draw_text(8, 4, l.bytes(), rgb(220, 220, 230), None);
        ctx.commit();
        t = t.wrapping_add(1);
        sleep_ms(33);
    }
}

fn diag(ctx: &mut Ctx) -> ! {
    ctx.set_title(b"diag");
    let mut st = SysStats::default();
    let mut last_log = 0u64;
    loop {
        ctx.poll();
        if ctx.close {
            exit(0);
        }
        unsafe { sc(SYS_STAT, &mut st as *mut SysStats as u64, 0, 0) };
        let mut s = ctx.surface();
        s.fill_rect(Rect::new(0, 0, ctx.w, ctx.h), rgb(14, 18, 24));
        let fg = rgb(190, 235, 200);
        let dim = rgb(130, 150, 165);
        let mut y = 8;
        let rows: [(&[u8], u64, &[u8]); 7] = [
            (b"uptime        ", st.uptime_ms / 1000, b" s"),
            (b"free frames   ", st.frames_free, b""),
            (b"total frames  ", st.frames_total, b""),
            (b"heap used     ", st.heap_used / 1024, b" KiB"),
            (b"ctx switches  ", st.ctx_switches, b""),
            (b"audit dropped ", st.audit_dropped, b""),
            (b"screen width  ", st.screen_w, b" px"),
        ];
        for (label, v, unit) in rows.iter() {
            let mut l = Line::new();
            l.s(label).u(*v).s(unit);
            s.draw_text(10, y, l.bytes(), fg, None);
            y += 18;
        }
        y += 8;
        let mut l = Line::new();
        l.s(b"last key: ");
        if ctx.last_key >= 32 && ctx.last_key < 127 {
            l.s(&[b'\'', ctx.last_key, b'\'']);
        } else {
            l.s(b"-");
        }
        s.draw_text(10, y, l.bytes(), rgb(255, 214, 120), None);
        y += 18;
        let mut l = Line::new();
        l.s(b"pointer: ");
        if ctx.px >= 0 {
            l.u(ctx.px as u64).s(b",").u(ctx.py as u64);
        } else {
            l.s(b"outside");
        }
        l.s(b"  clicks ").u(ctx.clicks as u64);
        s.draw_text(10, y, l.bytes(), rgb(255, 214, 120), None);
        s.draw_text(10, ctx.h - 20, if ctx.focused { b"focused" } else { b"unfocused" }, dim, None);
        ctx.commit();

        let now = now_ms();
        if now - last_log >= 3000 {
            last_log = now;
            let mut l = Line::new();
            l.s(b"diag: up=").u(st.uptime_ms / 1000).s(b"s free=").u(st.frames_free).s(b" heap=").u(st.heap_used / 1024).s(b"K\n");
            unsafe { sc(SYS_WRITE_DEBUG, l.bytes().as_ptr() as u64, l.n as u64, 0) };
        }
        sleep_ms(100);
    }
}
