//! i8042 PS/2 controller, keyboard (scancode set 1 via controller translation) and mouse.

use x86_64::instructions::port::Port;

use super::{push, InputEvent, EV_KEY, EV_MOUSE_BUTTON, EV_MOUSE_MOVE};
use crate::sync::IrqMutex;

const DATA: u16 = 0x60;
const STATUS_CMD: u16 = 0x64;

fn status() -> u8 {
    // SAFETY: 0x64 is the i8042 status register; reading has no side effects.
    unsafe { Port::<u8>::new(STATUS_CMD).read() }
}

fn wait_write() -> bool {
    for _ in 0..200_000 {
        if status() & 0x02 == 0 {
            return true;
        }
    }
    false
}

fn wait_read() -> bool {
    for _ in 0..200_000 {
        if status() & 0x01 != 0 {
            return true;
        }
    }
    false
}

fn cmd(c: u8) -> bool {
    if !wait_write() {
        return false;
    }
    // SAFETY: i8042 command port; `c` is a documented controller command.
    unsafe { Port::<u8>::new(STATUS_CMD).write(c) };
    true
}

fn write_data(d: u8) -> bool {
    if !wait_write() {
        return false;
    }
    // SAFETY: i8042 data port.
    unsafe { Port::<u8>::new(DATA).write(d) };
    true
}

fn read_data() -> Option<u8> {
    if !wait_read() {
        return None;
    }
    // SAFETY: i8042 data port; a byte is available (status bit 0).
    Some(unsafe { Port::<u8>::new(DATA).read() })
}

fn flush() {
    for _ in 0..64 {
        if status() & 1 == 0 {
            break;
        }
        // SAFETY: draining the output buffer.
        unsafe { Port::<u8>::new(DATA).read() };
    }
}

/// Send a byte to the mouse (via the controller) and expect ACK (0xFA).
fn mouse_cmd(b: u8) -> bool {
    cmd(0xD4) && write_data(b) && read_data() == Some(0xFA)
}

pub struct InitResult {
    pub keyboard: bool,
    pub mouse: bool,
}

/// Initialise the controller and devices. IRQs stay masked in the controller until the end.
pub fn init() -> Result<InitResult, &'static str> {
    if !cmd(0xAD) || !cmd(0xA7) {
        return Err("i8042 not responding");
    }
    flush();
    if !cmd(0x20) {
        return Err("config read failed");
    }
    let mut cfg = read_data().ok_or("config read timeout")?;
    cfg &= !0b0000_0011; // IRQs off while we talk to the devices
    if !cmd(0x60) || !write_data(cfg) {
        return Err("config write failed");
    }
    if !cmd(0xAA) || read_data() != Some(0x55) {
        return Err("controller self-test failed");
    }
    // the self-test may reset the config on some controllers: write it again
    if !cmd(0x60) || !write_data(cfg) {
        return Err("config rewrite failed");
    }

    let keyboard = cmd(0xAE) && write_data(0xF4) && read_data() == Some(0xFA);
    let mouse = cmd(0xA8) && mouse_cmd(0xF6) && mouse_cmd(0xF4);
    flush();

    if !cmd(0x20) {
        return Err("config read failed");
    }
    let mut cfg = read_data().ok_or("config read timeout")?;
    if keyboard {
        cfg |= 0b01;
    }
    if mouse {
        cfg |= 0b10;
    }
    if !cmd(0x60) || !write_data(cfg) {
        return Err("config write failed");
    }
    Ok(InitResult { keyboard, mouse })
}

// ----------------------------------------------------------- keyboard -------

const LOWER: &[u8; 0x3A] = b"\0\x1b1234567890-=\x08\tqwertyuiop[]\n\0asdfghjkl;'`\0\\zxcvbnm,./\0*\0 ";
const UPPER: &[u8; 0x3A] = b"\0\x1b!@#$%^&*()_+\x08\tQWERTYUIOP{}\n\0ASDFGHJKL:\"~\0|ZXCVBNM<>?\0*\0 ";

struct Kbd {
    extended: bool,
    shift: bool,
    ctrl: bool,
    alt: bool,
    sup: bool,
    caps: bool,
}

static KBD: IrqMutex<Kbd> = IrqMutex::new(Kbd { extended: false, shift: false, ctrl: false, alt: false, sup: false, caps: false });

/// IRQ1 body: read and decode one scancode.
pub fn kbd_irq() {
    crate::rand::add_event(1);
    // SAFETY: IRQ1 fired, so a byte is waiting in the i8042 output buffer.
    let sc = unsafe { Port::<u8>::new(DATA).read() };
    let mut k = KBD.lock();
    if sc == 0xE0 {
        k.extended = true;
        return;
    }
    let pressed = sc & 0x80 == 0;
    let ext = core::mem::take(&mut k.extended);
    decode(&mut k, ext, sc & 0x7F, pressed);
}

/// Feed a key event from another source (USB HID) through the same modifier tracking / ASCII translation.
/// `code` is the PS/2 set-1 scancode (without the 0x80 release bit). Safe from thread context (IrqMutex).
pub fn inject_key(ext: bool, code: u8, pressed: bool) {
    let mut k = KBD.lock();
    decode(&mut k, ext, code & 0x7F, pressed);
}

fn decode(k: &mut Kbd, ext: bool, code: u8, pressed: bool) {
    let code = code as usize;
    match (ext, code) {
        (false, 0x2A) | (false, 0x36) => k.shift = pressed,
        (false, 0x1D) | (true, 0x1D) => k.ctrl = pressed,
        (false, 0x38) | (true, 0x38) => k.alt = pressed,
        (true, 0x5B) | (true, 0x5C) => k.sup = pressed,
        (false, 0x3A) if pressed => k.caps = !k.caps,
        _ => {}
    }
    let mut ascii = 0u8;
    if pressed && !ext && code < 0x3A {
        let mut c = if k.shift { UPPER[code] } else { LOWER[code] };
        if k.caps && c.is_ascii_alphabetic() {
            c = if k.shift { c.to_ascii_lowercase() } else { c.to_ascii_uppercase() };
        }
        if k.ctrl && c.is_ascii_alphabetic() {
            c &= 0x1F;
        }
        ascii = c;
    }
    push(InputEvent {
        kind: EV_KEY,
        code: code as u16 | if ext { 0x100 } else { 0 },
        value: pressed as i32,
        x: ascii as i32,
        // modifier bits for consumers: 1 shift, 2 ctrl, 4 alt, 8 super
        y: (k.shift as i32) | (k.ctrl as i32) << 1 | (k.alt as i32) << 2 | (k.sup as i32) << 3,
    });
}

// -------------------------------------------------------------- mouse -------

struct Mouse {
    packet: [u8; 3],
    idx: usize,
    buttons: u8,
}

static MOUSE: IrqMutex<Mouse> = IrqMutex::new(Mouse { packet: [0; 3], idx: 0, buttons: 0 });

/// IRQ12 body: assemble 3-byte packets.
pub fn mouse_irq() {
    crate::rand::add_event(2);
    // SAFETY: IRQ12 fired, so a mouse byte is waiting in the output buffer.
    let b = unsafe { Port::<u8>::new(DATA).read() };
    let mut m = MOUSE.lock();
    if m.idx == 0 && b & 0x08 == 0 {
        return; // out of sync: first byte always has bit 3 set
    }
    let i = m.idx;
    m.packet[i] = b;
    m.idx += 1;
    if m.idx < 3 {
        return;
    }
    m.idx = 0;
    let [flags, rx, ry] = m.packet;
    if flags & 0xC0 != 0 {
        return; // overflow: discard packet
    }
    let dx = rx as i32 - if flags & 0x10 != 0 { 256 } else { 0 };
    let dy = ry as i32 - if flags & 0x20 != 0 { 256 } else { 0 };
    if dx != 0 || dy != 0 {
        push(InputEvent { kind: EV_MOUSE_MOVE, code: 0, value: 0, x: dx, y: -dy });
    }
    let now = flags & 0x07;
    let changed = now ^ m.buttons;
    for bit in 0..3u8 {
        if changed & (1 << bit) != 0 {
            push(InputEvent { kind: EV_MOUSE_BUTTON, code: bit as u16, value: ((now >> bit) & 1) as i32, x: 0, y: 0 });
        }
    }
    m.buttons = now;
}
