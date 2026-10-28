//! HID helpers: usage -> scancode translation, boot keyboard report diffing, and a small report-descriptor parser for
//! pointing devices (mice report relative motion, tablets absolute).

use alloc::vec::Vec;

use crate::drivers::input::{self, InputEvent, EV_MOUSE_ABS, EV_MOUSE_BUTTON, EV_MOUSE_MOVE};

/// USB HID keyboard usage (page 7) -> PS/2 set-1 scancode; bit 8 set = extended (E0) prefix. 0 = no mapping.
pub fn usage_to_scancode(u: u8) -> u16 {
    const LETTERS: [u8; 26] = [
        0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
    ];
    match u {
        0x04..=0x1D => LETTERS[(u - 4) as usize] as u16,
        0x1E..=0x26 => (u - 0x1E + 2) as u16, // 1..9
        0x27 => 0x0B,                         // 0
        0x28 => 0x1C,
        0x29 => 0x01,
        0x2A => 0x0E,
        0x2B => 0x0F,
        0x2C => 0x39,
        0x2D => 0x0C,
        0x2E => 0x0D,
        0x2F => 0x1A,
        0x30 => 0x1B,
        0x31 | 0x32 => 0x2B,
        0x33 => 0x27,
        0x34 => 0x28,
        0x35 => 0x29,
        0x36 => 0x33,
        0x37 => 0x34,
        0x38 => 0x35,
        0x39 => 0x3A,
        0x3A..=0x43 => (u - 0x3A + 0x3B) as u16, // F1..F10
        0x44 => 0x57,
        0x45 => 0x58,
        0x47 => 0x46,
        0x49 => 0x152,
        0x4A => 0x147,
        0x4B => 0x149,
        0x4C => 0x153,
        0x4D => 0x14F,
        0x4E => 0x151,
        0x4F => 0x14D,
        0x50 => 0x14B,
        0x51 => 0x150,
        0x52 => 0x148,
        0x53 => 0x45,
        0x54 => 0x135,
        0x55 => 0x37,
        0x56 => 0x4A,
        0x57 => 0x4E,
        0x58 => 0x11C,
        0x59..=0x61 => [0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47, 0x48, 0x49][(u - 0x59) as usize] as u16,
        0x62 => 0x52,
        0x63 => 0x53,
        _ => 0,
    }
}

/// Modifier bit (boot report byte 0) -> scancode.
const MODS: [u16; 8] = [0x1D, 0x2A, 0x38, 0x15B, 0x11D, 0x36, 0x138, 0x15C];

fn key(code: u16, pressed: bool) {
    super::super::input::ps2::inject_key(code & 0x100 != 0, (code & 0xFF) as u8, pressed);
}

/// Process one 8-byte boot keyboard report against the previous one. Returns the (non-modifier) usage that was newly
/// pressed, if any, so the caller can drive software key repeat.
pub fn kbd_report(prev: &mut [u8; 8], cur: &[u8]) -> Option<u8> {
    if cur.len() < 8 {
        return None;
    }
    if cur[2..8].iter().all(|b| *b == 1) {
        return None; // phantom state / rollover error
    }
    let mut newly = None;
    for bit in 0..8 {
        let (was, is) = (prev[0] & (1 << bit) != 0, cur[0] & (1 << bit) != 0);
        if was != is {
            key(MODS[bit], is);
        }
    }
    for k in prev[2..8].iter().filter(|k| **k > 3) {
        if !cur[2..8].contains(k) {
            let sc = usage_to_scancode(*k);
            if sc != 0 {
                key(sc, false);
            }
        }
    }
    for k in cur[2..8].iter().filter(|k| **k > 3) {
        if !prev[2..8].contains(k) {
            let sc = usage_to_scancode(*k);
            if sc != 0 {
                key(sc, true);
                newly = Some(*k);
            }
        }
    }
    prev.copy_from_slice(&cur[..8]);
    newly
}

// ------------------------------------------------------------ pointers ---

#[derive(Clone, Copy, Debug, Default)]
struct Field {
    bit_off: u32,
    bits: u32,
    signed: bool,
    min: i32,
    max: i32,
}

/// Layout of a pointing device's input report, from its report descriptor.
#[derive(Clone, Debug, Default)]
pub struct PointerLayout {
    pub report_id: u8,
    buttons: Vec<Field>, // one bit each
    x: Option<Field>,
    y: Option<Field>,
    wheel: Option<Field>,
    pub absolute: bool,
    pub total_bits: u32,
}

/// Parse a HID report descriptor looking for a Pointer/Mouse application collection (Generic Desktop 1, usage 1 or 2).
/// Returns None when the device is not a pointer or the descriptor is malformed.
pub fn parse_pointer(desc: &[u8]) -> Option<PointerLayout> {
    let mut i = 0usize;
    let (mut page, mut usage_min, mut usage_max) = (0u32, 0u32, 0u32);
    let mut usages: Vec<u32> = Vec::new();
    let (mut lmin, mut lmax, mut size, mut count, mut rid) = (0i32, 0i32, 0u32, 0u32, 0u8);
    let mut bit_pos = 0u32; // within the report of `rid` (excluding the id byte)
    let mut is_pointer = false;
    let mut depth = 0i32;
    let mut lay = PointerLayout::default();
    let mut found = false;
    let mut stack_guard = 0;
    while i < desc.len() && stack_guard < 4096 {
        stack_guard += 1;
        let b = desc[i];
        if b == 0xFE {
            let l = *desc.get(i + 1)? as usize;
            i += 3 + l;
            continue;
        }
        let sz = match b & 3 { 3 => 4, n => n as usize };
        let ty = (b >> 2) & 3;
        let tag = b >> 4;
        let raw = desc.get(i + 1..i + 1 + sz)?;
        let mut v = 0u32;
        for (k, x) in raw.iter().enumerate() {
            v |= (*x as u32) << (8 * k);
        }
        let sv = match sz {
            1 => v as u8 as i8 as i32,
            2 => v as u16 as i16 as i32,
            _ => v as i32,
        };
        i += 1 + sz;
        match (ty, tag) {
            (1, 0) => page = v,
            (1, 1) => lmin = sv,
            (1, 2) => lmax = if sz == 4 || sv >= 0 { sv } else { v as i32 },
            (1, 7) => size = v.min(32),
            (1, 8) => {
                rid = v as u8;
                bit_pos = 0;
            }
            (1, 9) => count = v.min(256),
            (2, 0) => usages.push(v),
            (2, 1) => usage_min = v,
            (2, 2) => usage_max = v,
            (0, 0xA) => {
                // collection
                if depth == 0 && page == 1 && usages.first().map_or(false, |u| *u == 1 || *u == 2) {
                    is_pointer = true;
                }
                depth += 1;
                usages.clear();
            }
            (0, 0xC) => {
                depth -= 1;
                usages.clear();
            }
            (0, 8) => {
                // input item
                let flags = v;
                let constant = flags & 1 != 0;
                if is_pointer && !constant {
                    if found && lay.report_id != rid {
                        // fields of another report id: ignore
                    } else {
                        let rel = flags & 4 != 0;
                        for n in 0..count {
                            let usage = if !usages.is_empty() {
                                usages.get(n as usize).copied().or(usages.last().copied()).unwrap_or(0)
                            } else if usage_max >= usage_min {
                                usage_min + n.min(usage_max - usage_min)
                            } else {
                                0
                            };
                            let f = Field { bit_off: bit_pos + n * size, bits: size, signed: lmin < 0, min: lmin, max: lmax };
                            match (page, usage) {
                                (9, _) if size == 1 && lay.buttons.len() < 8 => lay.buttons.push(f),
                                (1, 0x30) => {
                                    lay.x = Some(f);
                                    lay.absolute = !rel;
                                    lay.report_id = rid;
                                    found = true;
                                }
                                (1, 0x31) => lay.y = Some(f),
                                (1, 0x38) => lay.wheel = Some(f),
                                _ => {}
                            }
                        }
                    }
                }
                bit_pos += count * size;
                if rid == lay.report_id || !found {
                    lay.total_bits = lay.total_bits.max(bit_pos);
                }
                usages.clear();
                usage_min = 0;
                usage_max = 0;
            }
            (0, 9) | (0, 0xB) => {
                bit_pos += count * size;
                usages.clear();
                usage_min = 0;
                usage_max = 0;
            }
            _ => {}
        }
    }
    if found && lay.x.is_some() && lay.y.is_some() {
        Some(lay)
    } else {
        None
    }
}

fn field_value(buf: &[u8], f: &Field) -> Option<i32> {
    if f.bits == 0 || f.bits > 32 {
        return None;
    }
    let mut v: u64 = 0;
    for b in 0..f.bits {
        let pos = (f.bit_off + b) as usize;
        let byte = *buf.get(pos / 8)?;
        v |= (((byte >> (pos % 8)) & 1) as u64) << b;
    }
    let v = v as i64;
    Some(if f.signed && f.bits < 32 && v & (1 << (f.bits - 1)) != 0 { (v - (1 << f.bits)) as i32 } else { v as i32 })
}

/// Fallback layout for boot-protocol mice: buttons byte, dx, dy (i8).
pub fn boot_mouse_layout() -> PointerLayout {
    let mut l = PointerLayout::default();
    for b in 0..3 {
        l.buttons.push(Field { bit_off: b, bits: 1, signed: false, min: 0, max: 1 });
    }
    l.x = Some(Field { bit_off: 8, bits: 8, signed: true, min: -127, max: 127 });
    l.y = Some(Field { bit_off: 16, bits: 8, signed: true, min: -127, max: 127 });
    l.total_bits = 24;
    l
}

/// Decode one input report and emit mouse events. `buttons` keeps the previous button state.
pub fn pointer_report(l: &PointerLayout, report: &[u8], buttons: &mut u8) {
    let data = if l.report_id != 0 {
        if report.first() != Some(&l.report_id) {
            return;
        }
        &report[1..]
    } else {
        report
    };
    let (Some(xf), Some(yf)) = (l.x.as_ref(), l.y.as_ref()) else { return };
    let (Some(x), Some(y)) = (field_value(data, xf), field_value(data, yf)) else { return };
    let mut now = 0u8;
    for (i, f) in l.buttons.iter().enumerate().take(3) {
        if field_value(data, f).unwrap_or(0) != 0 {
            now |= 1 << i;
        }
    }
    let ev = |e: InputEvent| {
        x86_64::instructions::interrupts::without_interrupts(|| input::push(e));
    };
    if l.absolute {
        let span = (xf.max - xf.min).max(1) as i64;
        let spany = (yf.max - yf.min).max(1) as i64;
        let nx = ((x - xf.min) as i64 * 32767 / span).clamp(0, 32767) as i32;
        let ny = ((y - yf.min) as i64 * 32767 / spany).clamp(0, 32767) as i32;
        ev(InputEvent { kind: EV_MOUSE_ABS, code: 0, value: 0, x: nx, y: ny });
    } else if x != 0 || y != 0 {
        ev(InputEvent { kind: EV_MOUSE_MOVE, code: 0, value: 0, x, y });
    }
    let changed = now ^ *buttons;
    for bit in 0..3u8 {
        if changed & (1 << bit) != 0 {
            // HID button 1 = left, 2 = right, 3 = middle; the input layer uses 0 left / 1 right / 2 middle
            ev(InputEvent { kind: EV_MOUSE_BUTTON, code: bit as u16, value: ((now >> bit) & 1) as i32, x: 0, y: 0 });
        }
    }
    *buttons = now;
}
