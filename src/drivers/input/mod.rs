//! Input subsystem: PS/2 and USB keyboards/mice feed one lossy SPSC event ring.

pub mod ps2;

use crate::ipc::ring::Spsc;

pub const EV_KEY: u16 = 1;
pub const EV_MOUSE_MOVE: u16 = 2;
pub const EV_MOUSE_BUTTON: u16 = 3;
/// absolute pointer (tablets): `x`,`y` in 0..=32767 across the whole screen
pub const EV_MOUSE_ABS: u16 = 4;

/// 16-byte input event.
/// key: `code` = scancode (+0x100 if extended), `value` = 1 press / 0 release, `x` = ASCII (0 if none).
/// mouse move: `x`,`y` = relative motion (y grows downward).
/// mouse button: `code` = 0 left / 1 right / 2 middle, `value` = 1 press / 0 release.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct InputEvent {
    pub kind: u16,
    pub code: u16,
    pub value: i32,
    pub x: i32,
    pub y: i32,
}

const _: () = assert!(core::mem::size_of::<InputEvent>() == 16);

/// Producers are the keyboard and mouse IRQ handlers; interrupt gates keep IF=0 so
/// they never overlap (single CPU). The consumer is the compositor thread.
static EVENTS: Spsc<InputEvent, 256> = Spsc::new();

pub(crate) fn push(ev: InputEvent) {
    EVENTS.push_lossy(ev);
}

pub fn pop() -> Option<InputEvent> {
    EVENTS.pop()
}

pub fn dropped() -> u64 {
    EVENTS.dropped()
}
