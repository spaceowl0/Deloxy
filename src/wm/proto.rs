//! deloxy-wm-protocol: fixed 64-byte messages exchanged between the compositor and
//! a client over a Phase-4 channel (client writes ring page 0, compositor page 1).
//! Dependency-free: shared verbatim by kernel and user programs.
//!
//! Alpha simplification: the compositor provisions each client's pixel buffer
//! (a shared `Memory` capability) when it launches the client; clients then
//! announce changes with `C_COMMIT`. Client-created buffers need a factory
//! capability (post-alpha).

// client -> compositor
pub const C_TITLE: u32 = 1; // pad bytes (up to 40) hold the UTF-8/ASCII title
pub const C_COMMIT: u32 = 2; // a,b,c,d = damaged rectangle x,y,w,h (buffer coordinates)

// compositor -> client
pub const S_CONFIGURE: u32 = 101; // a = width, b = height, c = focused (0/1)
pub const S_FOCUS: u32 = 102; // a = 1 focused, 0 unfocused
pub const S_KEY: u32 = 103; // a = ascii (0 if none), b = scancode, c = 1 pressed / 0 released
pub const S_POINTER: u32 = 104; // a = x, b = y (surface coordinates), c = buttons bitmask, d = 0 move / 1 down / 2 up
pub const S_CLOSE: u32 = 105; // close requested

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WmMsg {
    pub kind: u32,
    pub id: u32,
    pub a: i32,
    pub b: i32,
    pub c: i32,
    pub d: i32,
    pub pad: [u64; 5],
}

const _: () = assert!(core::mem::size_of::<WmMsg>() == 64);

impl WmMsg {
    pub const fn new(kind: u32, id: u32, a: i32, b: i32, c: i32, d: i32) -> WmMsg {
        WmMsg { kind, id, a, b, c, d, pad: [0; 5] }
    }
}
