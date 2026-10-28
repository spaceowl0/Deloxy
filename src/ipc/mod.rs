//! Zero-copy IPC: SPSC rings living in shared memory, exposed as channel capabilities.
//!
//! A channel is a 2-page shared memory object: page `side` holds the ring that
//! `side` (0 or 1) *writes*; the other side reads it. Each end is a
//! `CapObject::Channel` capability. Endpoints map the pages into their address
//! space (`shm_map`) and drive the rings directly - the kernel never touches
//! the messages. Blocking/wake-up uses futexes on the ring indices.

pub mod memobj;
pub mod ring;

use alloc::sync::Arc;

use crate::cap::CapObject;
use memobj::MemObject;

/// Fixed 64-byte channel message.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Msg {
    pub seq: u64,
    pub payload: u64,
    pub pad: [u64; 6],
}

pub type MsgRing = ring::Spsc<Msg, 32>;

const _: () = assert!(core::mem::size_of::<Msg>() == 64);
const _: () = assert!(core::mem::size_of::<MsgRing>() <= 4096);

/// Create a channel; returns the two end capabilities.
pub fn create_channel() -> Option<(CapObject, CapObject)> {
    let mem: Arc<MemObject> = MemObject::new(2)?;
    Some((
        CapObject::Channel { mem: mem.clone(), side: 0 },
        CapObject::Channel { mem, side: 1 },
    ))
}
