//! Capability handles: the only way a process names a kernel resource.
//!
//! A handle is `[generation:32 | index:32]`. User space holds nothing but these
//! numbers; the kernel resolves them in the process's own table, checking the
//! generation (stale/forged handles -> EBADF) and the rights mask (-> EPERM).
//! Rights can only be narrowed (`derive`), and revoking a handle revokes every
//! handle derived from it.
//!
//! Note: on x86_64 there is no capability hardware (unlike CHERI); the
//! guarantee is kernel enforcement + address-space isolation.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ipc::memobj::MemObject;
use crate::sys::errno::{EBADF, EINVAL, ENOMEM, EPERM};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rights(pub u32);

impl core::ops::BitOr for Rights {
    type Output = Rights;
    fn bitor(self, o: Rights) -> Rights {
        Rights(self.0 | o.0)
    }
}

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const READ: Rights = Rights(1);
    pub const WRITE: Rights = Rights(2);
    pub const EXEC: Rights = Rights(4);
    pub const MAP: Rights = Rights(8);
    pub const GRANT: Rights = Rights(16);
    pub const DUP: Rights = Rights(32);
    pub const IO: Rights = Rights(64);
    pub const NET: Rights = Rights(128);
    pub const AUDIT_READ: Rights = Rights(256);

    pub const fn contains(self, o: Rights) -> bool {
        self.0 & o.0 == o.0
    }
    pub const fn union(self, o: Rights) -> Rights {
        Rights(self.0 | o.0)
    }
}

#[derive(Clone)]
pub enum CapObject {
    Memory(Arc<MemObject>),
    /// One end of a channel; `side` selects which ring page this end writes.
    Channel { mem: Arc<MemObject>, side: u8 },
    IoPort { base: u16, len: u16 },
    AuditStream,
    Process(u64),
    /// Write access to the kernel debug console (stdout/stderr of foreign-ABI programs).
    Console,
    /// Authority for one narrow slice of network access (see `net::grant`). Needs `Rights::NET` to use.
    Net(Arc<crate::net::NetGrant>),
    /// Authority to mint `Net` grants (held by whoever represents user consent: the shell).
    NetAdmin,
    /// A directory of the read-only initramfs (open files by name).
    Dir(Arc<crate::fs::RamDir>),
    /// A file of the initramfs.
    File(Arc<crate::fs::RamFile>),
    /// Authority to start programs; `console` = children receive a write-only `Tty` capability / console.
    Spawn { console: bool, files: bool },
    /// The kernel TTY (input read / output write).
    Tty,
    /// Read-only system inspection (process list).
    Sys,
    /// Poweroff / reboot.
    Power,
    /// A started process (wait for its exit).
    Proc(Arc<crate::task::Process>),
    /// The persistent store: READ lists/opens files, WRITE creates/replaces/deletes, GRANT formats the disk.
    Store,
    /// Application-permission policy: READ lists decisions, WRITE sets/revokes them.
    Policy,
    /// A file read from the persistent store (contents are in kernel memory, integrity-checked at open).
    StoreFile(Arc<crate::store::StoredFile>),
}

impl CapObject {
    pub fn kind(&self) -> u64 {
        match self {
            CapObject::Memory(_) => 1,
            CapObject::Channel { .. } => 2,
            CapObject::IoPort { .. } => 3,
            CapObject::AuditStream => 4,
            CapObject::Process(_) => 5,
            CapObject::Console => 6,
            CapObject::Net(_) => 7,
            CapObject::NetAdmin => 8,
            CapObject::Dir(_) => 9,
            CapObject::File(_) => 10,
            CapObject::Spawn { .. } => 11,
            CapObject::Tty => 12,
            CapObject::Sys => 13,
            CapObject::Power => 14,
            CapObject::Proc(_) => 15,
            CapObject::Store => 16,
            CapObject::Policy => 18,
            CapObject::StoreFile(_) => 17,
        }
    }
}

struct Entry {
    obj: CapObject,
    rights: Rights,
    parent: Option<u64>,
}

struct Slot {
    gen: u32,
    entry: Option<Entry>,
}

pub const MAX_CAPS: usize = 256;

pub struct CapTable {
    slots: Vec<Slot>,
    free: Vec<u32>,
    live: usize,
}

fn make_handle(gen: u32, idx: usize) -> u64 {
    ((gen as u64) << 32) | idx as u64
}

impl CapTable {
    pub const fn new() -> CapTable {
        CapTable { slots: Vec::new(), free: Vec::new(), live: 0 }
    }

    /// Capabilities a forked child inherits: the console, file access and the TTY, with the *same handle values* (the
    /// child continues running the parent's code, which has them in registers/memory). Process-control, network-admin,
    /// policy and power capabilities are never inherited.
    pub fn fork_copy(&self) -> CapTable {
        let mut slots = Vec::with_capacity(self.slots.len());
        let mut free = Vec::new();
        let mut live = 0;
        for (i, s) in self.slots.iter().enumerate() {
            let keep = match &s.entry {
                Some(e) => matches!(e.obj, CapObject::Console | CapObject::Dir(_) | CapObject::File(_) | CapObject::Store | CapObject::StoreFile(_) | CapObject::Tty),
                None => false,
            };
            if keep {
                let e = s.entry.as_ref().unwrap();
                slots.push(Slot { gen: s.gen, entry: Some(Entry { obj: e.obj.clone(), rights: e.rights, parent: None }) });
                live += 1;
            } else {
                slots.push(Slot { gen: s.gen.wrapping_add(1), entry: None });
                free.push(i as u32);
            }
        }
        CapTable { slots, free, live }
    }

    /// Visit live handles: `(handle, kind, rights)` for the `n`-th live entry.
    pub fn nth_live(&self, n: usize) -> Option<(u64, u64, Rights)> {
        let mut k = 0;
        for (i, s) in self.slots.iter().enumerate() {
            if let Some(e) = &s.entry {
                if k == n {
                    return Some((make_handle(s.gen, i), e.obj.kind(), e.rights));
                }
                k += 1;
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.live
    }

    pub fn insert(&mut self, obj: CapObject, rights: Rights) -> Result<u64, i64> {
        self.insert_with_parent(obj, rights, None)
    }

    fn insert_with_parent(&mut self, obj: CapObject, rights: Rights, parent: Option<u64>) -> Result<u64, i64> {
        if self.live >= MAX_CAPS {
            return Err(ENOMEM);
        }
        let idx = match self.free.pop() {
            Some(i) => i as usize,
            None => {
                self.slots.push(Slot { gen: 1, entry: None });
                self.slots.len() - 1
            }
        };
        let slot = &mut self.slots[idx];
        slot.entry = Some(Entry { obj, rights, parent });
        self.live += 1;
        Ok(make_handle(slot.gen, idx))
    }

    fn entry(&self, h: u64) -> Result<&Entry, i64> {
        let idx = (h & 0xFFFF_FFFF) as usize;
        let gen = (h >> 32) as u32;
        let s = self.slots.get(idx).ok_or(EBADF)?;
        if s.gen != gen {
            return Err(EBADF);
        }
        s.entry.as_ref().ok_or(EBADF)
    }

    /// Resolve `h`, requiring at least the rights `need`.
    /// EBADF: unknown/stale/forged handle. EPERM: rights insufficient.
    pub fn lookup(&self, h: u64, need: Rights) -> Result<(CapObject, Rights), i64> {
        let e = self.entry(h)?;
        if !e.rights.contains(need) {
            return Err(EPERM);
        }
        Ok((e.obj.clone(), e.rights))
    }

    /// New handle to the same object with `narrower` rights (must be a subset;
    /// the source needs DUP). Child dies with its parent.
    pub fn derive(&mut self, h: u64, narrower: Rights) -> Result<u64, i64> {
        if narrower.0 == 0 {
            return Err(EINVAL);
        }
        let e = self.entry(h)?;
        if !e.rights.contains(Rights::DUP) || !e.rights.contains(narrower) {
            return Err(EPERM);
        }
        let obj = e.obj.clone();
        self.insert_with_parent(obj, narrower, Some(h))
    }

    /// Drop `h` and (transitively) everything derived from it.
    pub fn remove(&mut self, h: u64) -> Result<(), i64> {
        self.entry(h)?;
        let mut work: Vec<u64> = Vec::new();
        work.push(h);
        while let Some(x) = work.pop() {
            if self.entry(x).is_err() {
                continue;
            }
            let idx = (x & 0xFFFF_FFFF) as usize;
            let slot = &mut self.slots[idx];
            slot.entry = None;
            slot.gen = slot.gen.wrapping_add(1).max(1);
            self.free.push(idx as u32);
            self.live -= 1;
            for (i, s) in self.slots.iter().enumerate() {
                if let Some(e) = &s.entry {
                    if e.parent == Some(x) {
                        work.push(make_handle(s.gen, i));
                    }
                }
            }
        }
        Ok(())
    }
}
