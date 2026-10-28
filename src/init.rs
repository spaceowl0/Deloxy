//! First user process: the shell. Its capability set is the whole of its authority.

use alloc::sync::Arc;

use crate::cap::{CapObject, Rights};
use crate::exec::{self, SpawnOpts};
use crate::task::Process;

/// Start `deloxy-sh` from the initramfs with: Tty (rw), Dir (ls/open), Spawn (+console), Sys (ps),
/// Power, NetAdmin (consent to network grants) and the audit stream.
pub fn spawn_shell() -> Result<Arc<Process>, &'static str> {
    let root = crate::fs::root().ok_or("no initramfs")?;
    let sh = root.lookup("deloxy-sh.elf").ok_or("deloxy-sh.elf missing from initramfs")?;
    let caps = [
        (CapObject::Tty, Rights::READ | Rights::WRITE),
        (CapObject::Dir(root), Rights::READ),
        (CapObject::Spawn { console: true, files: true }, Rights::EXEC),
        (CapObject::Sys, Rights::READ),
        (CapObject::Power, Rights::EXEC),
        (CapObject::NetAdmin, Rights::GRANT),
        (CapObject::AuditStream, Rights::AUDIT_READ),
        (CapObject::Store, Rights::READ | Rights::WRITE | Rights::GRANT),
        (CapObject::Policy, Rights::READ | Rights::WRITE),
    ];
    exec::spawn("deloxy-sh", sh.data, &SpawnOpts { args: &["deloxy-sh"], console: false, caps: &caps, foreign_caps: &[] }).map_err(|_| "cannot start deloxy-sh")
}
