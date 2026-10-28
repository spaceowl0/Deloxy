//! Structures shared verbatim between kernel and user space (no dependencies).

/// Result of `SYS_STAT`: 12 little-endian u64 words.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SysStats {
    pub uptime_ms: u64,
    pub ticks: u64,
    pub frames_total: u64,
    pub frames_free: u64,
    pub heap_used: u64,
    pub heap_mapped: u64,
    pub ctx_switches: u64,
    pub audit_dropped: u64,
    pub audit_pending: u64,
    pub screen_w: u64,
    pub screen_h: u64,
    pub reserved: u64,
}
