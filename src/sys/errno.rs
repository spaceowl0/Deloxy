//! Syscall error numbers (returned negated in RAX) and fault exit codes.

pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const EIO: i64 = 5;
pub const EBADF: i64 = 9;
pub const EAGAIN: i64 = 11;
pub const ENOMEM: i64 = 12;
pub const EFAULT: i64 = 14;
pub const ENODEV: i64 = 19;
pub const EINVAL: i64 = 22;
pub const EFBIG: i64 = 27;
pub const ENOSPC: i64 = 28;
pub const ENOTTY: i64 = 25;
pub const ERANGE: i64 = 34;
pub const ENOSYS: i64 = 38;

/// Exit codes recorded when a process is killed by a CPU fault in user mode.
pub const EXIT_FAULT_PF: i64 = -11;
pub const EXIT_FAULT_GP: i64 = -12;
pub const EXIT_FAULT_UD: i64 = -4;
pub const EXIT_FAULT_DE: i64 = -8;
