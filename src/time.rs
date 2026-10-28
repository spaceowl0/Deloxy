//! Kernel time base driven by the LAPIC timer.

use core::sync::atomic::{AtomicU64, Ordering};

pub const TICK_HZ: u64 = 1000;
static TICKS: AtomicU64 = AtomicU64::new(0);

/// Called from the timer interrupt.
pub fn tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}

pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

pub fn uptime_ms() -> u64 {
    ticks() * 1000 / TICK_HZ
}

pub fn ms_to_ticks(ms: u64) -> u64 {
    (ms * TICK_HZ + 999) / 1000
}

/// Wall-clock time from the CMOS RTC (UTC as set by the VM/firmware; no timezone support).
#[derive(Clone, Copy, Debug)]
pub struct WallClock {
    pub hour: u8,
    pub min: u8,
    pub sec: u8,
    pub day: u8,
    pub month: u8,
    pub year: u16,
}

fn cmos(reg: u8) -> u8 {
    use x86_64::instructions::port::Port;
    // SAFETY: ports 0x70/0x71 are the standard CMOS index/data pair; bit 7 of the index (NMI mask) stays clear.
    unsafe {
        Port::<u8>::new(0x70).write(reg & 0x7F);
        Port::<u8>::new(0x71).read()
    }
}

pub fn wall_clock() -> Option<WallClock> {
    // wait (bounded) for the update-in-progress flag to clear, then read twice until stable
    let mut spins = 0;
    while cmos(0x0A) & 0x80 != 0 {
        spins += 1;
        if spins > 100_000 {
            return None;
        }
    }
    let rd = || (cmos(0), cmos(2), cmos(4), cmos(7), cmos(8), cmos(9));
    let mut a = rd();
    for _ in 0..3 {
        let b = rd();
        if a == b {
            break;
        }
        a = b;
    }
    let regb = cmos(0x0B);
    let bcd = regb & 0x04 == 0;
    let conv = |v: u8| if bcd { (v & 0x0F) + (v >> 4) * 10 } else { v };
    let pm = a.2 & 0x80 != 0;
    let mut hour = conv(a.2 & 0x7F);
    if regb & 0x02 == 0 {
        // 12-hour mode
        hour %= 12;
        if pm {
            hour += 12;
        }
    }
    let wc = WallClock { hour, min: conv(a.1), sec: conv(a.0), day: conv(a.3), month: conv(a.4), year: 2000 + conv(a.5) as u16 };
    if wc.hour > 23 || wc.min > 59 || wc.sec > 59 || wc.month == 0 || wc.month > 12 || wc.day == 0 || wc.day > 31 {
        return None;
    }
    Some(wc)
}

/// Days since 1970-01-01 for a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468
}

static BOOT_EPOCH_MS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Unix time in milliseconds: the CMOS clock (read once, assumed UTC) plus uptime. If the RTC is unreadable it falls
/// back to a fixed recent date rather than 1970, so date checks (certificates) fail loudly instead of passing wrongly.
pub fn unix_ms() -> u64 {
    use core::sync::atomic::Ordering::SeqCst;
    let mut base = BOOT_EPOCH_MS.load(SeqCst);
    if base == 0 {
        let now_up = uptime_ms();
        let epoch_s = match wall_clock() {
            Some(c) => (days_from_civil(c.year as i64, c.month as i64, c.day as i64) * 86400 + c.hour as i64 * 3600 + c.min as i64 * 60 + c.sec as i64) as u64,
            None => 1_790_000_000,
        };
        base = (epoch_s * 1000).saturating_sub(now_up).max(1);
        BOOT_EPOCH_MS.store(base, SeqCst);
    }
    base + uptime_ms()
}
