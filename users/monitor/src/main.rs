//! deloxy-monitor: prints kernel statistics (SYS_STAT). `monitor.elf [samples] [interval_ms]`.
#![no_std]
#![no_main]

use core::fmt::Write;

#[path = "../../common/sys.rs"]
mod sys;
#[path = "../../../src/sys/abi.rs"]
mod abi;
use sys::*;

#[link_section = ".note.deloxy"]
#[used]
static NOTE: [u32; 5] = [7, 0, 1, u32::from_le_bytes(*b"Delo"), u32::from_le_bytes(*b"xy\0\0")];

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(255)
}

fn num(s: &[u8], default: u64) -> u64 {
    core::str::from_utf8(s).ok().and_then(|t| t.parse().ok()).unwrap_or(default)
}

#[no_mangle]
#[link_section = ".text._start"]
pub unsafe extern "C" fn _start() -> ! {
    let mut o = Out::new(info_handle(0));
    let mut parts = args().split(|&b| b == 0).filter(|p| !p.is_empty());
    let _argv0 = parts.next();
    let samples = num(parts.next().unwrap_or(b""), 1).clamp(1, 600);
    let interval = num(parts.next().unwrap_or(b""), 1000).clamp(50, 60_000);
    for i in 0..samples {
        let mut st = abi::SysStats::default();
        // SAFETY: `st` is a live repr(C) buffer of 12 u64 words, exactly what SYS_STAT fills.
        let r = sc(SYS_STAT, &mut st as *mut _ as u64, 0, 0, 0, 0, 0);
        if r < 0 {
            writeln!(o, "monitor: SYS_STAT failed ({})", -r).ok();
            o.flush();
            exit(1);
        }
        let used = st.frames_total - st.frames_free;
        writeln!(o, "deloxy-monitor sample {}/{}", i + 1, samples).ok();
        writeln!(o, "  uptime        {} ms ({} ticks)", st.uptime_ms, st.ticks).ok();
        writeln!(o, "  memory        {} / {} MiB frames used", used * 4 / 1024, st.frames_total * 4 / 1024).ok();
        writeln!(o, "  kernel heap   {} KiB used, {} KiB mapped", st.heap_used / 1024, st.heap_mapped / 1024).ok();
        writeln!(o, "  ctx switches  {}", st.ctx_switches).ok();
        writeln!(o, "  audit         {} pending, {} dropped", st.audit_pending, st.audit_dropped).ok();
        writeln!(o, "  screen        {}x{}", st.screen_w, st.screen_h).ok();
        writeln!(o, "  network       tx {} frames, rx {} frames", st.reserved >> 32, st.reserved & 0xFFFF_FFFF).ok();
        o.flush();
        if i + 1 < samples {
            sleep_ms(interval);
        }
    }
    exit(0)
}
