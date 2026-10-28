//! hello_native: a native Deloxy-ABI program shipped as a real ELF (PT_LOAD segments with
//! RW .data/.bss, PT_NOTE "Deloxy"). Proves the loader's W^X segment mapping.
#![no_std]
#![no_main]

use core::arch::asm;

#[link_section = ".note.deloxy"]
#[used]
static NOTE: [u32; 5] = [7, 0, 1, u32::from_le_bytes(*b"Delo"), u32::from_le_bytes(*b"xy\0\0")];

static mut COUNTER: u64 = 0xDEAD_BEEF; // .data (writable)
static mut SCRATCH: [u8; 6000] = [0; 6000]; // .bss (must start zeroed)
static GREETING: &[u8] = b"hello from native ELF (data+bss ok)\n";

unsafe fn sc(nr: i64, a: u64, b: u64) -> i64 {
    let ret: i64;
    asm!("syscall", inlateout("rax") nr => ret, in("rdi") a, in("rsi") b, in("rdx") 0u64,
        lateout("rcx") _, lateout("r11") _, options(nostack));
    ret
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { sc(0, 255, 0) };
    loop {}
}

#[no_mangle]
#[link_section = ".text._start"]
pub unsafe extern "C" fn _start() -> ! {
    let mut ok = true;
    if COUNTER != 0xDEAD_BEEF {
        ok = false;
    }
    COUNTER += 1;
    if COUNTER != 0xDEAD_BEF0 {
        ok = false;
    }
    let sp = core::ptr::addr_of_mut!(SCRATCH);
    for i in 0..6000 {
        if (*sp)[i] != 0 {
            ok = false;
        }
        (*sp)[i] = (i & 0xFF) as u8;
    }
    if (*sp)[5999] != (5999 & 0xFF) as u8 {
        ok = false;
    }
    sc(3, GREETING.as_ptr() as u64, GREETING.len() as u64);
    sc(0, if ok { 0 } else { 1 }, 0);
    loop {}
}
