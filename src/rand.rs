//! Kernel CSPRNG.
//!
//! * **Generator:** ChaCha20 with *fast key erasure* (after every request the key is replaced by fresh keystream, so a
//!   later memory disclosure cannot reveal earlier output).
//! * **Seeding / reseeding:** a SHA-256 pool absorbs every source: `RDSEED`/`RDRAND` when the CPU has them, a
//!   `virtio-rng` device when present, wall clock, and *TSC jitter* (cache-miss timing of a dependent memory walk) plus
//!   the timestamps of interrupts/input events (`add_event`). The generator reseeds from the pool every 1 MiB of output
//!   or 30 s.
//! * **Honesty about quality:** hardware sources (RDSEED/RDRAND/virtio-rng) are real entropy. With none of them (a bare
//!   QEMU `qemu64` CPU, no `-device virtio-rng-pci`) the seed rests on timing jitter only, which is *unpredictable in
//!   practice but not provably strong*; `quality()` reports which case we are in and it is logged at boot. Never blocks.

use crate::sync::IrqMutex;
use alloc::vec::Vec;

// ------------------------------------------------------------------ SHA-256 ---

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    n: usize,
    len: u64,
}

impl Sha256 {
    pub fn new() -> Sha256 {
        Sha256 { h: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19], buf: [0; 64], n: 0, len: 0 }
    }
    fn block(&mut self, b: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut v = self.h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let mj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(mj);
            v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
        }
        for i in 0..8 {
            self.h[i] = self.h[i].wrapping_add(v[i]);
        }
    }
    pub fn update(&mut self, mut d: &[u8]) {
        self.len += d.len() as u64;
        while !d.is_empty() {
            let take = (64 - self.n).min(d.len());
            self.buf[self.n..self.n + take].copy_from_slice(&d[..take]);
            self.n += take;
            d = &d[take..];
            if self.n == 64 {
                let b = self.buf;
                self.block(&b);
                self.n = 0;
            }
        }
    }
    pub fn finish(mut self) -> [u8; 32] {
        let bits = self.len * 8;
        self.update(&[0x80]);
        while self.n != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[4 * i..4 * i + 4].copy_from_slice(&self.h[i].to_be_bytes());
        }
        out
    }
}

pub fn sha256(d: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(d);
    s.finish()
}

// ------------------------------------------------------------------ ChaCha20 ---

fn chacha_block(key: &[u8; 32], counter: u64, out: &mut [u8; 64]) {
    let mut s = [0u32; 16];
    s[0..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    s[12] = counter as u32;
    s[13] = (counter >> 32) as u32;
    let init = s;
    macro_rules! qr {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            s[$a] = s[$a].wrapping_add(s[$b]); s[$d] = (s[$d] ^ s[$a]).rotate_left(16);
            s[$c] = s[$c].wrapping_add(s[$d]); s[$b] = (s[$b] ^ s[$c]).rotate_left(12);
            s[$a] = s[$a].wrapping_add(s[$b]); s[$d] = (s[$d] ^ s[$a]).rotate_left(8);
            s[$c] = s[$c].wrapping_add(s[$d]); s[$b] = (s[$b] ^ s[$c]).rotate_left(7);
        };
    }
    for _ in 0..10 {
        qr!(0, 4, 8, 12); qr!(1, 5, 9, 13); qr!(2, 6, 10, 14); qr!(3, 7, 11, 15);
        qr!(0, 5, 10, 15); qr!(1, 6, 11, 12); qr!(2, 7, 8, 13); qr!(3, 4, 9, 14);
    }
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
}

// ------------------------------------------------------------------ the generator ---

struct Rng {
    key: [u8; 32],
    counter: u64,
    out_since_reseed: u64,
    last_reseed_ms: u64,
    reseeds: u32,
    hw: bool,
    virtio: bool,
    /// ring of event timestamps (interrupt / input timing), absorbed at reseed
    events: [u64; 64],
    ev_idx: usize,
    seeded: bool,
}

static RNG: IrqMutex<Rng> = IrqMutex::new(Rng { key: [0; 32], counter: 0, out_since_reseed: 0, last_reseed_ms: 0, reseeds: 0, hw: false, virtio: false, events: [0; 64], ev_idx: 0, seeded: false });

fn rdtsc() -> u64 {
    // SAFETY: RDTSC is always available on x86_64.
    unsafe { core::arch::x86_64::_rdtsc() }
}

fn cpuid_bits() -> (bool, bool) {
    // SAFETY: CPUID is always available on x86_64.
    let l1 = unsafe { core::arch::x86_64::__cpuid(1) };
    let l7 = unsafe { core::arch::x86_64::__cpuid_count(7, 0) };
    (l1.ecx & (1 << 30) != 0, l7.ebx & (1 << 18) != 0)
}

#[target_feature(enable = "rdrand")]
unsafe fn rdrand64() -> Option<u64> {
    for _ in 0..10 {
        let mut v = 0u64;
        if core::arch::x86_64::_rdrand64_step(&mut v) == 1 {
            return Some(v);
        }
    }
    None
}
#[target_feature(enable = "rdseed")]
unsafe fn rdseed64() -> Option<u64> {
    for _ in 0..100 {
        let mut v = 0u64;
        if core::arch::x86_64::_rdseed64_step(&mut v) == 1 {
            return Some(v);
        }
        core::hint::spin_loop();
    }
    None
}

/// Timing jitter: a dependent walk through a buffer larger than the L1 cache, timed with the TSC. The low bits of the
/// cycle counts vary with cache/bus/interrupt activity. Hashed, never used raw.
fn jitter(h: &mut Sha256) {
    let mut buf: Vec<u64> = alloc::vec![0x9E37_79B9_7F4A_7C15; 8192]; // 64 KiB
    let mut idx = 0usize;
    let mut acc = 0u64;
    for round in 0..768u32 {
        let t0 = rdtsc();
        for _ in 0..16 {
            // SAFETY: idx is always < buf.len().
            let v = unsafe { core::ptr::read_volatile(buf.as_ptr().add(idx)) };
            idx = (v as usize ^ idx.wrapping_mul(2654435761) ^ round as usize) % buf.len();
            unsafe { core::ptr::write_volatile(buf.as_mut_ptr().add(idx), v.rotate_left(7) ^ t0) };
        }
        let d = rdtsc().wrapping_sub(t0);
        acc = acc.rotate_left(5) ^ d;
        if round % 8 == 7 {
            h.update(&acc.to_le_bytes());
            h.update(&rdtsc().to_le_bytes());
        }
    }
}

/// Collect entropy from every available source into `h`; returns (hardware source used, virtio-rng used).
fn gather(h: &mut Sha256) -> (bool, bool) {
    let (rdrand, rdseed) = cpuid_bits();
    let mut hw = false;
    if rdseed {
        for _ in 0..8 {
            // SAFETY: gated by the CPUID feature bit.
            if let Some(v) = unsafe { rdseed64() } {
                h.update(&v.to_le_bytes());
                hw = true;
            }
        }
    }
    if rdrand {
        for _ in 0..8 {
            // SAFETY: gated by the CPUID feature bit.
            if let Some(v) = unsafe { rdrand64() } {
                h.update(&v.to_le_bytes());
                hw = true;
            }
        }
    }
    let mut vr = false;
    let mut b = [0u8; 64];
    if virtio_rng_read(&mut b) {
        h.update(&b);
        vr = true;
    }
    h.update(&rdtsc().to_le_bytes());
    h.update(&crate::time::ticks().to_le_bytes());
    if let Some(w) = crate::time::wall_clock() {
        h.update(&[w.year as u8, (w.year >> 8) as u8, w.month, w.day, w.hour, w.min, w.sec]);
    }
    jitter(h);
    (hw, vr)
}

fn reseed(r: &mut Rng) {
    let mut h = Sha256::new();
    h.update(b"deloxy-rng-v1");
    h.update(&r.key);
    for e in r.events.iter() {
        h.update(&e.to_le_bytes());
    }
    let (hw, vr) = gather(&mut h);
    r.hw |= hw;
    r.virtio |= vr;
    r.key = h.finish();
    r.counter = 0;
    r.out_since_reseed = 0;
    r.last_reseed_ms = crate::time::uptime_ms();
    r.reseeds += 1;
    r.seeded = true;
}

/// Seed the generator. Call once after PCI probing (virtio-rng) and the heap are up.
pub fn init() {
    let mut r = RNG.lock();
    reseed(&mut r);
    log::info!("rand: CSPRNG seeded - {}", quality_of(&r));
}

fn quality_of(r: &Rng) -> &'static str {
    match (r.hw, r.virtio) {
        (true, true) => "hardware RNG (RDSEED/RDRAND) + virtio-rng + jitter: strong",
        (true, false) => "hardware RNG (RDSEED/RDRAND) + jitter: strong",
        (false, true) => "virtio-rng + jitter: strong",
        (false, false) => "WEAK: timing jitter only (no RDSEED/RDRAND/virtio-rng; run QEMU with -cpu max or -device virtio-rng-pci)",
    }
}

/// Human-readable entropy quality of the running generator.
pub fn quality() -> &'static str {
    quality_of(&RNG.lock())
}

/// Feed an event timestamp (interrupt, key press...). Cheap and non-blocking; absorbed at the next reseed.
pub fn add_event(sample: u64) {
    {
        let mut r = RNG.lock(); // IrqMutex masks interrupts while held: an IRQ never preempts a holder on one CPU
        let i = r.ev_idx;
        r.events[i % 64] ^= sample.rotate_left((i % 63) as u32) ^ rdtsc();
        r.ev_idx = i.wrapping_add(1);
    }
}

/// Fill `out` with cryptographically strong random bytes.
pub fn fill(out: &mut [u8]) {
    let mut r = RNG.lock();
    if !r.seeded {
        reseed(&mut r);
    }
    let now = crate::time::uptime_ms();
    if r.out_since_reseed > (1 << 20) || now.saturating_sub(r.last_reseed_ms) > 30_000 {
        reseed(&mut r);
    }
    let mut block = [0u8; 64];
    let mut i = 0;
    while i < out.len() {
        chacha_block(&r.key, r.counter, &mut block);
        r.counter += 1;
        let n = (out.len() - i).min(64);
        out[i..i + n].copy_from_slice(&block[..n]);
        i += n;
    }
    // fast key erasure: the next key is fresh keystream, the old key is gone
    chacha_block(&r.key, r.counter, &mut block);
    r.key.copy_from_slice(&block[..32]);
    r.counter = 0;
    r.out_since_reseed += out.len() as u64;
    block.fill(0);
}

pub fn next_u64() -> u64 {
    let mut b = [0u8; 8];
    fill(&mut b);
    u64::from_le_bytes(b)
}

// ------------------------------------------------------------------ virtio-rng ---

struct VirtioRng {
    q: crate::drivers::virtio::VirtQueue,
    buf: x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB>,
    _t: crate::drivers::virtio::Transport,
}
// SAFETY: only used under the VRNG lock.
unsafe impl Send for VirtioRng {}
static VRNG: IrqMutex<Option<VirtioRng>> = IrqMutex::new(None);

/// Probe a virtio-rng device (modern 0x1044 / transitional 0x1005). Safe to call more than once.
pub fn probe_virtio_rng() {
    use crate::drivers::virtio::{self, Transport, VirtQueue};
    let mut slot = VRNG.lock();
    if slot.is_some() {
        return;
    }
    let Some(d) = virtio::find_devices(0x1044, 0x1005).first().copied() else { return };
    crate::drivers::pci::enable_bus_master(d.bdf);
    let Ok(t) = Transport::new(d) else { return };
    if t.negotiate(1 << 32).is_err() {
        return;
    }
    let Some(mut q) = VirtQueue::new(0, 8) else { return };
    if t.enable_queue(0, &q).is_err() {
        return;
    }
    q.set_notify(t.notify_ptr(0));
    t.driver_ok();
    let Some(buf) = crate::mm::frame::allocate_frame() else { return };
    *slot = Some(VirtioRng { q, buf, _t: t });
    log::info!("rand: virtio-rng device found");
}

fn virtio_rng_read(out: &mut [u8; 64]) -> bool {
    let mut g = VRNG.lock();
    let Some(v) = g.as_mut() else { return false };
    let phys = v.buf.start_address().as_u64();
    v.q.post(0, phys, 64, true);
    v.q.notify();
    for _ in 0..20_000_000u32 {
        if let Some((_, len)) = v.q.poll_used() {
            let n = (len as usize).min(64);
            if n == 0 {
                return false;
            }
            // SAFETY: the device wrote `n` <= 64 bytes into our frame.
            unsafe { core::ptr::copy_nonoverlapping(crate::mm::vmm::phys_to_virt(v.buf.start_address()), out.as_mut_ptr(), n) };
            return n >= 16;
        }
        core::hint::spin_loop();
    }
    false
}
