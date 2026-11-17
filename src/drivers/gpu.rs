//! virtio-gpu 2D driver (VirtIO 1.x modern transport, polled, one request in flight).
//!
//! Display path: the driver allocates one physically contiguous XRGB8888 backing buffer, creates a 2D resource on
//! it, attaches the buffer as the resource's backing store and binds the resource to scanout 0. The kernel
//! framebuffer (`drivers::fb`) is then re-pointed at that buffer, so the boot console and the compositor draw into
//! guest memory exactly as before; `FbInfo::present` (and the console) call [`flush`] with the dirty rectangle,
//! which sends `TRANSFER_TO_HOST_2D` + `RESOURCE_FLUSH` for just that rectangle. No 3D, no cursor queue, no EDID,
//! no multiple heads (scanout 0 only). When no virtio-gpu is present nothing changes: the Limine framebuffer stays.

use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use crate::drivers::fb::{self, FbInfo};
use crate::drivers::pci;
use crate::drivers::virtio::{self, Transport, VirtQueue};
use crate::mm::{frame, vmm};
use crate::sync::IrqMutex;

const F_VERSION_1: u64 = 1 << 32;
const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const CMD_SET_SCANOUT: u32 = 0x0103;
const CMD_RESOURCE_FLUSH: u32 = 0x0104;
const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
const RESP_OK_NODATA: u32 = 0x1100;
const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
/// VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: a little-endian u32 `0x00RRGGBB`, the layout the compositor already uses.
const FMT_B8G8R8X8: u32 = 2;
const RES_ID: u32 = 1;
const SPIN_LIMIT: u64 = 300_000_000;
const MAX_DIM: u32 = 4096;
const MAX_FB_BYTES: u64 = 64 * 1024 * 1024;

struct Gpu {
    t: Transport,
    q: VirtQueue,
    /// request at offset 0, response at offset 2048
    cmd: PhysFrame<Size4KiB>,
    width: u32,
    height: u32,
    failed: bool,
    flushes: u64,
}

static GPU: IrqMutex<Option<Gpu>> = IrqMutex::new(None);
static ACTIVE: AtomicBool = AtomicBool::new(false);

fn hdr(ty: u32) -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&ty.to_le_bytes());
    h
}

fn le(v: &mut alloc::vec::Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

impl Gpu {
    /// Send one command and wait for the response; returns the response type.
    fn exec(&mut self, req: &[u8], resp_len: usize) -> Result<u32, ()> {
        if self.failed || req.len() > 2048 || resp_len > 2048 || resp_len < 24 {
            return Err(());
        }
        let base = vmm::phys_to_virt(self.cmd.start_address());
        let p = self.cmd.start_address().as_u64();
        // SAFETY: `cmd` is one exclusively owned HHDM-mapped DMA frame; request and response areas are disjoint halves.
        unsafe {
            core::ptr::copy_nonoverlapping(req.as_ptr(), base, req.len());
            core::ptr::write_bytes(base.add(2048), 0, resp_len);
        }
        self.q.post_chain(&[(p, req.len() as u32, false), (p + 2048, resp_len as u32, true)]);
        self.q.notify();
        let mut spins = 0u64;
        while self.q.poll_used().is_none() {
            spins += 1;
            if spins > SPIN_LIMIT {
                self.failed = true;
                self.t.reset();
                return Err(());
            }
            core::hint::spin_loop();
        }
        // SAFETY: the device wrote the response header into our frame.
        Ok(unsafe { core::ptr::read_volatile(base.add(2048) as *const u32) })
    }

    fn cmd_ok(&mut self, req: &[u8]) -> bool {
        self.exec(req, 24) == Ok(RESP_OK_NODATA)
    }

    fn display_size(&mut self) -> Option<(u32, u32)> {
        let h = hdr(CMD_GET_DISPLAY_INFO);
        if self.exec(&h, 24 + 16 * 24) != Ok(RESP_OK_DISPLAY_INFO) {
            return None;
        }
        let base = vmm::phys_to_virt(self.cmd.start_address());
        for i in 0..16usize {
            // SAFETY: the response area holds 16 modes of 24 bytes after the 24-byte header.
            let (w, h, en) = unsafe {
                let m = base.add(2048 + 24 + i * 24);
                (
                    core::ptr::read_volatile(m.add(8) as *const u32),
                    core::ptr::read_volatile(m.add(12) as *const u32),
                    core::ptr::read_volatile(m.add(16) as *const u32),
                )
            };
            if en != 0 && w >= 640 && h >= 480 && w <= MAX_DIM && h <= MAX_DIM {
                return Some((w, h));
            }
        }
        None
    }

    fn rect_cmd(&mut self, ty: u32, x: u32, y: u32, w: u32, h: u32, offset: u64) -> bool {
        let mut v = alloc::vec::Vec::with_capacity(56);
        v.extend_from_slice(&hdr(ty));
        for n in [x, y, w, h] {
            le(&mut v, n);
        }
        if ty == CMD_TRANSFER_TO_HOST_2D {
            v.extend_from_slice(&offset.to_le_bytes());
        }
        le(&mut v, RES_ID);
        le(&mut v, 0);
        self.cmd_ok(&v)
    }
}

/// Probe for a virtio-gpu and, if found, take over the display. Returns true when the framebuffer now belongs to it.
pub fn init() -> bool {
    use log::{info, warn};
    let Some(d) = virtio::find_devices(0x1050, 0x1050).first().copied() else { return false };
    pci::enable_bus_master(d.bdf);
    let setup = (|| -> Result<Gpu, &'static str> {
        let t = Transport::new(d)?;
        t.negotiate(F_VERSION_1)?;
        let mut q = VirtQueue::new(0, 16).ok_or("gpu ring alloc")?;
        t.enable_queue(0, &q)?;
        q.set_notify(t.notify_ptr(0));
        t.driver_ok();
        let cmd = frame::allocate_frame().ok_or("gpu cmd alloc")?;
        Ok(Gpu { t, q, cmd, width: 0, height: 0, failed: false, flushes: 0 })
    })();
    let mut g = match setup {
        Ok(g) => g,
        Err(e) => {
            warn!("gpu: virtio-gpu found but not usable: {}", e);
            return false;
        }
    };
    let (mut w, mut h) = g.display_size().unwrap_or((1024, 768));
    let mut frames = ((w as u64 * h as u64 * 4) + 4095) / 4096;
    if w as u64 * h as u64 * 4 > MAX_FB_BYTES {
        (w, h) = (1024, 768);
        frames = (w as u64 * h as u64 * 4) / 4096;
    }
    let Some(fbm) = frame::allocate_contiguous(frames as usize, 1) else {
        warn!("gpu: no {} KiB of contiguous memory for the framebuffer", frames * 4);
        return false;
    };
    let virt = vmm::phys_to_virt(fbm.start_address());
    // SAFETY: freshly allocated, exclusively owned, HHDM-mapped frames.
    unsafe { core::ptr::write_bytes(virt, 0, (frames * 4096) as usize) };

    let mut create = alloc::vec::Vec::new();
    create.extend_from_slice(&hdr(CMD_RESOURCE_CREATE_2D));
    for n in [RES_ID, FMT_B8G8R8X8, w, h] {
        le(&mut create, n);
    }
    let mut attach = alloc::vec::Vec::new();
    attach.extend_from_slice(&hdr(CMD_RESOURCE_ATTACH_BACKING));
    le(&mut attach, RES_ID);
    le(&mut attach, 1);
    attach.extend_from_slice(&fbm.start_address().as_u64().to_le_bytes());
    le(&mut attach, (w as u64 * h as u64 * 4) as u32);
    le(&mut attach, 0);
    let mut scan = alloc::vec::Vec::new();
    scan.extend_from_slice(&hdr(CMD_SET_SCANOUT));
    for n in [0, 0, w, h, 0, RES_ID] {
        le(&mut scan, n);
    }
    if !(g.cmd_ok(&create) && g.cmd_ok(&attach) && g.cmd_ok(&scan)) {
        warn!("gpu: resource setup was refused by the device");
        return false;
    }
    g.width = w;
    g.height = h;
    let ok = g.rect_cmd(CMD_TRANSFER_TO_HOST_2D, 0, 0, w, h, 0) && g.rect_cmd(CMD_RESOURCE_FLUSH, 0, 0, w, h, 0);
    if !ok {
        warn!("gpu: first flush failed");
        return false;
    }
    *GPU.lock() = Some(g);
    ACTIVE.store(true, Ordering::SeqCst);
    fb::set(FbInfo { addr: virt as usize, width: w as usize, height: h as usize, pitch: w as usize * 4, bpp: 32, r_shift: 16, g_shift: 8, b_shift: 0 });
    fb::console::init();
    flush_all();
    info!("gpu: virtio-gpu 2D scanout {}x{} ({} KiB backing), dirty-rectangle flushes", w, h, frames * 4);
    true
}

pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Make a rectangle of the framebuffer visible (no-op without a virtio-gpu, or if the device is busy/broken).
pub fn flush(x: usize, y: usize, w: usize, h: usize) {
    if !ACTIVE.load(Ordering::Relaxed) || w == 0 || h == 0 {
        return;
    }
    let Some(mut guard) = GPU.try_lock() else { return };
    let Some(g) = guard.as_mut() else { return };
    let (sw, sh) = (g.width as usize, g.height as usize);
    if x >= sw || y >= sh {
        return;
    }
    let (w, h) = (w.min(sw - x), h.min(sh - y));
    let off = (y * sw + x) as u64 * 4;
    let ok = g.rect_cmd(CMD_TRANSFER_TO_HOST_2D, x as u32, y as u32, w as u32, h as u32, off) && g.rect_cmd(CMD_RESOURCE_FLUSH, x as u32, y as u32, w as u32, h as u32, 0);
    g.flushes += 1;
    if !ok {
        ACTIVE.store(false, Ordering::SeqCst);
    }
}

pub fn flush_all() {
    if let Some(f) = fb::info() {
        flush(0, 0, f.width, f.height);
    }
}
