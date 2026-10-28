//! xHCI host controller driver (polled). Brings up the controller, enumerates devices on the root-hub ports, and runs
//! HID interrupt endpoints. Everything the device says is untrusted: descriptor and report lengths are bounds-checked.
//!
//! Not supported (yet): external hubs, isochronous/bulk transfers (no mass storage / audio), streams, MSI-X, power
//! management, USB 3 link-state recovery.

use alloc::vec::Vec;
use log::{info, warn};
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use super::hid;
use crate::drivers::pci::{self, Bar, PciDevice};
use crate::mm::{frame, vmm};
use crate::task::sleep_ms;
use crate::time::uptime_ms;

const TRB_NORMAL: u32 = 1;
const TRB_SETUP: u32 = 2;
const TRB_DATA: u32 = 3;
const TRB_STATUS: u32 = 4;
const TRB_LINK: u32 = 6;
const TRB_ENABLE_SLOT: u32 = 9;
const TRB_DISABLE_SLOT: u32 = 10;
const TRB_ADDRESS: u32 = 11;
const TRB_CONFIGURE: u32 = 12;
const TRB_EVALUATE: u32 = 13;
const EV_TRANSFER: u32 = 32;
const EV_CMD_DONE: u32 = 33;
const EV_PORT: u32 = 34;

const RING_TRBS: usize = 256;
const CC_SUCCESS: u8 = 1;
const CC_SHORT: u8 = 13;

#[derive(Clone, Copy, Default)]
struct Trb {
    param: u64,
    status: u32,
    control: u32,
}

fn zeroed_frame() -> Option<PhysFrame<Size4KiB>> {
    let f = frame::allocate_frame()?;
    // SAFETY: freshly allocated, HHDM-mapped 4 KiB frame owned by us.
    unsafe { core::ptr::write_bytes(vmm::phys_to_virt(f.start_address()), 0, 4096) };
    Some(f)
}
fn pa(f: &PhysFrame<Size4KiB>) -> u64 {
    f.start_address().as_u64()
}
fn va(f: &PhysFrame<Size4KiB>) -> *mut u8 {
    vmm::phys_to_virt(f.start_address())
}

/// A producer ring (command or transfer): 255 TRBs + a link TRB back to the start.
struct Ring {
    f: PhysFrame<Size4KiB>,
    enq: usize,
    cycle: bool,
}

impl Ring {
    fn new() -> Option<Ring> {
        Some(Ring { f: zeroed_frame()?, enq: 0, cycle: true })
    }
    fn phys(&self) -> u64 {
        pa(&self.f)
    }
    fn write(&self, idx: usize, t: Trb) {
        let p = va(&self.f);
        // SAFETY: idx < 256; the ring frame is 4096 bytes = 256 TRBs. The control word (with the cycle bit) is written last.
        unsafe {
            let d = p.add(idx * 16);
            core::ptr::write_volatile(d as *mut u64, t.param);
            core::ptr::write_volatile(d.add(8) as *mut u32, t.status);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            core::ptr::write_volatile(d.add(12) as *mut u32, t.control);
        }
    }
    /// Enqueue a TRB (cycle bit applied here); returns its physical address.
    fn push(&mut self, param: u64, status: u32, control: u32) -> u64 {
        let addr = self.phys() + self.enq as u64 * 16;
        self.write(self.enq, Trb { param, status, control: (control & !1) | self.cycle as u32 });
        self.enq += 1;
        if self.enq == RING_TRBS - 1 {
            self.write(self.enq, Trb { param: self.phys(), status: 0, control: (TRB_LINK << 10) | 2 | self.cycle as u32 });
            self.cycle = !self.cycle;
            self.enq = 0;
        }
        addr
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IfKind {
    Keyboard,
    Pointer,
}

struct HidIf {
    iface: u8,
    kind: IfKind,
    dci: u8,
    mps: u16,
    ring: Ring,
    buf: PhysFrame<Size4KiB>,
    prev: [u8; 8],
    buttons: u8,
    layout: hid::PointerLayout,
    boot: bool,
}

struct Dev {
    slot: u8,
    port: u8,
    ep0: Ring,
    inctx: PhysFrame<Size4KiB>,
    outctx: PhysFrame<Size4KiB>,
    ifs: Vec<HidIf>,
}

struct Xhci {
    base: *mut u8,
    op: *mut u8,
    rt: *mut u8,
    db: *mut u8,
    ctx: usize,
    max_ports: u8,
    dcbaa: PhysFrame<Size4KiB>,
    cmd: Ring,
    erst: PhysFrame<Size4KiB>,
    ev: PhysFrame<Size4KiB>,
    ev_deq: usize,
    ev_cycle: bool,
    scratch: Vec<PhysFrame<Size4KiB>>,
    ctl_buf: PhysFrame<Size4KiB>,
    devs: Vec<Dev>,
    cmd_result: Option<(u8, u8, u64)>,
    ctl_result: Option<(u8, u32)>,
    /// software key repeat: (usage, next repeat at ms)
    repeat: Option<(u8, u64)>,
}

// SAFETY: the controller is only touched by the USB kernel thread.
unsafe impl Send for Xhci {}

impl Xhci {
    fn r32(&self, p: *mut u8, off: usize) -> u32 {
        // SAFETY: `p + off` stays inside the mapped register block (capability/operational/runtime/doorbell areas).
        unsafe { core::ptr::read_volatile(p.add(off) as *const u32) }
    }
    fn w32(&self, p: *mut u8, off: usize, v: u32) {
        // SAFETY: as in `r32`.
        unsafe { core::ptr::write_volatile(p.add(off) as *mut u32, v) }
    }
    fn w64(&self, p: *mut u8, off: usize, v: u64) {
        self.w32(p, off, v as u32);
        self.w32(p, off + 4, (v >> 32) as u32);
    }
    fn ring_db(&self, slot: u8, target: u8) {
        self.w32(self.db, slot as usize * 4, target as u32);
    }
    fn portsc(&self, port: u8) -> u32 {
        self.r32(self.op, 0x400 + 0x10 * (port as usize - 1))
    }
    fn set_portsc(&self, port: u8, v: u32) {
        self.w32(self.op, 0x400 + 0x10 * (port as usize - 1), v);
    }

    // ---- event ring ----
    fn next_event(&mut self) -> Option<Trb> {
        let p = va(&self.ev);
        // SAFETY: ev_deq < 256 within the 4 KiB event ring frame.
        let (param, status, control) = unsafe {
            let d = p.add(self.ev_deq * 16);
            (core::ptr::read_volatile(d as *const u64), core::ptr::read_volatile(d.add(8) as *const u32), core::ptr::read_volatile(d.add(12) as *const u32))
        };
        if (control & 1 != 0) != self.ev_cycle {
            return None;
        }
        self.ev_deq += 1;
        if self.ev_deq == RING_TRBS {
            self.ev_deq = 0;
            self.ev_cycle = !self.ev_cycle;
        }
        let erdp = pa(&self.ev) + self.ev_deq as u64 * 16;
        self.w64(self.rt, 0x38, erdp | (1 << 3)); // interrupter 0 ERDP, clear EHB
        Some(Trb { param, status, control })
    }

    /// Drain pending events: command completions and EP0 transfers are stored; HID reports are handled.
    fn pump(&mut self) {
        let mut guard = 0;
        while let Some(t) = self.next_event() {
            guard += 1;
            if guard > 512 {
                break;
            }
            let ty = (t.control >> 10) & 0x3F;
            match ty {
                EV_CMD_DONE => self.cmd_result = Some(((t.status >> 24) as u8, (t.control >> 24) as u8, t.param)),
                EV_TRANSFER => {
                    let slot = (t.control >> 24) as u8;
                    let ep = ((t.control >> 16) & 0x1F) as u8;
                    let cc = (t.status >> 24) as u8;
                    let resid = t.status & 0xFF_FFFF;
                    if ep == 1 {
                        self.ctl_result = Some((cc, resid));
                    } else {
                        self.hid_event(slot, ep, cc, resid);
                    }
                }
                EV_PORT => {} // handled by the periodic port scan
                _ => {}
            }
        }
    }

    fn wait<T>(&mut self, timeout_ms: u64, mut f: impl FnMut(&mut Xhci) -> Option<T>) -> Option<T> {
        let t0 = uptime_ms();
        loop {
            self.pump();
            if let Some(v) = f(self) {
                return Some(v);
            }
            if uptime_ms().saturating_sub(t0) > timeout_ms {
                return None;
            }
            sleep_ms(1);
        }
    }

    /// Issue a command; returns (completion code, slot id, command TRB pointer).
    fn command(&mut self, param: u64, status: u32, control: u32) -> Option<(u8, u8)> {
        self.cmd_result = None;
        let at = self.cmd.push(param, status, control);
        self.ring_db(0, 0);
        let r = self.wait(1500, |x| x.cmd_result.take())?;
        let _ = at;
        Some((r.0, r.1))
    }

    // ---- bring-up ----
    fn init(d: &PciDevice) -> Result<Xhci, &'static str> {
        let Bar::Mem { base, size, .. } = d.bars[0] else { return Err("xhci: BAR0 is not memory") };
        pci::enable_bus_master(d.bdf);
        let mmio = vmm::map_mmio(base, (size as usize).clamp(0x1000, 0x10_0000)).ok_or("xhci: mmio map")?;
        let caplen = unsafe { core::ptr::read_volatile(mmio) } as usize;
        let mut x = Xhci {
            base: mmio,
            op: unsafe { mmio.add(caplen) },
            rt: core::ptr::null_mut(),
            db: core::ptr::null_mut(),
            ctx: 32,
            max_ports: 0,
            dcbaa: zeroed_frame().ok_or("xhci: alloc")?,
            cmd: Ring::new().ok_or("xhci: alloc")?,
            erst: zeroed_frame().ok_or("xhci: alloc")?,
            ev: zeroed_frame().ok_or("xhci: alloc")?,
            ev_deq: 0,
            ev_cycle: true,
            scratch: Vec::new(),
            ctl_buf: zeroed_frame().ok_or("xhci: alloc")?,
            devs: Vec::new(),
            cmd_result: None,
            ctl_result: None,
            repeat: None,
        };
        let hcs1 = x.r32(mmio, 4);
        let hcs2 = x.r32(mmio, 8);
        let hcc1 = x.r32(mmio, 0x10);
        let dboff = x.r32(mmio, 0x14) as usize & !3;
        let rtsoff = x.r32(mmio, 0x18) as usize & !0x1F;
        x.db = unsafe { mmio.add(dboff) };
        x.rt = unsafe { mmio.add(rtsoff) };
        x.ctx = if hcc1 & (1 << 2) != 0 { 64 } else { 32 };
        let max_slots = (hcs1 & 0xFF) as u8;
        x.max_ports = ((hcs1 >> 24) & 0xFF) as u8;
        // BIOS -> OS ownership handoff (USB legacy support extended capability)
        let mut off = ((hcc1 >> 16) as usize) * 4;
        for _ in 0..32 {
            if off == 0 || off + 8 > (size as usize).min(0x10_0000) {
                break;
            }
            let cap = x.r32(mmio, off);
            if cap & 0xFF == 1 {
                if cap & (1 << 16) != 0 {
                    x.w32(mmio, off, cap | (1 << 24));
                    for _ in 0..1000 {
                        if x.r32(mmio, off) & (1 << 16) == 0 {
                            break;
                        }
                        sleep_ms(1);
                    }
                }
                x.w32(mmio, off + 4, 0); // no SMIs
            }
            let next = ((cap >> 8) & 0xFF) as usize;
            if next == 0 {
                break;
            }
            off += next * 4;
        }
        // stop + reset
        x.w32(x.op, 0, x.r32(x.op, 0) & !1);
        for _ in 0..200 {
            if x.r32(x.op, 4) & 1 != 0 {
                break;
            }
            sleep_ms(1);
        }
        x.w32(x.op, 0, 2);
        for _ in 0..500 {
            if x.r32(x.op, 0) & 2 == 0 && x.r32(x.op, 4) & (1 << 11) == 0 {
                break;
            }
            sleep_ms(1);
        }
        if x.r32(x.op, 4) & (1 << 11) != 0 {
            return Err("xhci: controller not ready after reset");
        }
        x.w32(x.op, 0x38, max_slots as u32); // CONFIG.MaxSlotsEn
        // scratchpad buffers
        let nscratch = (((hcs2 >> 21) & 0x1F) << 5 | ((hcs2 >> 27) & 0x1F)) as usize;
        if nscratch > 0 {
            let arr = zeroed_frame().ok_or("xhci: alloc")?;
            if nscratch > 512 {
                return Err("xhci: too many scratchpad buffers");
            }
            for i in 0..nscratch {
                let f = zeroed_frame().ok_or("xhci: alloc")?;
                // SAFETY: arr is a 4 KiB frame holding up to 512 u64 pointers.
                unsafe { core::ptr::write_volatile((va(&arr) as *mut u64).add(i), pa(&f)) };
                x.scratch.push(f);
            }
            // SAFETY: DCBAA slot 0 is the scratchpad array pointer.
            unsafe { core::ptr::write_volatile(va(&x.dcbaa) as *mut u64, pa(&arr)) };
            x.scratch.push(arr);
        }
        x.w64(x.op, 0x30, pa(&x.dcbaa));
        x.w64(x.op, 0x18, x.cmd.phys() | 1); // CRCR with RCS
        // event ring segment table (one segment of 256 TRBs)
        // SAFETY: erst is a zeroed 4 KiB frame; one 16-byte entry fits.
        unsafe {
            core::ptr::write_volatile(va(&x.erst) as *mut u64, pa(&x.ev));
            core::ptr::write_volatile(va(&x.erst).add(8) as *mut u32, RING_TRBS as u32);
        }
        x.w32(x.rt, 0x28, 1); // ERSTSZ
        x.w64(x.rt, 0x38, pa(&x.ev) | (1 << 3)); // ERDP
        x.w64(x.rt, 0x30, pa(&x.erst)); // ERSTBA (written last: it arms the ring)
        x.w32(x.op, 0, 1); // RS (no interrupts: polled)
        for _ in 0..200 {
            if x.r32(x.op, 4) & 1 == 0 {
                break;
            }
            sleep_ms(1);
        }
        info!("usb: xHCI up: {} ports, {} slots, {}-byte contexts, {} scratchpad buffers", x.max_ports, max_slots, x.ctx, nscratch);
        Ok(x)
    }

    // ---- enumeration ----
    fn reset_port(&mut self, port: u8) -> Option<u8> {
        const KEEP: u32 = 0x0E00_C3E0;
        let v = self.portsc(port);
        if v & 1 == 0 {
            return None;
        }
        // USB3 ports may already be enabled (the controller trains the link itself)
        self.set_portsc(port, (v & KEEP) | (1 << 4)); // PR
        let ok = self.wait(500, |x| if x.portsc(port) & (1 << 21) != 0 { Some(()) } else { None });
        let v = self.portsc(port);
        self.set_portsc(port, (v & KEEP) | (1 << 21) | (1 << 17) | (1 << 18) | (1 << 19) | (1 << 22)); // ack PRC/CSC/PEC/WRC/PLC
        if ok.is_none() || v & 2 == 0 {
            return None;
        }
        Some(((v >> 10) & 0xF) as u8)
    }

    fn ctx_ptr(&self, f: &PhysFrame<Size4KiB>, n: usize) -> *mut u32 {
        // SAFETY: context n (0 = input control / slot of the output ctx) lies within the 4 KiB frame (<= 33 x 64 bytes = 2112).
        unsafe { va(f).add(n * self.ctx) as *mut u32 }
    }

    fn enumerate(&mut self, port: u8) {
        if self.devs.iter().any(|d| d.port == port) {
            return;
        }
        let Some(speed) = self.reset_port(port) else { return };
        match self.try_enumerate(port, speed) {
            Ok(()) => {}
            Err(e) => warn!("usb: port {} (speed {}): {}", port, speed, e),
        }
    }

    fn try_enumerate(&mut self, port: u8, speed: u8) -> Result<(), &'static str> {
        let (cc, slot) = self.command(0, 0, TRB_ENABLE_SLOT << 10).ok_or("enable slot timed out")?;
        if cc != CC_SUCCESS || slot == 0 {
            return Err("enable slot failed");
        }
        let outctx = zeroed_frame().ok_or("alloc")?;
        let inctx = zeroed_frame().ok_or("alloc")?;
        let ep0 = Ring::new().ok_or("alloc")?;
        // SAFETY: DCBAA is a 4 KiB frame of 256 u64 slots; slot <= max_slots <= 255.
        unsafe { core::ptr::write_volatile((va(&self.dcbaa) as *mut u64).add(slot as usize), pa(&outctx)) };
        let mps0: u32 = match speed {
            4 => 512,
            3 => 64,
            _ => 8,
        };
        // input context: control (add slot + ep0), slot, ep0
        let c = self.ctx_ptr(&inctx, 0);
        let s = self.ctx_ptr(&inctx, 1);
        let e = self.ctx_ptr(&inctx, 2);
        // SAFETY: pointers computed above stay inside the zeroed input-context frame.
        unsafe {
            *c.add(1) = 0b11;
            *s = (1 << 27) | ((speed as u32) << 20);
            *s.add(1) = (port as u32) << 16;
            *e.add(1) = (3 << 1) | (4 << 3) | (mps0 << 16); // CErr 3, control endpoint
            let r = ep0.phys() | 1;
            *e.add(2) = r as u32;
            *e.add(3) = (r >> 32) as u32;
            *e.add(4) = 8;
        }
        let mut dev = Dev { slot, port, ep0, inctx, outctx, ifs: Vec::new() };
        let (cc, _) = self.command(pa(&dev.inctx), 0, (TRB_ADDRESS << 10) | ((slot as u32) << 24)).ok_or("address device timed out")?;
        if cc != CC_SUCCESS {
            self.disable_slot(slot);
            return Err("address device failed");
        }
        // device descriptor: first 8 bytes tell us the real EP0 packet size
        let mut d8 = [0u8; 8];
        self.control(&mut dev, [0x80, 6, 0, 1, 0, 0, 8, 0], Some(&mut d8)).ok_or("get descriptor failed")?;
        let real = if speed == 4 { 512 } else { d8[7] as u32 };
        if real != 0 && real != mps0 {
            let e = self.ctx_ptr(&dev.inctx, 2);
            // SAFETY: as above.
            unsafe {
                *self.ctx_ptr(&dev.inctx, 0).add(1) = 0b10;
                *e.add(1) = (3 << 1) | (4 << 3) | (real << 16);
            }
            let (cc, _) = self.command(pa(&dev.inctx), 0, (TRB_EVALUATE << 10) | ((slot as u32) << 24)).ok_or("evaluate timed out")?;
            if cc != CC_SUCCESS {
                self.disable_slot(slot);
                return Err("evaluate context failed");
            }
        }
        let mut dd = [0u8; 18];
        self.control(&mut dev, [0x80, 6, 0, 1, 0, 0, 18, 0], Some(&mut dd)).ok_or("device descriptor failed")?;
        // configuration descriptor (9 bytes -> total length -> everything, up to 512)
        let mut c9 = [0u8; 9];
        self.control(&mut dev, [0x80, 6, 0, 2, 0, 0, 9, 0], Some(&mut c9)).ok_or("config descriptor failed")?;
        let total = (u16::from_le_bytes([c9[2], c9[3]]) as usize).clamp(9, 512);
        let mut cfg = alloc::vec![0u8; total];
        self.control(&mut dev, [0x80, 6, 0, 2, 0, 0, total as u8, (total >> 8) as u8], Some(&mut cfg)).ok_or("config descriptor failed")?;
        let cfg_value = c9[5];
        let ifs = Self::parse_config(&cfg);
        if ifs.is_empty() {
            info!("usb: port {}: {:04x}:{:04x} class {:02x} - no supported HID interface (ignored)", port, u16::from_le_bytes([dd[8], dd[9]]), u16::from_le_bytes([dd[10], dd[11]]), dd[4]);
            self.disable_slot(slot);
            return Ok(());
        }
        // fetch report descriptors for pointer interfaces, build endpoint contexts
        let mut max_dci = 1u8;
        let mut add = 1u32;
        for (iface, proto, ep_addr, mps, interval) in ifs.iter().take(4) {
            let dci = (ep_addr & 0xF) * 2 + 1;
            let kind = if *proto == 1 { IfKind::Keyboard } else { IfKind::Pointer };
            let (mut layout, mut boot) = (hid::boot_mouse_layout(), true);
            if kind == IfKind::Pointer {
                let mut rd = alloc::vec![0u8; 512];
                let setup = [0x81, 6, 0, 0x22, *iface, 0, 0x00, 0x02];
                if let Some(n) = self.control(&mut dev, setup, Some(&mut rd)) {
                    if let Some(l) = hid::parse_pointer(&rd[..n.min(512)]) {
                        layout = l;
                        boot = false;
                    }
                }
            }
            let Some(ring) = Ring::new() else { continue };
            let Some(buf) = zeroed_frame() else { continue };
            let e = self.ctx_ptr(&dev.inctx, 1 + dci as usize);
            let ival: u32 = if speed == 1 || speed == 2 {
                3 + (31 - (*interval as u32).max(1).leading_zeros()).min(7)
            } else {
                (*interval as u32).clamp(1, 16) - 1
            };
            // SAFETY: dci <= 31, context inside the input-context frame (1 + 31 contexts of <= 64 bytes).
            unsafe {
                *e = ival << 16;
                *e.add(1) = (3 << 1) | (7 << 3) | ((*mps as u32) << 16);
                let r = ring.phys() | 1;
                *e.add(2) = r as u32;
                *e.add(3) = (r >> 32) as u32;
                *e.add(4) = (*mps as u32) | ((*mps as u32) << 16);
            }
            max_dci = max_dci.max(dci);
            add |= 1 << dci;
            dev.ifs.push(HidIf { iface: *iface, kind, dci, mps: *mps, ring, buf, prev: [0; 8], buttons: 0, layout, boot });
        }
        if dev.ifs.is_empty() {
            self.disable_slot(slot);
            return Err("no usable interface");
        }
        // SAFETY: slot context + control context inside the input frame.
        unsafe {
            *self.ctx_ptr(&dev.inctx, 0) = 0;
            *self.ctx_ptr(&dev.inctx, 0).add(1) = add;
            let s = self.ctx_ptr(&dev.inctx, 1);
            *s = (*s & 0x07FF_FFFF) | ((max_dci as u32) << 27);
        }
        let (cc, _) = self.command(pa(&dev.inctx), 0, (TRB_CONFIGURE << 10) | ((slot as u32) << 24)).ok_or("configure timed out")?;
        if cc != CC_SUCCESS {
            self.disable_slot(slot);
            return Err("configure endpoint failed");
        }
        self.control(&mut dev, [0x00, 9, cfg_value, 0, 0, 0, 0, 0], None).ok_or("set configuration failed")?;
        let setup: Vec<(u8, bool)> = dev.ifs.iter().map(|h| (h.iface, h.kind == IfKind::Keyboard || h.boot)).collect();
        for (iface, boot) in setup {
            if boot {
                let _ = self.control(&mut dev, [0x21, 0x0B, 0, 0, iface, 0, 0, 0], None); // SET_PROTOCOL(boot)
            }
            let _ = self.control(&mut dev, [0x21, 0x0A, 0, 0, iface, 0, 0, 0], None); // SET_IDLE(0): may stall, harmless
        }
        info!(
            "usb: port {}: {:04x}:{:04x} -> {}",
            port,
            u16::from_le_bytes([dd[8], dd[9]]),
            u16::from_le_bytes([dd[10], dd[11]]),
            dev.ifs.iter().map(|h| match (h.kind, h.layout.absolute) { (IfKind::Keyboard, _) => "keyboard", (_, true) => "tablet", _ => "mouse" }).collect::<Vec<_>>().join("+")
        );
        let slot = dev.slot;
        let dcis: Vec<u8> = dev.ifs.iter().map(|h| h.dci).collect();
        self.devs.push(dev);
        for dci in dcis {
            self.queue_in(slot, dci);
        }
        Ok(())
    }

    /// (interface, protocol, endpoint address, max packet, interval) of every HID boot keyboard / mouse / pointer interface.
    fn parse_config(cfg: &[u8]) -> Vec<(u8, u8, u8, u16, u8)> {
        let mut out = Vec::new();
        let mut i = 0;
        let mut cur: Option<(u8, u8)> = None; // (iface, kind: 1 kbd 2 pointer)
        while i + 2 <= cfg.len() {
            let l = cfg[i] as usize;
            if l < 2 || i + l > cfg.len() {
                break;
            }
            match cfg[i + 1] {
                4 if l >= 9 => {
                    let (class, sub, proto) = (cfg[i + 5], cfg[i + 6], cfg[i + 7]);
                    cur = if class == 3 && sub == 1 && proto == 1 {
                        Some((cfg[i + 2], 1))
                    } else if class == 3 && (proto == 2 || sub == 0) {
                        Some((cfg[i + 2], 2)) // mouse, or a report-protocol HID that may be a tablet
                    } else {
                        None
                    };
                }
                5 if l >= 7 => {
                    if let Some((iface, kind)) = cur {
                        let (addr, attr) = (cfg[i + 2], cfg[i + 3]);
                        if addr & 0x80 != 0 && attr & 3 == 3 && out.iter().all(|o: &(u8, u8, u8, u16, u8)| o.0 != iface) {
                            let mps = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]) & 0x7FF;
                            if (1..=64).contains(&mps) {
                                out.push((iface, kind, addr & 0xF | 0x80, mps, cfg[i + 6]));
                            }
                        }
                    }
                }
                _ => {}
            }
            i += l;
        }
        out
    }

    fn disable_slot(&mut self, slot: u8) {
        let _ = self.command(0, 0, (TRB_DISABLE_SLOT << 10) | ((slot as u32) << 24));
        // SAFETY: clears the DCBAA entry of the slot we just released.
        unsafe { core::ptr::write_volatile((va(&self.dcbaa) as *mut u64).add(slot as usize), 0) };
    }

    /// One control transfer on EP0. Returns the number of bytes transferred (data stage) or 0.
    fn control(&mut self, dev: &mut Dev, setup: [u8; 8], data: Option<&mut [u8]>) -> Option<usize> {
        let len = data.as_ref().map_or(0, |d| d.len().min(4096));
        let inb = setup[0] & 0x80 != 0;
        self.ctl_result = None;
        let trt = if len == 0 { 0 } else if inb { 3 } else { 2 };
        dev.ep0.push(u64::from_le_bytes(setup), 8, (TRB_SETUP << 10) | (1 << 6) | (trt << 16));
        if len > 0 {
            if !inb {
                if let Some(d) = data.as_ref() {
                    // SAFETY: ctl_buf is a 4 KiB DMA frame; len <= 4096.
                    unsafe { core::ptr::copy_nonoverlapping(d.as_ptr(), va(&self.ctl_buf), len) };
                }
            }
            dev.ep0.push(pa(&self.ctl_buf), len as u32, (TRB_DATA << 10) | if inb { 1 << 16 } else { 0 });
        }
        let status_dir = if len > 0 && inb { 0 } else { 1 << 16 };
        dev.ep0.push(0, 0, (TRB_STATUS << 10) | (1 << 5) | status_dir);
        self.ring_db(dev.slot, 1);
        let (cc, resid) = self.wait(1500, |x| x.ctl_result.take())?;
        if cc != CC_SUCCESS && cc != CC_SHORT {
            return None;
        }
        let got = len.saturating_sub(resid as usize);
        if let (true, Some(d)) = (inb && len > 0, data) {
            // SAFETY: the device wrote at most `len` bytes into ctl_buf.
            unsafe { core::ptr::copy_nonoverlapping(va(&self.ctl_buf), d.as_mut_ptr(), got.min(d.len())) };
        }
        Some(got)
    }

    // ---- HID runtime ----
    fn queue_in(&mut self, slot: u8, dci: u8) {
        let Some(di) = self.devs.iter().position(|d| d.slot == slot) else { return };
        let Some(h) = self.devs[di].ifs.iter_mut().find(|h| h.dci == dci) else { return };
        // SAFETY: clear the report buffer before the device fills it.
        unsafe { core::ptr::write_bytes(va(&h.buf), 0, 64) };
        h.ring.push(pa(&h.buf), h.mps as u32, (TRB_NORMAL << 10) | (1 << 5) | (1 << 2)); // IOC | ISP
        self.ring_db(slot, dci);
    }

    fn hid_event(&mut self, slot: u8, ep: u8, cc: u8, resid: u32) {
        let Some(di) = self.devs.iter().position(|d| d.slot == slot) else { return };
        let ok = cc == CC_SUCCESS || cc == CC_SHORT;
        let mut newly = None;
        if let Some(h) = self.devs[di].ifs.iter_mut().find(|h| h.dci == ep) {
            if ok {
                let n = (h.mps as usize).saturating_sub(resid as usize).min(64);
                let mut rep = [0u8; 64];
                // SAFETY: the device wrote at most mps (<= 64) bytes into the 4 KiB report buffer.
                unsafe { core::ptr::copy_nonoverlapping(va(&h.buf), rep.as_mut_ptr(), 64) };
                match h.kind {
                    IfKind::Keyboard => newly = hid::kbd_report(&mut h.prev, &rep[..n.max(8).min(64)]),
                    IfKind::Pointer => {
                        let l = h.layout.clone();
                        hid::pointer_report(&l, &rep[..n], &mut h.buttons)
                    }
                }
            }
        }
        if let Some(u) = newly {
            self.repeat = Some((u, uptime_ms() + 500));
        }
        if ok {
            self.queue_in(slot, ep);
        } else if cc == 6 {
            // stall: clearing it needs Reset Endpoint; drop the device so it is re-enumerated cleanly
            self.remove_port(self.devs[di].port);
        } else {
            self.queue_in(slot, ep); // transient error: try again
        }
    }

    fn remove_port(&mut self, port: u8) {
        if let Some(i) = self.devs.iter().position(|d| d.port == port) {
            let d = self.devs.remove(i);
            self.disable_slot(d.slot);
            info!("usb: port {} device removed", port);
        }
    }

    /// Periodic: hot-plug scan + software key repeat.
    fn tick(&mut self) {
        for p in 1..=self.max_ports {
            let v = self.portsc(p);
            let connected = v & 1 != 0;
            if v & (1 << 17) != 0 || (connected && !self.devs.iter().any(|d| d.port == p) && uptime_ms() % 2000 < 4) {
                const KEEP: u32 = 0x0E00_C3E0;
                self.set_portsc(p, (v & KEEP) | (1 << 17)); // ack CSC
                if connected {
                    if self.devs.iter().any(|d| d.port == p) {
                        continue;
                    }
                    self.enumerate(p);
                } else {
                    self.remove_port(p);
                }
            }
        }
        if let Some((u, at)) = self.repeat {
            let still = self.devs.iter().any(|d| d.ifs.iter().any(|h| h.kind == IfKind::Keyboard && h.prev[2..8].contains(&u)));
            if !still {
                self.repeat = None;
            } else if uptime_ms() >= at {
                let sc = hid::usage_to_scancode(u);
                // repeat only keys that type or navigate; never modifiers/locks
                if sc != 0 && !matches!(sc, 0x3A | 0x45 | 0x46) {
                    super::super::input::ps2::inject_key(sc & 0x100 != 0, (sc & 0xFF) as u8, true);
                }
                self.repeat = Some((u, uptime_ms() + 33));
            }
        }
    }
}

pub fn run() {
    let Some(d) = pci::devices().iter().find(|d| d.class == 0x0C && d.subclass == 0x03 && d.prog_if == 0x30) else { return };
    let mut x = match Xhci::init(d) {
        Ok(x) => x,
        Err(e) => {
            warn!("usb: {}", e);
            return;
        }
    };
    sleep_ms(100); // let ports settle after RS
    for p in 1..=x.max_ports {
        if x.portsc(p) & 1 != 0 {
            x.enumerate(p);
        }
    }
    loop {
        x.pump();
        x.tick();
        sleep_ms(1);
    }
}
