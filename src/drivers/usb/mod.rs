//! USB: an xHCI (USB 3.x/2.0) host-controller driver and HID class support (keyboards, mice, tablets).
//! Polled (no interrupts), root-hub ports only (no external hubs yet), HID boot keyboard + report-descriptor
//! driven pointers. Devices are treated as untrusted: every length from a descriptor or report is bounds-checked.

pub mod hid;
pub mod xhci;

/// Kernel thread body: find an xHCI controller, enumerate, then service HID devices forever.
pub fn run() {
    xhci::run();
}

/// Is there an xHCI controller on the PCI bus?
pub fn present() -> bool {
    crate::drivers::pci::devices().iter().any(|d| d.class == 0x0C && d.subclass == 0x03 && d.prog_if == 0x30)
}
