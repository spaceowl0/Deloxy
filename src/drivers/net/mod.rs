//! Network interface drivers behind one enum so the stack (`net`) does not care which NIC it drives.

pub mod e1000;
pub mod virtio_net;

pub const MAX_FRAME: usize = 1514;

use e1000::E1000;
use virtio_net::VirtioNet;

pub enum Nic {
    Virtio(VirtioNet),
    E1000(E1000),
}

macro_rules! each {
    ($s:expr, $n:ident => $e:expr) => {
        match $s {
            Nic::Virtio($n) => $e,
            Nic::E1000($n) => $e,
        }
    };
}

impl Nic {
    pub fn kind(&self) -> &'static str {
        match self {
            Nic::Virtio(_) => "virtio-net",
            Nic::E1000(_) => "Intel e1000",
        }
    }
    pub fn mac(&self) -> [u8; 6] { each!(self, n => n.mac()) }
    pub fn start(&mut self) -> Result<(), &'static str> { each!(self, n => n.start()) }
    pub fn stop(&mut self) { each!(self, n => n.stop()) }
    pub fn can_send(&mut self) -> bool { each!(self, n => n.can_send()) }
    pub fn send(&mut self, f: &[u8]) -> bool { each!(self, n => n.send(f)) }
    pub fn recv(&mut self, out: &mut [u8; MAX_FRAME]) -> Option<usize> { each!(self, n => n.recv(out)) }
    pub fn device_status(&self) -> u8 { each!(self, n => n.device_status()) }
    pub fn tx_frames(&self) -> u64 { each!(self, n => n.tx_frames) }
    pub fn rx_frames(&self) -> u64 { each!(self, n => n.rx_frames) }
}

/// First NIC found: virtio-net, else an Intel e1000.
pub fn probe_first() -> Option<Result<Nic, &'static str>> {
    if let Some(r) = virtio_net::probe_first() {
        return Some(r.map(Nic::Virtio));
    }
    e1000::probe_first().map(|r| r.map(Nic::E1000))
}
