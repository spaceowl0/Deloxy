pub mod ahci;
pub mod virtio_blk;

pub const SECTOR: usize = 512;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlkErr {
    OutOfRange,
    Io,
    Timeout,
    ReadOnly,
    Invalid,
}

/// The system disk: virtio-blk (VMs) or the first AHCI/SATA disk (VirtualBox, VMware, real PCs).
pub enum Disk {
    Virtio(virtio_blk::VirtioBlk),
    Ahci(ahci::Ahci),
}

impl Disk {
    pub fn kind(&self) -> &'static str {
        match self {
            Disk::Virtio(_) => "virtio-blk",
            Disk::Ahci(_) => "AHCI/SATA",
        }
    }
    pub fn capacity_sectors(&self) -> u64 {
        match self { Disk::Virtio(d) => d.capacity_sectors(), Disk::Ahci(d) => d.capacity_sectors() }
    }
    pub fn is_read_only(&self) -> bool {
        match self { Disk::Virtio(d) => d.is_read_only(), Disk::Ahci(_) => false }
    }
    pub fn read(&mut self, s: u64, b: &mut [u8]) -> Result<(), BlkErr> {
        match self { Disk::Virtio(d) => d.read(s, b), Disk::Ahci(d) => d.read(s, b) }
    }
    pub fn write(&mut self, s: u64, b: &[u8]) -> Result<(), BlkErr> {
        match self { Disk::Virtio(d) => d.write(s, b), Disk::Ahci(d) => d.write(s, b) }
    }
    pub fn flush(&mut self) -> Result<(), BlkErr> {
        match self { Disk::Virtio(d) => d.flush(), Disk::Ahci(d) => d.flush() }
    }
}

pub fn probe_first() -> Option<Result<Disk, &'static str>> {
    if let Some(r) = virtio_blk::probe_first() {
        return Some(r.map(Disk::Virtio));
    }
    ahci::probe_first().map(|r| r.map(Disk::Ahci))
}
