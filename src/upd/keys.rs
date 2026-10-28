//! Trusted update-signing keys, compiled into the kernel image.
//!
//! ALPHA: the only entry is the public TEST key from `tools/mock-update-server.py`. Its private half is in
//! that script, so anyone can sign "updates" for it. It exists so the whole pipeline can be tested;
//! replace it (key ceremony in docs/SECURITY.md) before any real release.

pub struct TrustedKey {
    pub key_id: [u8; 8], // first 8 bytes of SHA-256(public key)
    pub public: [u8; 32],
    pub name: &'static str,
}

pub static TRUSTED: [TrustedKey; 1] = [TrustedKey {
    key_id: [0x4e, 0x33, 0xc0, 0x96, 0xcd, 0xf8, 0x40, 0xf2],
    public: [
        0x3f, 0x4e, 0x55, 0x8b, 0x1d, 0x8e, 0xcf, 0xdd, 0x0d, 0x4c, 0x99, 0xb7, 0x40, 0x69, 0x31, 0x6b, 0x4f, 0x2d, 0x25, 0x87, 0x09, 0x0d, 0xd0, 0x11, 0xae, 0x93, 0xdb, 0x24, 0xa2, 0xc9, 0x91, 0x55,
    ],
    name: "deloxy-alpha-TEST",
}];
