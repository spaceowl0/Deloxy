fn main() {
    println!("cargo:rerun-if-changed=linker.ld");
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{dir}/linker.ld");
    println!("cargo:rustc-link-arg=-zmax-page-size=0x1000");
    println!("cargo:rustc-link-arg=-no-pie");
}
