fn main() {
    println!("cargo:rustc-link-arg=-Wl,-q");
    println!("cargo:rustc-link-arg=-nostdlib");
    println!("cargo:rustc-link-arg=--entry=module_start");
    println!("cargo:rustc-link-arg=-Wl,-z,max-page-size=0x10");
}
