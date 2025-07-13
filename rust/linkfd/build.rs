
fn main() {
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libvtun_linkfd.so");
}
