
fn main() {
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libvtun_linkfd.so");
    let stat_dir = std::env::var("VTUN_STAT_DIR")
        .unwrap_or_else(|_| "/var/run/vtun".to_string());
    println!("cargo:rustc-env=VTUN_STAT_DIR={}", stat_dir);
    let enable_nat_hack = std::env::var("ENABLE_NAT_HACK")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);
    if (enable_nat_hack) {
        println!("cargo:rustc-env=ENABLE_NAT_HACK=true");
    } else {
        println!("cargo:rustc-env=ENABLE_NAT_HACK=false");
    }
}
