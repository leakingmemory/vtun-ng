
pub fn vtun_syslog(priority: libc::c_int, str: &str) {
    let msg = format!("{}\n\0", str);
    unsafe {
        libc::syslog(priority, msg.as_ptr() as *const i8);
    }
}