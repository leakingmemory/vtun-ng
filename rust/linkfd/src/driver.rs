extern "C" {
    pub static mut dev_write: extern "C" fn(fd: i32, buf: *const libc::c_char, len: i32) -> i32;
    pub static mut dev_read: extern "C" fn(fd: i32, buf: *const libc::c_char, len: i32) -> i32;

    pub static mut proto_write: extern "C" fn(fd: i32, buf: *const libc::c_char, len: i32) -> i32;
    pub static mut proto_read: extern "C" fn(fd: i32, buf: *const libc::c_char) -> i32;
}