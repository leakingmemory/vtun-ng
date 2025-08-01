

pub fn select_read_timeout(fds: &mut Vec<libc::c_int>, timeout: libc::time_t) -> libc::c_int {
    let mut tv: libc::timeval = libc::timeval {
        tv_usec: 0, tv_sec: timeout
    };
    let mut fdset: libc::fd_set = unsafe { std::mem::zeroed() };
    let result;
    let mut fdmax = 0;
    unsafe { libc::FD_ZERO(&mut fdset); }
    let len = fds.len();
    for i in 0..len {
        let fd = fds[i];
        if fd < 0 {
            continue;
        }
        if fd > fdmax {
            fdmax = fd;
        }
        unsafe { libc::FD_SET(fd, &mut fdset); }
    }
    result = unsafe { libc::select(fdmax + 1, &mut fdset, std::ptr::null_mut(), std::ptr::null_mut(), if timeout > 0 { &mut tv } else { std::ptr::null_mut() }) };
    if result < 0 {
        return result;
    }
    let mut off: usize = 0;
    let len = fds.len();
    for i in 0..len {
        let fd = fds[i];
        if unsafe { libc::FD_ISSET(fd, &fdset) } {
            fds[off] = fd;
            off = off + 1;
        }
    }
    fds.truncate(off);
    result
}

pub fn select_write_timeout(fds: &mut Vec<libc::c_int>, timeout: libc::time_t) -> libc::c_int {
    let mut tv: libc::timeval = libc::timeval {
        tv_usec: 0, tv_sec: timeout
    };
    let mut fdset: libc::fd_set = unsafe { std::mem::zeroed() };
    let result;
    let mut fdmax = 0;
    unsafe { libc::FD_ZERO(&mut fdset); }
    let len = fds.len();
    for i in 0..len {
        let fd = fds[i];
        if fd < 0 {
            continue;
        }
        if fd > fdmax {
            fdmax = fd;
        }
        unsafe { libc::FD_SET(fd, &mut fdset); }
    }
    result = unsafe { libc::select(fdmax + 1, std::ptr::null_mut(), &mut fdset, std::ptr::null_mut(), if timeout > 0 { &mut tv } else { std::ptr::null_mut() }) };
    if result < 0 {
        return result;
    }
    let mut off: usize = 0;
    let len = fds.len();
    for i in 0..len {
        let fd = fds[i];
        if unsafe { libc::FD_ISSET(fd, &fdset) } {
            fds[off] = fd;
            off = off + 1;
        }
    }
    fds.truncate(off);
    result
}
