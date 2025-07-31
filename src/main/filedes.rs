/*
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 2025 Jan-Espen Oversand <sigsegv@radiotube.org>

    VTun has been derived from VPPP package by Maxim Krasnyansky.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 */

pub struct FileDes {
    fd: libc::c_int
}

impl FileDes {
    pub fn new() -> FileDes {
        FileDes { fd: -1 }
    }
    pub fn open_m(name: &str, flags: libc::c_int) -> FileDes {
        FileDes::open(name, flags, 0644)
    }
    pub fn open(name: &str, flags: libc::c_int, mode: libc::c_int) -> FileDes {
        let name = format!("{}\0", name);
        FileDes {
            fd: unsafe { libc::open(name.as_ptr() as *const libc::c_char, flags, mode) }
        }
    }
    #[cfg(target_os = "linux")]
    pub fn getpt() -> FileDes {
        FileDes { fd: unsafe { libc::getpt() } }
    }
    #[cfg(not(target_os = "linux"))]
    pub fn getpt() -> FileDes {
        FileDes { fd: -1 }
    }

    #[cfg(target_os = "linux")]
    pub fn grantpt(&self) -> bool {
        unsafe { libc::grantpt(self.fd) == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    pub fn grantpt(&self) -> bool {
        false
    }

    #[cfg(target_os = "linux")]
    pub fn unlockpt(&self) -> bool {
        unsafe { libc::unlockpt(self.fd) == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    pub fn unlockpt(&self) -> bool {
        false
    }

    #[cfg(target_os = "linux")]
    pub fn ptsname(&self) -> Option<String> {
        let ptr = unsafe { libc::ptsname(self.fd) };
        if ptr.is_null() {
            return None;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(ptr) };
        Some(name.to_string_lossy().into_owned())
    }
    #[cfg(not(target_os = "linux"))]
    pub fn ptsname(&self) -> Option<String> {
        None
    }

    pub fn socketpair(domain: libc::c_int, type_: libc::c_int, protocol: libc::c_int) -> Result<(FileDes, FileDes), libc::c_int> {
        let mut fds: [libc::c_int; 2] = [0, 0];
        let res = unsafe { libc::socketpair(domain, type_, protocol, fds.as_mut_ptr()) };
        if res >= 0 {
            Ok((FileDes { fd: fds[0] }, FileDes { fd: fds[1] }))
        } else {
            Err(res)
        }
    }
    pub fn ok(&self) -> bool {
        self.fd >= 0
    }
    pub fn close(&mut self) -> bool {
        if self.fd < 0 {
            return true;
        }
        if unsafe { libc::close(self.fd) } == 0 {
            self.fd = -1;
            return true;
        }
        false
    }

    fn replace_fd(&self, fd: libc::c_int) -> FileDes {
        unsafe { libc::close(fd); }
        FileDes { fd: unsafe { libc::dup(self.fd) } }
    }

    pub fn detach(&mut self) -> libc::c_int {
        let fd = self.fd;
        self.fd = -1;
        fd
    }

    pub fn move_out(&mut self) -> FileDes {
        FileDes { fd: self.detach() }
    }

    pub fn i_absolutely_need_the_raw_value(&self) -> libc::c_int {
        self.fd
    }

    pub fn replace_stdin(&self) -> bool {
        self.replace_fd(libc::STDIN_FILENO).detach() == libc::STDIN_FILENO
    }
    pub fn replace_stdout(&self) -> bool {
        self.replace_fd(libc::STDOUT_FILENO).detach() == libc::STDOUT_FILENO
    }
    pub fn replace_stderr(&self) -> bool {
        self.replace_fd(libc::STDERR_FILENO).detach() == libc::STDERR_FILENO
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, libc::ssize_t> {
        let r = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as libc::size_t) };
        if r >= 0 {
            let n = r as usize;
            Ok(n)
        } else {
            Err(r)
        }
    }
    pub fn write(&self, buf: &[u8]) -> Result<usize, libc::ssize_t> {
        let r = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len() as libc::size_t) };
        if r >= 0 {
            let n = r as usize;
            Ok(n)
        } else {
            Err(r)
        }
    }

    pub unsafe fn ioctl_mut_ulong(&self, request: libc::c_ulong, arg: libc::c_ulong) -> Result<libc::c_ulong, libc::c_int> {
        let mut arg = arg;
        let r = unsafe { libc::ioctl(self.fd, request, &mut arg) };
        if r >= 0 {
            Ok(arg)
        } else {
            Err(r)
        }
    }
    pub unsafe fn ioctl<T>(&self, request: libc::c_ulong, arg: T) -> Result<libc::c_int, libc::c_int> {
        let r = unsafe { libc::ioctl(self.fd, request, arg) };
        if r >= 0 {
            Ok(r)
        } else {
            Err(r)
        }
    }
}

impl Drop for FileDes {
    fn drop(&mut self) {
        self.close();
    }
}

impl Clone for FileDes {
    fn clone(&self) -> FileDes {
        FileDes { fd: unsafe { libc::dup(self.fd) } }
    }
}