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
use crate::fdselect;

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
    pub fn socket(domain: libc::c_int, type_: libc::c_int, protocol: libc::c_int) -> FileDes {
        FileDes {
            fd: unsafe { libc::socket(domain, type_, protocol) }
        }
    }

    #[cfg(target_os = "linux")]
    pub fn getpt() -> FileDes {
        FileDes { fd: unsafe { libc::getpt() } }
    }

    #[cfg(target_os = "linux")]
    pub fn grantpt(&self) -> bool {
        unsafe { libc::grantpt(self.fd) == 0 }
    }

    #[cfg(target_os = "linux")]
    pub fn unlockpt(&self) -> bool {
        unsafe { libc::unlockpt(self.fd) == 0 }
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

    pub fn clone_stdin() -> FileDes {
        FileDes { fd: unsafe { libc::dup(libc::STDIN_FILENO) } }
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

    pub fn recvfrom_sockaddr_in(&self, buf: &mut [u8], addr: &mut libc::sockaddr_in, flags: libc::c_int) -> Result<usize, libc::ssize_t> {
        let len = buf.len();
        let mut addrlen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let res = unsafe { libc::recvfrom(self.fd, buf.as_mut_ptr() as *mut libc::c_void, len, flags, (addr as *mut libc::sockaddr_in).cast(), &mut addrlen) };
        if res >= 0 {
            Ok(res as usize)
        } else {
            Err(res)
        }
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
    pub fn read_both(&self, buf1: &mut [u8], buf2: &mut [u8]) -> Result<usize, libc::ssize_t> {
        let len1 = buf1.len();
        let len2 = buf2.len();
        let iov: [libc::iovec; 2] = [
            libc::iovec { iov_base: buf1.as_mut_ptr() as *mut libc::c_void, iov_len: len1 },
            libc::iovec { iov_base: buf2.as_mut_ptr() as *mut libc::c_void, iov_len: len2 }
        ];
        let r = unsafe { libc::readv(self.fd, iov.as_ptr(), 2) };
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
    // open for more when needed
    #[cfg(target_os = "openbsd")]
    pub fn write_both(&self, buf1: &[u8], buf2: &[u8]) -> Result<usize, libc::ssize_t> {
        let len1 = buf1.len();
        let len2 = buf2.len();
        let iov: [libc::iovec; 2] = [
            libc::iovec { iov_base: buf1.as_ptr() as *mut libc::c_void, iov_len: len1 },
            libc::iovec { iov_base: buf2.as_ptr() as *mut libc::c_void, iov_len: len2 }
        ];
        let r = unsafe { libc::writev(self.fd, iov.as_ptr(), 2) };
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
    // enable when needed
    #[cfg(target_os = "linux")]
    pub unsafe fn ioctl<T>(&self, request: libc::c_ulong, arg: T) -> Result<libc::c_int, libc::c_int> {
        let r = unsafe { libc::ioctl(self.fd, request, arg) };
        if r >= 0 {
            Ok(r)
        } else {
            Err(r)
        }
    }

    pub fn set_so_reuseaddr(&self, val: bool) -> bool {
        let val: libc::c_int = if val { 1 } else { 0 };
        unsafe { libc::setsockopt(self.fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &val as *const libc::c_int as *const libc::c_void, size_of::<libc::c_int>() as libc::socklen_t) == 0 }
    }

    pub fn bind_sockaddr_in(&self, addr: &libc::sockaddr_in) -> bool {
        unsafe { libc::bind(self.fd, (addr as *const libc::sockaddr_in).cast(), size_of::<libc::sockaddr_in>() as libc::socklen_t) == 0 }
    }

    pub fn fcntl_getfl(&self) -> Result<libc::c_int, libc::c_int> {
        let r = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if r >= 0 {
            Ok(r)
        } else {
            Err(r)
        }
    }
    pub fn fcntl_setfl(&self, flags: libc::c_int) -> bool {
        unsafe { libc::fcntl(self.fd, libc::F_SETFL, flags) == 0 }
    }

    pub fn connect_sockaddr_in(&self, addr: &libc::sockaddr_in) -> bool {
        unsafe { libc::connect(self.fd, (addr as *const libc::sockaddr_in).cast(), size_of::<libc::sockaddr_in>() as libc::socklen_t) == 0 }
    }

    pub fn get_so_error(&self) -> Result<libc::c_int, libc::c_int> {
        let mut errno: libc::c_int = 0;
        let mut l: libc::socklen_t = size_of::<libc::c_int>() as libc::socklen_t;
        if unsafe { libc::getsockopt(self.fd,libc::SOL_SOCKET,libc::SO_ERROR,&mut errno as *mut libc::c_int as *mut libc::c_void,&mut l) == 0 } {
            Ok(errno)
        } else {
            Err(-1)
        }
    }

    pub fn getsockname_sockaddr_in(&self, addr: &mut libc::sockaddr_in) -> bool {
        let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        unsafe { libc::getsockname(self.fd, (addr as *mut libc::sockaddr_in).cast(), &mut len) == 0 }
    }

    pub fn set_so_keepalive(&self, val: bool) -> bool {
        let val: libc::c_int = if val { 1 } else { 0 };
        unsafe { libc::setsockopt(self.fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, &val as *const libc::c_int as *const libc::c_void, size_of::<libc::c_int>() as libc::socklen_t) == 0 }
    }

    pub fn set_tcp_nodelay(&self, val: bool) -> bool {
        let val: libc::c_int = if val { 1 } else { 0 };
        unsafe { libc::setsockopt(self.fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, &val as *const libc::c_int as *const libc::c_void, size_of::<libc::c_int>() as libc::socklen_t) == 0 }
    }

    pub fn getpeername_sockaddr_in(&self, addr: &mut libc::sockaddr_in) -> bool {
        let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        unsafe { libc::getpeername(self.fd, (addr as *mut libc::sockaddr_in).cast(), &mut len) == 0 }
    }

    pub fn listen(&self, backlog: libc::c_int) -> bool {
        unsafe { libc::listen(self.fd, backlog) == 0 }
    }

    pub fn accept_sockaddr_in(&self, addr: &mut libc::sockaddr_in) -> Result<FileDes, libc::c_int> {
        let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let s = unsafe { libc::accept(self.fd, (addr as *mut libc::sockaddr_in).cast(), &mut len) };
        if s >= 0 {
            Ok(FileDes { fd: s })
        } else {
            Err(s)
        }
    }

    pub fn wait_for_read_with_timeout(&self, timeout: libc::time_t) -> Result<bool, libc::c_int> {
        let mut fds: Vec<libc::c_int> = Vec::new();
        fds.push(self.fd);
        let res = fdselect::select_read_timeout(&mut fds, timeout);
        if res >= 0 {
            Ok(res > 0)
        } else {
            Err(res)
        }
    }
    pub fn wait_for_write_with_timeout(&self, timeout: libc::time_t) -> Result<bool, libc::c_int> {
        let mut fds: Vec<libc::c_int> = Vec::new();
        fds.push(self.fd);
        let res = fdselect::select_write_timeout(&mut fds, timeout);
        if res >= 0 {
            Ok(res > 0)
        } else {
            Err(res)
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