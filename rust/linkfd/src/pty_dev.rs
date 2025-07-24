/*
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2016  Maxim Krasnyansky <max_mk@yahoo.com>
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
use std::ffi::CStr;
use crate::driver;

pub(crate) struct PtyDev{
    pub fd: i32,
    pub ptyname: Box<String>
}

impl PtyDev {
    pub fn new() -> Option<Self> {
        /*
         * At first it appears that getpt is available on if not all,
         * at least most of, unices in use today. Lets go with that at
         * first, and if it breaks we'll add new implementations using
         * #cfg-annotations.
         */
        let fd = unsafe { libc::getpt() };
        if fd < 0 {
            return None;
        }
        if unsafe { libc::grantpt(fd) } < 0 {
            unsafe { libc::close(fd); }
            return None;
        }
        if unsafe { libc::unlockpt(fd) } < 0 {
            unsafe { libc::close(fd); }
            return None;
        }
        /*
         * Would prefer ptsname_r, but as far as I remember it is
         * not available on all platforms. But at some point
         * because subsequent calls will overwrite the buffer.
         * But it's not really a problem in a single threaded app.
         */
        let ptyname = unsafe {CStr::from_ptr(libc::ptsname(fd))}.to_str().unwrap();
        Some(PtyDev {
            fd, ptyname: Box::new(ptyname.to_string())
        })
    }
    pub fn new_from_fd(fd: i32, ptyname: &str) -> Self {
        PtyDev {
            fd, ptyname: Box::new(ptyname.to_string())
        }
    }
    pub fn close(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}

impl Drop for PtyDev {
    fn drop(&mut self) {
        self.close();
    }
}

impl driver::Driver for PtyDev {
    fn write(&self, buf: &[u8]) -> Option<usize> {
        let res = unsafe {
            libc::write(self.fd, buf.as_ptr() as *mut libc::c_void, buf.len())
        };
        if res < 0 {
            return None;
        }
        Some(res as usize)
    }
    fn read(&self, buf: &mut Vec<u8>, len: usize) -> bool {
        buf.resize(len, 0);
        let res = unsafe {
            libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        if res < 0 {
            return false;
        }
        buf.truncate(res as usize);
        true
    }
    fn io_fd(&self) -> i32 {
        self.fd
    }
    fn detach(&mut self) -> i32 {
        let fd = self.fd;
        self.fd = -1;
        fd
    }
    fn close_first_pipe_fd(&mut self) {
        self.close();
    }
}