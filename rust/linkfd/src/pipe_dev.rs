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
use crate::driver;

pub(crate) struct PipeDev {
    pub fd1: i32,
    pub fd2: i32
}

impl PipeDev {
    pub fn new() -> Option<Self> {
        let mut fd: [i32; 2] = [0i32; 2];
        let res = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, &mut fd as *mut _) };
        if res >= 0 {
            Some(PipeDev { fd1: fd[0], fd2: fd[1] })
        } else {
            None
        }
    }
    pub fn close(&mut self) {
        if self.fd1 >= 0 {
            unsafe {
                libc::close(self.fd1);
            }
            self.fd1 = -1;
        }
        if self.fd2 >= 0 {
            unsafe { libc::close(self.fd2); }
            self.fd2 = -1;
        }
    }
}

impl Drop for PipeDev {
    fn drop(&mut self) {
        self.close();
    }
}

impl driver::Driver for PipeDev {
    fn write(&self, buf: &[u8]) -> Option<usize> {
        let res = unsafe {
            libc::write(self.fd1, buf.as_ptr() as *mut libc::c_void, buf.len())
        };
        if res < 0 {
            return None;
        }
        Some(res as usize)
    }
    fn read(&self, buf: &mut Vec<u8>, len: usize) -> bool {
        buf.resize(len, 0);
        let res = unsafe {
            libc::read(self.fd1, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        if res < 0 {
            return false;
        }
        buf.truncate(res as usize);
        true
    }
    fn io_fd(&self) -> i32 {
        self.fd2
    }
    fn close_first_pipe_fd(&mut self) {
        if self.fd1 >= 0 {
            unsafe {
                libc::close(self.fd1);
            }
            self.fd1 = -1;
        }
    }
    fn second_pipe_fd(&self) -> i32 {
        self.fd2
    }
    fn close_second_pipe_fd(&mut self) {
        if self.fd2 >= 0 {
            unsafe { libc::close(self.fd2); }
            self.fd2 = -1;
        }
    }
}