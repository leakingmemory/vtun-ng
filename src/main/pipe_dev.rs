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
use crate::filedes::FileDes;

pub(crate) struct PipeDev {
    pub fd1: FileDes,
    pub fd2: FileDes
}

impl PipeDev {
    pub fn new() -> Option<Self> {
        match FileDes::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0) {
            Ok(res) => Some(PipeDev { fd1: res.0, fd2: res.1 }),
            Err(_) => None
        }
    }
    pub fn new_from_fd(fd: FileDes) -> Self {
        PipeDev { fd1: FileDes::new(), fd2: fd }
    }
    pub fn close(&mut self) {
        if self.fd1.ok() {
            self.fd1.close();
        }
        if self.fd2.ok() {
            self.fd2.close();
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
        let res = self.fd1.write(buf);
        match res {
            Ok(res) => Some(res),
            Err(_) => None
        }
    }
    fn read(&self, buf: &mut Vec<u8>, len: usize) -> bool {
        buf.resize(len, 0);
        let res = self.fd1.read(buf);
        let res = match res {
            Ok(res) => res,
            Err(_) => return false
        };
        buf.truncate(res);
        true
    }
    fn io_fd(&self) -> Option<&FileDes> {
        Some(&self.fd2)
    }
    fn detach(&mut self) -> FileDes {
        self.fd2.move_out()
    }
    fn close_first_pipe_fd(&mut self) {
        self.fd1.close();
    }
    fn clone_second_pipe_fd(&self) -> FileDes {
        self.fd2.clone()
    }
    fn close_second_pipe_fd(&mut self) {
        self.fd2.close();
    }
}