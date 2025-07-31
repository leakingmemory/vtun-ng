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

pub(crate) struct PtyDev{
    pub fd: FileDes,
    pub ptyname: Box<String>
}

impl PtyDev {
    #[cfg(not(target_os = "linux"))]
    pub fn new() -> Option<Self> {
        let mut ptyname: [u8;10] = [0u8; 10];
        {
            let const_ptyname = "/dev/ptyXY".as_bytes();
            for i in 0..const_ptyname.len() {
                ptyname[i] = const_ptyname[i];
            }
        }
        let ch = "pqrstuvwxyz".as_bytes();
        let digit = "0123456789abcdefghijklmnopqrstuv".as_bytes();

        /* This algorithm should work for almost all standard Unices */
        for l in 0..ch.len() {
            for m in 0..digit.len() {
                ptyname[8 as usize] = ch[l];
                ptyname[9 as usize] = digit[m];
                let nm = String::from_utf8(ptyname.to_vec()).unwrap();
                /* Open the master */
                let mut mr_fd= FileDes::open_m(nm.as_str(), libc::O_RDWR);
                if !mr_fd.ok() {
                    continue;
                }
                /* Check the slave */
                ptyname[5 as usize] = 't' as u8;
                if unsafe { libc::access(ptyname.as_ptr() as *const i8, libc::R_OK | libc::W_OK) } < 0 {
                    mr_fd.close();
                    ptyname[5 as usize] = 'p' as u8;
                    continue;
                }
                return Some(Self {
                    fd: mr_fd,
                    ptyname: Box::new(str::from_utf8(&ptyname).unwrap().to_string())
                });
            }
        }
        None
    }
    #[cfg(target_os = "linux")]
    pub fn new() -> Option<Self> {
        /*
         * At first it appears that getpt is available on if not all,
         * at least most of, unices in use today. Lets go with that at
         * first, and if it breaks we'll add new implementations using
         * #cfg-annotations.
         */
        let mut fd = FileDes::getpt();
        if !fd.ok() {
            return None;
        }
        if !fd.grantpt() {
            fd.close();
            return None;
        }
        if !fd.unlockpt() {
            fd.close();
            return None;
        }
        /*
         * Would prefer ptsname_r, but as far as I remember it is
         * not available on all platforms. But at some point
         * because subsequent calls will overwrite the buffer.
         * But it's not really a problem in a single threaded app.
         */
        let ptyname = match fd.ptsname() {
            Some(s) => s,
            None => {
                fd.close();
                return None;
            }
        };
        Some(PtyDev {
            fd, ptyname: Box::new(ptyname)
        })
    }
    pub fn new_from_fd(fd: FileDes, ptyname: &str) -> Self {
        PtyDev {
            fd, ptyname: Box::new(ptyname.to_string())
        }
    }
    pub fn close(&mut self) {
        self.fd.close();
    }
}

impl Drop for PtyDev {
    fn drop(&mut self) {
        self.close();
    }
}

impl driver::Driver for PtyDev {
    fn write(&self, buf: &[u8]) -> Option<usize> {
        match self.fd.write(buf) {
            Ok(n) => Some(n),
            Err(_) => None
        }
    }
    fn read(&self, buf: &mut Vec<u8>, len: usize) -> bool {
        buf.resize(len, 0);
        match self.fd.read(buf) {
            Ok(res) => {
                buf.truncate(res as usize);
                true
            },
            Err(_) => false
        }
    }
    fn io_fd(&self) -> Option<&FileDes> {
        Some(&self.fd)
    }
    fn detach(&mut self) -> FileDes {
        self.fd.move_out()
    }
    fn close_first_pipe_fd(&mut self) {
        self.close();
    }
}