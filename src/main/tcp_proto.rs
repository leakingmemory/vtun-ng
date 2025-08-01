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
use crate::{driver, linkfd, mainvtun};
use crate::filedes::FileDes;

pub(crate) struct TcpProto {
    pub fd: FileDes
}

impl driver::NetworkDriver for TcpProto {
    fn io_fd(&self) -> &FileDes {
        &self.fd
    }
    fn write(&self, buf: &mut Vec<u8>, flags: u16) -> Option<usize> {
        let payloadlen = buf.len();
        if (payloadlen & linkfd::VTUN_FSIZE_MASK as usize) != payloadlen || (flags & linkfd::VTUN_FSIZE_MASK as u16) != 0 {
            return None;
        }
        buf.resize(payloadlen + 2, 0u8);
        for i in 0..payloadlen {
            buf[payloadlen - i + 1] = buf[payloadlen - i - 1];
        }
        let prefix = payloadlen | flags as usize;
        buf[0] = ((prefix & 0xff00) >> 8) as u8;
        buf[1] = (prefix & 0xff) as u8;

        match self.fd.write(buf) {
            Ok(wres) => Some(wres),
            Err(_) => None
        }
    }
    fn read(&mut self, _ctx: &mut mainvtun::VtunContext, buf: &mut Vec<u8>) -> Option<u16> {
        let mut len: usize;
        let flags: u16;

        /* Read frame size */
        {
            let mut prefix: u16;
            let mut prefixbuf: [u8; 2] = [0u8; 2];
            loop {
                match self.fd.read(&mut prefixbuf) {
                    Ok(rlen) => {
                        if rlen == 2 {
                            break;
                        }
                        if rlen == 1 {
                            let mut tmpbuf: [u8; 1] = [0u8; 1];
                            loop {
                                match self.fd.read(&mut tmpbuf) {
                                    Ok(rlen) => {
                                        if rlen == 1 {
                                            break;
                                        }
                                    },
                                    Err(_) => {
                                        let errno = errno::errno();
                                        if errno == errno::Errno(libc::EAGAIN) || errno == errno::Errno(libc::EINTR) {
                                            continue;
                                        }
                                    }
                                };
                                return None;
                            }
                            prefixbuf[1] = tmpbuf[0];
                            break;
                        }
                    }
                    Err(_) => {
                        let errno = errno::errno();
                        if errno == errno::Errno(libc::EAGAIN) || errno == errno::Errno(libc::EINTR) {
                            continue;
                        }
                        return None;
                    }
                }
                return None;
            }
            prefix = prefixbuf[0] as u16;
            prefix = prefix << 8;
            prefix = prefix + (prefixbuf[1] as u16);
            flags = prefix & !(linkfd::VTUN_FSIZE_MASK as u16);
            len = (prefix & linkfd::VTUN_FSIZE_MASK as u16) as usize;
        }

        if len > linkfd::VTUN_FRAME_SIZE + linkfd::VTUN_FRAME_OVERHEAD {
            /* Oversized frame, drop it. */
            buf.clear();
            while len > 0 {
                let mut rdlen = linkfd::VTUN_FRAME_SIZE;
                if len < rdlen {
                    rdlen = len;
                }
                buf.resize(rdlen, 0u8);
                match self.fd.read(buf) {
                    Ok(rlen) => {
                        len = len - rlen;
                    },
                    Err(_) => {
                        let errno = errno::errno();
                        if errno == errno::Errno(libc::EAGAIN) || errno == errno::Errno(libc::EINTR) {
                            continue;
                        }
                        break;
                    }
                };
            }
            buf.clear();
            return Some(0);
        }

        /*
         * Comment when reimplementing in vtun-ng:
         * This could get weird if a frame was sent with
         * both flags and a frame length other than 0. Looks
         * like worst case we would be thrown out of sync with
         * the writer in that case, to only observe junk after
         * that.
         */
        if flags != 0 {
            /* Return flags */
            buf.clear();
            return Some(flags);
        }

        /* Read frame */
        buf.resize(len, 0u8);
        let mut offset: usize = 0;
        let mut err: bool = false;
        loop {
            match self.fd.read(&mut buf[offset..]) {
                Ok(rlen) => {
                    offset = offset + rlen;
                    if rlen > 0 && offset < len {
                        continue;
                    }
                    break;
                },
                Err(_) => {
                    let errno = errno::errno();
                    if errno == errno::Errno(libc::EAGAIN) || errno == errno::Errno(libc::EINTR) {
                        continue;
                    }
                    err = true;
                    break;
                }
            };
        }
        if err || offset < len {
            buf.clear();
            return None;
        }
        Some(flags)
    }
}