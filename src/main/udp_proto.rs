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
use std::ptr::null_mut;
use crate::{driver, lfd_mod, linkfd, mainvtun, syslog};
use crate::filedes::FileDes;

pub(crate) struct UdpProto {
    pub fd: FileDes
}

impl UdpProto {
    #[cfg(not(target_os = "linux"))] /* freebsd */
    fn create_sockaddr_in() -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: 0,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0i8; 8],
            sin_len: 0
        }
    }
    #[cfg(target_os = "linux")] /* linux */
    fn create_sockaddr_in() -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: 0,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0u8; 8],
        }
    }
}

impl driver::NetworkDriver for UdpProto {
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
        let prefix = (payloadlen as u16) | flags;
        buf[0] = ((prefix & 0xff00) >> 8) as u8;
        buf[1] = (prefix & 0xff) as u8;

        loop {
            return match self.fd.write(buf) {
                Ok(wlen) => Some(wlen),
                Err(_) => {
                    let errno = errno::errno();
                    if errno == errno::Errno(libc::EAGAIN) || errno == errno::Errno(libc::EINTR) {
                        continue;
                    }
                    None
                }
            };
        }
    }

    fn read(&mut self, ctx: &mut mainvtun::VtunContext, buf: &mut Vec<u8>) -> Option<u16> {
        let mut hdrbuf: [u8; 2] = [0u8; 2];
        let mut iv: [libc::iovec; 2] = [libc::iovec { iov_base: null_mut(), iov_len: 0 }; 2];
        let mut from: libc::sockaddr_in = UdpProto::create_sockaddr_in();

        /* Late connect (NAT hack enabled) */
        if !ctx.is_rmt_fd_connected {
            loop {
                match self.fd.recvfrom_sockaddr_in(&mut hdrbuf, &mut from, libc::MSG_PEEK) {
                    Ok(_) => break,
                    Err(_) => {
                        let errno = errno::errno();
                        if errno == errno::Errno(libc::EAGAIN) || errno == errno::Errno(libc::EINTR) { continue; }
                        else { return None; }
                    }
                }
            }
            if !self.fd.connect_sockaddr_in(&from) {
                syslog::vtun_syslog(lfd_mod::LOG_ERR,"Can't connect socket");
                return None;
            }
            ctx.is_rmt_fd_connected = true;
        }

        /* Read frame */
        buf.resize(linkfd::VTUN_FRAME_SIZE + linkfd::VTUN_FRAME_OVERHEAD, 0u8);
        iv[0].iov_len  = size_of::<libc::c_short>();
        iv[0].iov_base = &mut hdrbuf as *mut u8 as *mut libc::c_void;
        iv[1].iov_len  = linkfd::VTUN_FRAME_SIZE + linkfd::VTUN_FRAME_OVERHEAD;
        iv[1].iov_base = buf.as_mut_ptr() as *mut libc::c_void;

        let mut hdr: u16;
        loop {
            let rlen = match self.fd.read_both(&mut hdrbuf, buf) {
                Ok(rlen) => rlen,
                Err(_) => {
                    let errno = errno::errno();
                    if errno == errno::Errno(libc::EAGAIN) || errno == errno::Errno(libc::EINTR) {
                        continue;
                    } else {
                        return None;
                    }
                }
            };
            hdr = hdrbuf[0] as u16;
            hdr = hdr << 8;
            hdr = hdr | hdrbuf[1] as u16;
            let flen = hdr & linkfd::VTUN_FSIZE_MASK as u16;
            let flags = hdr & !(linkfd::VTUN_FSIZE_MASK as u16);

            if rlen < 2 || (rlen - 2) != flen as usize {
                buf.clear();
                return None;
            }
            buf.resize(flen as usize, 0u8);

            return Some(flags);
        }
    }
}