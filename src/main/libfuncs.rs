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

/* Read N bytes with timeout */
use std::ptr::null_mut;
use crate::{auth};
use crate::filedes::FileDes;
use crate::linkfd::LinkfdCtx;
/* Read exactly len bytes (Signal safe)*/
pub fn read_n(linkfdctx: &LinkfdCtx, fd: &FileDes, buf: &mut [u8]) -> Option<usize>
{
    let mut off = 0;

    while !linkfdctx.is_io_cancelled() && off < buf.len() {
        let w = match fd.read(&mut buf[off..]) {
            Ok(w) => w,
            Err(_) => {
                let errno = errno::errno();
                if errno == errno::Errno(libc::EINTR) || errno == errno::Errno(libc::EAGAIN) {
                    continue;
                }
                return None;
            }
        };
        if w == 0 {
            return Some(off);
        }
        off = off + w;
    }
    Some(off)
}

pub fn readn_t(linkfdctx: &LinkfdCtx, fd: &FileDes, buf: &mut [u8], timeout: libc::time_t) -> libc::c_int
{
    let mut fdset: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe {
        libc::FD_ZERO(&mut fdset);
        libc::FD_SET(fd.i_absolutely_need_the_raw_value(), &mut fdset);
    }
    let mut tv: libc::timeval = libc::timeval {
        tv_usec: 0, tv_sec: timeout
    };

    unsafe {
        if libc::select(fd.i_absolutely_need_the_raw_value()+1,&mut fdset, null_mut(), null_mut(), &mut tv) <= 0 {
            return -1;
        }
    }

    match read_n(linkfdctx, fd, buf) {
        Some(n) => n as libc::c_int,
        None => -1
    }
}

/* Write exactly len bytes (Signal safe)*/
pub fn write_n(linkfdctx: &LinkfdCtx, fd: &FileDes, buf: &[u8]) -> Option<usize>
{
    let mut t: usize = 0;

    while !linkfdctx.is_io_cancelled() && t < buf.len() {
        match fd.write(&buf[t..buf.len()]) {
            Ok(w) => {
                if w == 0 {
                    return Some(t);
                }
                t = t + w;
            },
            Err(_) => {
                let errno = errno::errno();
                if errno == errno::Errno(libc::EINTR) || errno == errno::Errno(libc::EAGAIN) {
                    continue;
                }
                return None;
            }
        };
    }
    Some(t)
}

pub fn print_p(fd: &FileDes, buf: &[u8]) -> bool {
    let mut padded = [0u8; auth::VTUN_MESG_SIZE];
    for i in 0..buf.len() {
        if i >= auth::VTUN_MESG_SIZE {
            break;
        }
        padded[i] = buf[i];
    }
    match fd.write(&padded) {
        Ok(res) => res == auth::VTUN_MESG_SIZE,
        Err(_) => false
    }
}
