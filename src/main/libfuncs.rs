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
use crate::{auth, linkfd};
/* Read exactly len bytes (Signal safe)*/
pub fn read_n(fd: libc::c_int, buf: &mut [u8]) -> Option<usize>
{
    let mut off = 0;

    while linkfd::is_io_cancelled() == 0 && off < buf.len() {
        let w = unsafe { libc::read(fd, buf.as_ptr().add(off) as *mut libc::c_void, buf.len() - off) };
        if w < 0 {
            let errno = errno::errno();
            if errno == errno::Errno(libc::EINTR) || errno == errno::Errno(libc::EAGAIN) {
                continue;
            }
            return None;
        }
        if w == 0 {
            return Some(off);
        }
        off = off + w as usize;
    }
    Some(off)
}

pub fn readn_t(fd: libc::c_int, buf: &mut [u8], timeout: libc::time_t) -> libc::c_int
{
    let mut fdset: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe {
        libc::FD_ZERO(&mut fdset);
        libc::FD_SET(fd, &mut fdset);
    }
    let mut tv: libc::timeval = libc::timeval {
        tv_usec: 0, tv_sec: timeout
    };

    unsafe {
        if libc::select(fd+1,&mut fdset, null_mut(), null_mut(), &mut tv) <= 0 {
            return -1;
        }
    }

    match read_n(fd, buf) {
        Some(n) => n as libc::c_int,
        None => -1
    }
}

/* Write exactly len bytes (Signal safe)*/
pub fn write_n(fd: libc::c_int, buf: &[u8]) -> Option<usize>
{
    let mut t: usize = 0;

    while linkfd::is_io_cancelled() == 0 && t < buf.len() {
        let w = unsafe { libc::write(fd, buf[t..buf.len()].as_ptr() as *const libc::c_void, buf.len() - t) };
        if w < 0 {
            let errno = errno::errno();
            if errno == errno::Errno(libc::EINTR) || errno == errno::Errno(libc::EAGAIN) {
                continue;
            }
            return None;
        }
        if w == 0 {
            return Some(t);
        }
        t = t + w as usize;
    }
    Some(t)
}

pub fn print_p(fd: libc::c_int, buf: &[u8]) -> bool {
    let mut padded = [0u8; auth::VTUN_MESG_SIZE];
    for i in 0..buf.len() {
        if i >= auth::VTUN_MESG_SIZE {
            break;
        }
        padded[i] = buf[i];
    }
    let res = unsafe { libc::write(fd, padded.as_ptr() as *const libc::c_void, auth::VTUN_MESG_SIZE) };
    res == auth::VTUN_MESG_SIZE as libc::ssize_t
}
