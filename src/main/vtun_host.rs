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

use std::ptr;
use crate::{lfd_mod, linkfd, llist};

fn free_non_null(ptr: *mut libc::c_char) {
    if !ptr.is_null() {
        unsafe {
            libc::free(ptr as *mut libc::c_void);
        }
    }
}

fn strdup(str: *mut libc::c_char) -> *mut libc::c_char {
    if str.is_null() {
        return ptr::null_mut();
    }
    unsafe { libc::strdup(str) }
}

#[repr(C)]
pub struct VtunSopt {
    pub dev: *mut libc::c_char,
    pub laddr: *mut libc::c_char,
    pub lport: libc::c_int,
    pub raddr: *mut libc::c_char,
    pub rport: libc::c_int,
    pub host: *mut libc::c_char,
}

impl VtunSopt {
    pub fn new() -> Self {
        Self {
            dev: ptr::null_mut(),
            laddr: ptr::null_mut(),
            lport: 0,
            raddr: ptr::null_mut(),
            rport: 0,
            host: ptr::null_mut()
        }
    }
}

impl Clone for VtunSopt {
    fn clone(&self) -> Self {
        Self {
            dev: strdup(self.dev),
            laddr: strdup(self.laddr),
            lport: self.lport,
            raddr: strdup(self.raddr),
            rport: self.rport,
            host: strdup(self.host),
        }
    }
}

impl Drop for VtunSopt {
    fn drop(&mut self) {
        free_non_null(self.dev);
        free_non_null(self.laddr);
        free_non_null(self.raddr);
        free_non_null(self.host);
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct VtunStat {
    pub byte_in: u64,
    pub byte_out: u64,
    pub comp_in: u64,
    pub comp_out: u64,
    pub file: *mut libc::c_void,
}

impl VtunStat {
    pub fn new() -> Self {
        Self {
            byte_in: 0,
            byte_out: 0,
            comp_in: 0,
            comp_out: 0,
            file: ptr::null_mut(),
        }
    }
}

#[repr(C)]
pub struct VtunAddr {
    pub name: *mut libc::c_char,
    pub ip: *mut libc::c_char,
    pub port: libc::c_int,
    pub type_: libc::c_int,
}

impl VtunAddr {
    pub fn new() -> Self {
        Self {
            name: ptr::null_mut(),
            ip: ptr::null_mut(),
            port: 0,
            type_: 0,
        }
    }
}

impl Clone for VtunAddr {
    fn clone(&self) -> Self {
        Self {
            name: strdup(self.name),
            ip: strdup(self.ip),
            port: self.port,
            type_: self.type_,
        }
    }
}

impl Drop for VtunAddr {
    fn drop(&mut self) {
        free_non_null(self.name);
        free_non_null(self.ip);
    }
}

#[repr(C)]
pub struct VtunHost {
    pub host: *mut libc::c_char,
    pub passwd: *mut libc::c_char,
    pub dev: *mut libc::c_char,
    pub up: llist::LList,
    pub down: llist::LList,
    pub flags: libc::c_int,
    pub timeout: libc::c_int,
    pub spd_in: libc::c_int,
    pub spd_out: libc::c_int,
    pub zlevel: libc::c_int,
    pub cipher: libc::c_int,
    pub rmt_fd: libc::c_int,
    pub loc_fd: libc::c_int,
    pub persist: libc::c_int,
    pub multi: libc::c_int,
    pub ka_interval: libc::c_int,
    pub ka_maxfail: libc::c_int,
    pub src_addr: VtunAddr,
    pub stat: VtunStat,
    pub sopt: VtunSopt,
}

impl VtunHost {
    pub fn new() -> Self {
        Self {
            host: ptr::null_mut(),
            passwd: ptr::null_mut(),
            dev: ptr::null_mut(),
            up: llist::LList::new(),
            down: llist::LList::new(),
            flags: linkfd::VTUN_TTY | linkfd::VTUN_TCP,
            timeout: lfd_mod::VTUN_CONNECT_TIMEOUT,
            spd_in: 0,
            spd_out: 0,
            zlevel: 0,
            cipher: 0,
            rmt_fd: -1,
            loc_fd: -1,
            persist: 0,
            multi: lfd_mod::VTUN_MULTI_ALLOW,
            ka_interval: 30,
            ka_maxfail: 4,
            src_addr: VtunAddr::new(),
            stat: VtunStat::new(),
            sopt: VtunSopt::new(),
        }
    }
    pub fn clear_nat_hack_server(&mut self)
    {
        self.flags = self.flags & !lfd_mod::VTUN_NAT_HACK_CLIENT;
    }

    pub fn clear_nat_hack_client(&mut self)
    {
        self.flags = self.flags & !lfd_mod::VTUN_NAT_HACK_SERVER;
    }

    pub fn host_name(&self) -> &str
    {
        unsafe {
            std::ffi::CStr::from_ptr(self.host).to_str().unwrap()
        }
    }
}

impl Clone for VtunHost {
    fn clone(&self) -> Self {
        Self {
            host: strdup(self.host),
            passwd: strdup(self.passwd),
            dev: strdup(self.dev),
            up: self.up.clone(),
            down: self.down.clone(),
            flags: self.flags,
            timeout: self.timeout,
            spd_in: self.spd_in,
            spd_out: self.spd_out,
            zlevel: self.zlevel,
            cipher: self.cipher,
            rmt_fd: self.rmt_fd,
            loc_fd: self.loc_fd,
            persist: self.persist,
            multi: self.multi,
            ka_interval: self.ka_interval,
            ka_maxfail: self.ka_maxfail,
            src_addr: self.src_addr.clone(),
            stat: self.stat.clone(),
            sopt: self.sopt.clone()
        }
    }
}
