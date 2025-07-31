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

use crate::{lfd_mod, linkfd};
use crate::tunnel::VtunCmd;

#[derive(Clone)]
pub struct VtunSopt {
    pub dev: Option<String>,
    pub laddr: Option<String>,
    pub lport: libc::c_int,
    pub raddr: Option<String>,
    pub rport: libc::c_int,
    pub host: Option<String>
}

impl VtunSopt {
    pub fn new() -> Self {
        Self {
            dev: None,
            laddr: None,
            lport: 0,
            raddr: None,
            rport: 0,
            host: None
        }
    }
}

#[derive(Clone)]
pub struct VtunAddr {
    pub name: Option<String>,
    pub ip: Option<String>,
    pub port: libc::c_int,
    pub type_: libc::c_int,
}

impl VtunAddr {
    pub fn new() -> Self {
        Self {
            name: None,
            ip: None,
            port: 0,
            type_: 0,
        }
    }
}

#[derive(Clone)]
pub struct VtunHost {
    pub host: Option<String>,
    pub passwd: Option<String>,
    pub dev: Option<String>,
    pub up: Vec<VtunCmd>,
    pub down: Vec<VtunCmd>,
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
    pub sopt: VtunSopt,
}

impl VtunHost {
    pub fn new() -> Self {
        Self {
            host: None,
            passwd: None,
            dev: None,
            up: Vec::new(),
            down: Vec::new(),
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
        match &self.host {
            Some(host) => host.as_str(),
            None => ""
        }
    }
}
