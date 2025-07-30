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
use libc::LOG_DAEMON;
use crate::vtun_host;

#[repr(C)]
pub struct VtunOpts {
    pub timeout: libc::c_int,
    pub persist: libc::c_int,

    pub cfg_file: *mut libc::c_char,

    pub shell: *mut libc::c_char, /* Shell */
    pub ppp: *mut libc::c_char, /* Command to configure ppp devices */
    pub ifcfg: *mut libc::c_char, /* Command to configure net devices */
    pub route: *mut libc::c_char, /* Command to configure routing */
    pub fwall: *mut libc::c_char, /* Command to configure FireWall */
    pub iproute: *mut libc::c_char, /* iproute command */

    pub svr_name: *mut libc::c_char, /* Server's host name */
    pub svr_addr: *mut libc::c_char, /* Server's address (string) */
    pub bind_addr: vtun_host::VtunAddr, /* Server should listen on this address */
    pub svr_type: libc::c_int, /* Server mode */
    pub syslog: libc::c_int, /* Facility to log messages to syslog under */
    pub quiet: libc::c_int, /* Be quiet about common errors */
}

impl VtunOpts {
    pub(crate) fn new() -> Self {
        Self {
            timeout: -1,
            persist: -1,
            cfg_file: ptr::null_mut(),
            shell: ptr::null_mut(),
            ppp: ptr::null_mut(),
            ifcfg: ptr::null_mut(),
            route: ptr::null_mut(),
            fwall: ptr::null_mut(),
            iproute: ptr::null_mut(),

            svr_name: ptr::null_mut(),
            svr_addr: ptr::null_mut(),
            bind_addr: vtun_host::VtunAddr::new(),
            svr_type: -1,
            syslog: LOG_DAEMON,
            quiet: 0,
        }
    }
}

pub const VTUN_ENC_BF128ECB: libc::c_int = 1;
pub const VTUN_ENC_BF128CBC: libc::c_int = 2;
pub const VTUN_ENC_BF128CFB: libc::c_int = 3;
pub const VTUN_ENC_BF128OFB: libc::c_int = 4;
pub const VTUN_ENC_BF256ECB: libc::c_int = 5;
pub const VTUN_ENC_BF256CBC: libc::c_int = 6;
pub const VTUN_ENC_BF256CFB: libc::c_int = 7;
pub const VTUN_ENC_BF256OFB: libc::c_int = 8;

pub const VTUN_ENC_AES128ECB: libc::c_int = 9;
pub const VTUN_ENC_AES128CBC: libc::c_int = 10;
pub const VTUN_ENC_AES128CFB: libc::c_int = 11;
pub const VTUN_ENC_AES128OFB: libc::c_int = 12;
pub const VTUN_ENC_AES256ECB: libc::c_int = 13;
pub const VTUN_ENC_AES256CBC: libc::c_int = 14;
pub const VTUN_ENC_AES256CFB: libc::c_int = 15;
pub const VTUN_ENC_AES256OFB: libc::c_int = 16;

pub const VTUN_LEGACY_ENCRYPT: libc::c_int = 999;

/* Mask to drop the flags which will be supplied by the server */
pub const VTUN_CLNT_MASK: libc::c_int =  0xf000;

pub const  VTUN_PERSIST_KEEPIF: libc::c_int =     2;

/* Support for multiple connections */
pub const VTUN_MULTI_DENY: libc::c_int =	0;  /* no */
pub const VTUN_MULTI_ALLOW: libc::c_int =	1;  /* yes */
pub const VTUN_MULTI_KILL: libc::c_int =	2;

pub const VTUN_ADDR_IFACE: libc::c_int =	0x01;
pub const VTUN_ADDR_NAME: libc::c_int =  0x02;

pub const VTUN_STAND_ALONE: libc::c_int =	0;
pub const VTUN_INETD: libc::c_int =		1;

pub const VTUN_NAT_HACK_CLIENT: libc::c_int =	0x4000;
pub const VTUN_NAT_HACK_SERVER: libc::c_int =	0x8000;
pub const VTUN_NAT_HACK_MASK: libc::c_int =	(VTUN_NAT_HACK_CLIENT | VTUN_NAT_HACK_SERVER);

pub const VTUN_CONNECT_TIMEOUT: libc::c_int = 30;

pub const VTUN_VER: &str = "3.X 07/24/2025";

pub const LOG_EMERG: libc::c_int = 0;
pub const LOG_ALERT: libc::c_int = 1;
pub const LOG_CRIT: libc::c_int = 2;
pub const LOG_ERR: libc::c_int = 3;
pub const LOG_WARNING: libc::c_int = 4;
pub const LOG_NOTICE: libc::c_int = 5;
pub const LOG_INFO: libc::c_int = 6;
pub const LOG_DEBUG: libc::c_int = 7;

extern "C" {
    pub fn vtun_syslog(_priority: libc::c_int, _format: *mut libc::c_char);
}