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

use crate::lfd_mod;

extern "C" {
    #[no_mangle]
    pub fn find_host(host: *const libc::c_char) -> *mut lfd_mod::VtunHost;
}

pub fn find_host_rs(host: &str) -> Option<&mut lfd_mod::VtunHost> {
    unsafe {
        let mut host = host.to_string();
        host.push_str("\0");
        let host = find_host(host.as_ptr() as *const libc::c_char);
        if host.is_null() {
            return None;
        }
        Some( &mut *host)
    }
}
