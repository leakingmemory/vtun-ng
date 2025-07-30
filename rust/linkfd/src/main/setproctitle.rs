/*
    VTun - Virtual Tunnel over TCP/IP network.

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

/*
 * This stuff is very close to, if not actually, impossible with
 * rust. There are maybe some syscalls accesible as root, so potentially
 * those could be invoked if getuid() == 0
 */

pub fn init_title() {
}

pub fn set_title(title: &str) {
    proctitle::set_title(title);
}
