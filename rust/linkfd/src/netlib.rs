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

use std::ffi::CStr;
use std::ptr;
use std::ptr::null_mut;
use libc::timeval;
use crate::{lfd_mod, vtun_host};
use crate::lfd_mod::VTUN_ADDR_NAME;

/* Connect with timeout */
pub fn connect_t(s: i32, svr: *const libc::sockaddr, timeout: libc::time_t) -> bool {
    let mut tv: timeval = timeval { tv_sec: timeout, tv_usec: 0 };

    let sock_flags= unsafe { libc::fcntl(s,libc::F_GETFL) };
    if unsafe { libc::fcntl(s,libc::F_SETFL,libc::O_NONBLOCK) } < 0 {
        return false;
    }

    if unsafe { libc::connect(s,svr,size_of::<libc::sockaddr>() as libc::socklen_t) } < 0 && errno::errno() != errno::Errno(libc::EINPROGRESS)
    {
        return false;
    }

    let mut fdset: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe {
        libc::FD_ZERO(&mut fdset);
        libc::FD_SET(s, &mut fdset);
    }
    let mut errno: libc::c_int;
    if unsafe { libc::select(s+1,ptr::null_mut(),&mut fdset,ptr::null_mut(),if timeout > 0 { &mut tv } else { ptr::null_mut() }) } > 0 {
        let mut l: libc::socklen_t = size_of::<libc::c_int>() as libc::socklen_t;
        errno=0;
        unsafe { libc::getsockopt(s,libc::SOL_SOCKET,libc::SO_ERROR,&mut errno as *mut libc::c_int as *mut libc::c_void,&mut l); }
    } else {
        errno = libc::ETIMEDOUT;
    }

    unsafe { libc::fcntl(s,libc::F_SETFL,sock_flags); }

    if errno == 0 {
        true
    } else {
        false
    }
}

/* Get interface address */
fn getifaddr(ifname: &str) -> Option<u32>
{
    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if s == -1 {
        return None;
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let ifname = ifname.as_bytes();
    for i in 0..ifname.len() {
        ifr.ifr_name[i] = if ifname[i] < 128 { ifname[i] as libc::c_char } else { (ifname[i] - 128u8) as libc::c_char - (127 as libc::c_char)};
    }

    if unsafe { libc::ioctl(s, libc::SIOCGIFADDR, &ifr) } < 0 {
        unsafe { libc::close(s); }
        return None;
    }
    unsafe { libc::close(s); }

    let addr: *const libc::sockaddr_in = unsafe { &(ifr.ifr_ifru.ifru_addr) as *const libc::sockaddr }.cast();

    let s_addr = Some(unsafe { &*addr} .sin_addr.s_addr);

    s_addr
}

/* Set local address */
pub fn local_addr_rs(addr: &mut libc::sockaddr_in, host: &mut vtun_host::VtunHost, con: bool) -> bool
{
    if con {
        /* Use address of the already connected socket. */
        let mut opt: libc::socklen_t = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if unsafe { libc::getsockname(host.rmt_fd, (addr as *mut libc::sockaddr_in).cast(), &mut opt) } < 0 {
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR,"Can't get local socket address\n\0".as_ptr() as *mut libc::c_char); }
            return false;
        }
    } else {
        if !generic_addr_rs(addr, &host.src_addr) {
            return false;
        }
    }

    // TODO - IPv6
    let mut ipv4addr = std::net::Ipv4Addr::from(addr.sin_addr.s_addr).to_string();
    ipv4addr.push_str("\0");
    host.sopt.laddr = unsafe { libc::strdup(ipv4addr.as_ptr() as *const libc::c_char) };

    true
}

pub fn server_addr(addr: &mut libc::sockaddr_in, host: &mut vtun_host::VtunHost) -> bool
{
    {
        let z: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        *addr = z;
    }
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = libc::htons(unsafe { &lfd_mod::vtun }.bind_addr.port as u16);

    /* Lookup server's IP address.
     * We do it on every reconnect because server's IP
     * address can be dynamic.
     */
    let hostname = unsafe { CStr::from_ptr(lfd_mod::vtun.svr_name) }.to_str().unwrap();
    let hent = dns_lookup::lookup_host(hostname).unwrap_or(Vec::new());

    if hent.is_empty() {
        let msg = format!("Can't resolv server address: {}", hostname);
        unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, msg.as_ptr() as *mut libc::c_char); }
        return false;
    }
    /*
     * TODO
     * * We should handle multiple IP-addresses, perhaps with a round-robin retry
     * * We should handle IPv6!
     */
    let hent = hent[0];
    let mut straddr = "".to_string();
    if let std::net::IpAddr::V4(ipv4) = hent {
        straddr = ipv4.to_string();
        addr.sin_addr.s_addr = u32::from_ne_bytes(ipv4.octets());
    }
    straddr.push_str("\0");

    if host.sopt.raddr != ptr::null_mut() {
        unsafe { libc::free(host.sopt.raddr as *mut libc::c_void) };
    }
    host.sopt.raddr = unsafe { libc::strdup(straddr.as_ptr() as *const libc::c_char) };
    host.sopt.rport = unsafe { &lfd_mod::vtun }.bind_addr.port;

    true
}

/* Set address by interface name, ip address or hostname */
pub fn generic_addr_rs(addr: &mut libc::sockaddr_in, vaddr: &vtun_host::VtunAddr) -> bool {
    {
        let z: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        *addr = z;
    }

    addr.sin_family = libc::AF_INET as libc::sa_family_t;

    /*
     * TODO - IPv6 and multiple dns results
     */
    if vaddr.type_ == lfd_mod::VTUN_ADDR_IFACE {
        let ifname = unsafe { CStr::from_ptr(vaddr.name) }.to_str().unwrap().to_string();
        addr.sin_addr.s_addr = match getifaddr(ifname.as_str()) {
            Some(s_addr) => s_addr as libc::in_addr_t,
            None => {
                let msg = format!("Can't get address of interface {}\n\0", ifname);
                unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, msg.as_ptr() as *mut libc::c_char); }
                return false;
            }
        };
    } else if vaddr.type_ == VTUN_ADDR_NAME {
        let hostname = unsafe { CStr::from_ptr(vaddr.name) }.to_str().unwrap().to_string();
        let hent = dns_lookup::lookup_host(hostname.as_str()).unwrap_or(Vec::new());
        if hent.is_empty() {
            let msg = format!("Can't resolv local address {}\n\0", hostname);
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, msg.as_ptr() as *mut libc::c_char); }
            return false;
        }
        for hent in hent {
            if let std::net::IpAddr::V4(ipv4) = hent {
                addr.sin_addr.s_addr = u32::from_ne_bytes(ipv4.octets());
            }
        }
    } else if vaddr.ip != null_mut() {
        let ip = unsafe { CStr::from_ptr(vaddr.ip) }.to_str().unwrap().to_string();
        let parts = ip.split('.').collect::<Vec<&str>>();
        if parts.len() != 4 {
            let msg = format!("Can't decode address {}\n\0", ip);
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, msg.as_ptr() as *mut libc::c_char); }
            return false;
        }
        let mut ip_addr: u32 = 0;
        for i in 0..4 {
            ip_addr = ip_addr << 8 | parts[i].parse::<u32>().unwrap();
        }
        addr.sin_addr.s_addr = ip_addr.to_be();
    } else {
        addr.sin_addr.s_addr = libc::INADDR_ANY;
    }

    if vaddr.port != 0 {
        addr.sin_port = (vaddr.port as u16).to_be();
    }

    true
}

#[no_mangle]
pub extern "C" fn local_addr(addr: *mut libc::sockaddr_in, host: *mut vtun_host::VtunHost, con: libc::c_int) -> libc::c_int {
    let host_ = unsafe { &mut *host };
    let addr_ = unsafe { &mut *addr };
    if local_addr_rs(addr_, host_, con != 0) {
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn generic_addr(addr: *mut libc::sockaddr_in, vaddr: *const vtun_host::VtunAddr) -> libc::c_int {
    let addr_ = unsafe { &mut *addr };
    let vaddr_ = unsafe { &*vaddr };
    if generic_addr_rs(addr_, vaddr_) {
        0
    } else {
        -1
    }
}
