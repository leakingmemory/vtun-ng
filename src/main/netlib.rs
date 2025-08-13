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

use crate::{lfd_mod, libfuncs, vtun_host};
use crate::filedes::FileDes;
use crate::lfd_mod::VTUN_ADDR_NAME;
use crate::linkfd::LinkfdCtx;
use crate::mainvtun::VtunContext;
use crate::syslog::SyslogObject;
/* Connect with timeout */
pub fn connect_t(s: &FileDes, svr: &libc::sockaddr_in, timeout: libc::time_t) -> bool {
    let sock_flags= match s.fcntl_getfl() {
        Ok(f) => f,
        Err(_) => return false
    };
    if !s.fcntl_setfl(libc::O_NONBLOCK) {
        return false;
    }

    if !s.connect_sockaddr_in(svr) && errno::errno() != errno::Errno(libc::EINPROGRESS)
    {
        return false;
    }

    let mut fdset: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe {
        libc::FD_ZERO(&mut fdset);
        libc::FD_SET(s.i_absolutely_need_the_raw_value(), &mut fdset);
    }
    let errno: libc::c_int;
    match s.wait_for_write_with_timeout(timeout) {
        Ok(selres) => {
            if selres {
                match s.get_so_error() {
                    Ok(e) => errno = e,
                    Err(_) => return false
                }
            } else {
                errno = libc::ETIMEDOUT;
            }
        },
        Err(_) => return false
    }

    s.fcntl_setfl(sock_flags);

    if errno == 0 {
        true
    } else {
        false
    }
}

/* Get interface address */
fn getifaddr(ifname: &str) -> Option<u32>
{
    let mut s = FileDes::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
    if !s.ok() {
        return None;
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let ifname = ifname.as_bytes();
    for i in 0..ifname.len() {
        ifr.ifr_name[i] = if ifname[i] < 128 { ifname[i] as libc::c_char } else { (ifname[i] - 128u8) as libc::c_char - (127 as libc::c_char)};
    }

    if unsafe { libc::ioctl(s.i_absolutely_need_the_raw_value(), libc::SIOCGIFADDR, &ifr) } < 0 {
        s.close();
        return None;
    }
    s.close();

    let addr: *const libc::sockaddr_in = unsafe { &(ifr.ifr_ifru.ifru_addr) as *const libc::sockaddr }.cast();

    let s_addr = Some(unsafe { &*addr} .sin_addr.s_addr);

    s_addr
}

/* Set local address */
pub fn local_addr_rs(ctx: &VtunContext, addr: &mut libc::sockaddr_in, host: &mut vtun_host::VtunHost, con: Option<&FileDes>) -> bool
{
    match con {
        Some(rmt_fd) => {
            /* Use address of the already connected socket. */
            if !rmt_fd.getsockname_sockaddr_in(addr) {
                ctx.syslog(lfd_mod::LOG_ERR,"Can't get local socket address");
                return false;
            }
        },
        None => {
            if !generic_addr_rs(ctx, addr, &host.src_addr) {
                return false;
            }
        }
    }

    // TODO - IPv6
    let ipv4addr = std::net::Ipv4Addr::from(addr.sin_addr.s_addr).to_string();
    host.sopt.laddr = Some(ipv4addr);

    true
}

pub fn server_addr(ctx: &VtunContext, addr: &mut libc::sockaddr_in, host: &mut vtun_host::VtunHost) -> bool
{
    {
        let z: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        *addr = z;
    }
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = libc::htons(ctx.vtun.bind_addr.port as u16);

    /* Lookup server's IP address.
     * We do it on every reconnect because server's IP
     * address can be dynamic.
     */
    let hostname = match ctx.vtun.svr_name {
        Some(ref s) => s.clone(),
        None => {
            ctx.syslog(lfd_mod::LOG_ERR, "Server name is not specified");
            return false;
        }
    };
    let hent = dns_lookup::lookup_host(hostname.as_str()).unwrap_or(Vec::new());

    if hent.is_empty() {
        let msg = format!("Can't resolv server address: {}", hostname);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
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

    host.sopt.raddr = Some(straddr);
    host.sopt.rport = ctx.vtun.bind_addr.port;

    true
}

/* Set address by interface name, ip address or hostname */
pub fn generic_addr_rs(ctx: &VtunContext, addr: &mut libc::sockaddr_in, vaddr: &vtun_host::VtunAddr) -> bool {
    {
        let z: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        *addr = z;
    }

    addr.sin_family = libc::AF_INET as libc::sa_family_t;

    /*
     * TODO - IPv6 and multiple dns results
     */
    if vaddr.type_ == lfd_mod::VTUN_ADDR_IFACE {
        let ifname = match vaddr.name {
            Some(ref ifname) => ifname.clone(),
            None => {
                ctx.syslog(lfd_mod::LOG_ERR, "Can't get interface name");
                return false;
            }
        };
        addr.sin_addr.s_addr = match getifaddr(ifname.as_str()) {
            Some(s_addr) => s_addr as libc::in_addr_t,
            None => {
                let msg = format!("Can't get address of interface {}", ifname);
                ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                return false;
            }
        };
    } else if vaddr.type_ == VTUN_ADDR_NAME {
        let hostname = match vaddr.name {
            Some(ref name) => name.clone(),
            None => {
                ctx.syslog(lfd_mod::LOG_ERR, "Can't get address to resolve");
                return false;
            }
        };
        let hent = dns_lookup::lookup_host(hostname.as_str()).unwrap_or(Vec::new());
        if hent.is_empty() {
            let msg = format!("Can't resolv local address {}", hostname);
            ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
            return false;
        }
        for hent in hent {
            if let std::net::IpAddr::V4(ipv4) = hent {
                addr.sin_addr.s_addr = u32::from_ne_bytes(ipv4.octets());
            }
        }
    } else if let Some(ref ip) = vaddr.ip {
        let ip = ip.to_string();
        let parts = ip.split('.').collect::<Vec<&str>>();
        if parts.len() != 4 {
            let msg = format!("Can't decode address {}", ip);
            ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
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

/*
 * Establish UDP session with host connected to fd(socket).
 * Returns connected UDP socket or -1 on error.
 */
pub fn udp_session(ctx: &mut VtunContext, linkfdctx: &LinkfdCtx, host: &mut vtun_host::VtunHost, rmt_fd: &mut FileDes) -> bool
{
    let mut saddr: libc::sockaddr_in = unsafe { std::mem::zeroed() };

    let s = FileDes::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
    if !s.ok() {
        ctx.syslog(lfd_mod::LOG_ERR,"Can't create socket");
        return false;
    }

    s.set_so_reuseaddr(true);

    /* Set local address and port */
    local_addr_rs(ctx, &mut saddr, host, Some(rmt_fd));
    if !s.bind_sockaddr_in(&saddr) {
        ctx.syslog(lfd_mod::LOG_ERR,"Can't bind to the socket");
        return false;
    }

    if !s.getsockname_sockaddr_in(&mut saddr) {
        ctx.syslog(lfd_mod::LOG_ERR,"Can't get socket name");
        return false;
    }

    /* Write port of the new UDP socket */
    let port: libc::c_short = saddr.sin_port as libc::c_short;
    {
        let buf = u16::from_be(port as libc::in_port_t).to_be_bytes();
        if libfuncs::write_n(linkfdctx, rmt_fd, &buf).is_none() {
            ctx.syslog(lfd_mod::LOG_ERR, "Can't write port number");
            return false;
        }
    }
    host.sopt.lport = u16::from_be(port as libc::in_port_t) as libc::c_int;

    /* Read port of the other's end UDP socket */
    let mut port = [0u8; 2];
    if libfuncs::readn_t(linkfdctx, rmt_fd,&mut port,host.timeout as libc::time_t) < 0 {
        let msg = format!("Can't read port number {}", errno::errno().to_string());
        ctx.syslog(lfd_mod::LOG_ERR,msg.as_str());
        return false;
    }

    if !rmt_fd.getpeername_sockaddr_in(&mut saddr) {
        ctx.syslog(lfd_mod::LOG_ERR,"Can't get peer name");
        return false;
    }

    let port = u16::from_be_bytes(port).to_be();

    saddr.sin_port = port;

    /* if the config says to delay the UDP connection, we wait for an
    incoming packet and then force a connection back.  We need to
    put this here because we need to keep that incoming triggering
    packet and pass it back up the chain. */

    if (host.flags & lfd_mod::VTUN_NAT_HACK_MASK) != 0 {
        ctx.is_rmt_fd_connected = false;
    } else {
        if !s.connect_sockaddr_in(&saddr) {
            ctx.syslog(lfd_mod::LOG_ERR,"Can't connect socket");
            return false;
        }
        ctx.is_rmt_fd_connected = true;
    }

    host.sopt.rport = u16::from_be(port) as libc::c_int;

    /* Close TCP socket and replace with UDP socket */
    rmt_fd.close();
    *rmt_fd = s;

    ctx.syslog(lfd_mod::LOG_INFO,"UDP connection initialized");
    true
}