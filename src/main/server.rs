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
use std::{mem, ptr};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use signal_hook::low_level;
use crate::{lfd_mod, linkfd, lock, mainvtun, netlib, setproctitle, syslog, tunnel};
use crate::auth::auth_server;
use crate::filedes::FileDes;
use crate::linkfd::LinkfdCtx;

struct ServerCtx {
    server_term: Arc<AtomicI32>
}

impl ServerCtx {
    fn new() -> Self {
        Self {
            server_term: Arc::new(AtomicI32::new(0))
        }
    }
    fn set_server_term(&self, server_term: i32) {
        self.server_term.store(server_term, Ordering::Relaxed);
    }
    fn sig_term(&self) {
        syslog::vtun_syslog(lfd_mod::LOG_INFO,"Terminated");
        self.set_server_term(linkfd::VTUN_SIG_TERM);
    }
}
fn connection(ctx: &mut mainvtun::VtunContext, sock: FileDes) {
    let mut cl_addr : libc::sockaddr_in = unsafe { mem::zeroed() };
    if !sock.getpeername_sockaddr_in(&mut cl_addr) {
        syslog::vtun_syslog(lfd_mod::LOG_ERR, "Can't get peer name");
        unsafe {
            libc::exit(1);
        }
    }
    let mut my_addr : libc::sockaddr_in = unsafe { mem::zeroed() };
    if !sock.getsockname_sockaddr_in(&mut my_addr) {
        syslog::vtun_syslog(lfd_mod::LOG_ERR, "Can't get local socket address");
        unsafe {
            libc::exit(1);
        }
    }

    let ip = std::net::Ipv4Addr::from(u32::from_be(cl_addr.sin_addr.s_addr)).to_string();

    let linkfdctx = LinkfdCtx::new();
    linkfdctx.io_init();

    match auth_server(ctx, &linkfdctx, &sock) {
        Some(mut host) => {
            let mut sa: libc::sigaction = unsafe { mem::zeroed() };
            sa.sa_sigaction = libc::SIG_IGN;
            sa.sa_flags = libc::SA_NOCLDWAIT;
            unsafe { libc::sigaction(libc::SIGHUP, &sa, ptr::null_mut()); }

            {
                let msg = format!("Session {}[{}:{}] opened",
                                  match host.host {Some(ref h) => h.as_str(), None => "<none>"},
                                  ip,
                                  u16::from_be(cl_addr.sin_port));
                syslog::vtun_syslog(lfd_mod::LOG_INFO, msg.as_str());
            }

            let l_ip = std::net::Ipv4Addr::from(cl_addr.sin_addr.s_addr).to_string();
            {
                let l_n_ip = l_ip.clone();
                host.sopt.laddr = Some(l_n_ip);
            }
            host.sopt.lport = ctx.vtun.bind_addr.port;
            {
                let n_ip = ip.clone();
                host.sopt.raddr = Some(n_ip);
            }
            host.sopt.rport = u16::from_be(cl_addr.sin_port) as libc::c_int;

            /* Start tunnel */
            let linkfdctx = Arc::new(linkfdctx);
            tunnel::tunnel(ctx, &linkfdctx, &mut host, sock);

            {
                let msg = format!("Session {} closed", match host.host {Some(ref h) => h.as_str(), None => "<none>"});
                syslog::vtun_syslog(lfd_mod::LOG_INFO, msg.as_str());
            }

            /* Unlock host. (locked in auth_server) */
            lock::unlock_host(&host);
        }
        None => {
            let msg = format!("Denied connection from {}:{}", ip, u16::from_be(cl_addr.sin_port));
            syslog::vtun_syslog(lfd_mod::LOG_INFO, msg.as_str());
        }
    }
    unsafe {
        libc::exit(0);
    }
}

fn listener(ctx: &mut mainvtun::VtunContext) {
    let mut my_addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    my_addr.sin_family = libc::AF_INET as libc::sa_family_t;

    /* Set listen address */
    if !netlib::generic_addr_rs(&mut my_addr, & ctx.vtun.bind_addr) {
        syslog::vtun_syslog(lfd_mod::LOG_ERR, "Can't fill in listen socket");
        unsafe {
            libc::exit(1);
        }
    }

    let mut s= FileDes::socket(libc::AF_INET, libc::SOCK_STREAM,0);
    if !s.ok() {
        syslog::vtun_syslog(lfd_mod::LOG_ERR, "Can't create socket");
        unsafe {
            libc::exit(1);
        }
    }

    s.set_so_reuseaddr(true);

    if !s.bind_sockaddr_in(&my_addr) {
        syslog::vtun_syslog(lfd_mod::LOG_ERR, "Can't bind to the socket");
        unsafe {
            libc::exit(1);
        }
    }

    if !s.listen(10) {
        syslog::vtun_syslog(lfd_mod::LOG_ERR, "Can't listen on the socket");
        unsafe {
            libc::exit(1);
        }
    }

    let server_ctx = Arc::new(ServerCtx::new());

    let sigterm_restore = {
        let server_ctx = Arc::clone(&server_ctx);
        match unsafe { low_level::register(libc::SIGTERM, move || {
            server_ctx.sig_term()
        }) } {
            Ok(id) => Some(id),
            Err(_) => None
        }
    };
    let sigint_restore = {
        let server_ctx = Arc::clone(&server_ctx);
        match unsafe { low_level::register(libc::SIGINT, move || {
            server_ctx.sig_term()
        }) } {
            Ok(id) => Some(id),
            Err(_) => None
        }
    };

    setproctitle::set_title(format!("waiting for connections on port {}", ctx.vtun.bind_addr.port).as_str());

    loop {
        {
            let server_term = server_ctx.server_term.load(Ordering::Relaxed);
            if server_term != 0 {
                if server_term != linkfd::VTUN_SIG_HUP {
                    break;
                }
                mainvtun::reread_config(ctx);
            }
        }
        let mut fdset: libc::fd_set = unsafe { mem::zeroed() };
        let mut tv: libc::timeval = libc::timeval {
            tv_sec: 10,
            tv_usec: 0
        };
        let selres;
        unsafe {
            libc::FD_ZERO(&mut fdset);
            libc::FD_SET(s.i_absolutely_need_the_raw_value(), &mut fdset);
            selres = libc::select(s.i_absolutely_need_the_raw_value()+1, &mut fdset, ptr::null_mut(), ptr::null_mut(), &mut tv);
        }
        if selres <= 0 {
            continue;
        }
        let mut cl_addr: libc::sockaddr_in = unsafe { mem::zeroed() };
        let mut s1 = match s.accept_sockaddr_in(&mut cl_addr) {
            Ok(s1) => s1,
            Err(_) => continue,
        };

        let f = unsafe { libc::fork() };
        if f == 0 {
            s.close();
            connection(ctx, s1);
        } else {
            if f == -1 {
                syslog::vtun_syslog(lfd_mod::LOG_ERR, "Couldn't fork()");
            }
            s1.close();
        }
    }

    match sigterm_restore {
        Some(sig_restore) => low_level::unregister(sig_restore),
        None => false
    };
    match sigint_restore {
        Some(sig_restore) => low_level::unregister(sig_restore),
        None => false
    };
}

pub fn server_rs(ctx: &mut mainvtun::VtunContext, sock: FileDes) {
    let mut sa: libc::sigaction = unsafe { mem::zeroed() };
    sa.sa_sigaction=libc::SIG_IGN;
    sa.sa_flags=libc::SA_NOCLDWAIT;
    unsafe {
        libc::sigaction(libc::SIGINT, &sa, ptr::null_mut());
        libc::sigaction(libc::SIGQUIT, &sa, ptr::null_mut());
        libc::sigaction(libc::SIGCHLD, &sa, ptr::null_mut());
        libc::sigaction(libc::SIGPIPE, &sa, ptr::null_mut());
        libc::sigaction(libc::SIGUSR1, &sa, ptr::null_mut());
    }

    {
        let svr_type = if ctx.vtun.svr_type == lfd_mod::VTUN_INETD  { "inetd" } else { "stand" };
        let msg = format!("VTUN server ver {} ({})", lfd_mod::VTUN_VER, svr_type);
        syslog::vtun_syslog(lfd_mod::LOG_INFO,msg.as_str());
    }

    let svr_type = ctx.vtun.svr_type;
    if svr_type == lfd_mod::VTUN_STAND_ALONE {
        listener(ctx);
    } else if svr_type == lfd_mod::VTUN_INETD {
        connection(ctx, sock);
    }
}
