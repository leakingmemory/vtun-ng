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

/*
 * $Id: client.c,v 1.11.2.4 2016/10/01 21:27:51 mtbishop Exp $
 */
use std::{mem, ptr, thread};
use std::ffi::CStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;
use signal_hook::low_level;
use crate::{auth, lfd_mod, libfuncs, linkfd, main, mainvtun, netlib, setproctitle, syslog, tunnel, vtun_host};

struct ClientCtx {
    client_term: Arc<AtomicI32>
}

impl ClientCtx {
    fn new() -> Self {
        Self {
            client_term: Arc::new(AtomicI32::new(0))
        }
    }
    fn set_client_term(&self, client_term: i32) {
        self.client_term.store(client_term, Ordering::Relaxed);
    }
    fn sig_term(&self) {
        syslog::vtun_syslog(lfd_mod::LOG_INFO,"Terminated");
        self.set_client_term(linkfd::VTUN_SIG_TERM);
    }
}

pub fn client_rs(ctx: &mut mainvtun::VtunContext, host: &mut vtun_host::VtunHost)
{
    {
        let msg = format!("VTun client ver {} started", lfd_mod::VTUN_VER);
        syslog::vtun_syslog(lfd_mod::LOG_INFO, msg.as_str());
    }
    let client_ctx: Arc<ClientCtx> = Arc::new(ClientCtx::new());

    let mut sa: libc::sigaction = unsafe { mem::zeroed() };
    sa.sa_sigaction=libc::SIG_IGN;
    sa.sa_flags = libc::SA_NOCLDWAIT;
    unsafe {
        libc::sigaction(libc::SIGHUP, &sa, ptr::null_mut());
        libc::sigaction(libc::SIGQUIT, &sa, ptr::null_mut());
        libc::sigaction(libc::SIGPIPE, &sa, ptr::null_mut());
        libc::sigaction(libc::SIGCHLD, &sa, ptr::null_mut());
    }
    let sigterm_restore = {
        let client_ctx = Arc::clone(&client_ctx);
        match unsafe { low_level::register(libc::SIGTERM, move || {
            client_ctx.sig_term()
        }) } {
            Ok(id) => Some(id),
            Err(_) => None
        }
    };
    let sigint_restore = {
        let client_ctx = Arc::clone(&client_ctx);
        match unsafe { low_level::register(libc::SIGINT, move || {
            client_ctx.sig_term()
        }) } {
            Ok(id) => Some(id),
            Err(_) => None
        }
    };


    let mut reconnect = false;
    loop {
        {
            let client_term = client_ctx.client_term.load(Ordering::Relaxed);
            if client_term != 0 && client_term != linkfd::VTUN_SIG_HUP {
                break;
            }
            if reconnect && client_term != linkfd::VTUN_SIG_HUP {
                if ctx.vtun.persist != 0 || host.persist != 0 {
                    /* Persist mode. Sleep and reconnect. */
                    thread::sleep(Duration::from_secs(5));
                } else {
                    /* Exit */
                    break;
                }
            } else {
                reconnect = true;
            }
        }

        let msg = format!("{} init initializing", unsafe { CStr::from_ptr(host.host) }.to_str().unwrap());
        setproctitle::set_title(msg.as_str());

        /* Set server address */
        let mut svr_addr = unsafe { mem::zeroed() };
        if !netlib::server_addr(ctx, &mut svr_addr, host) {
            continue;
        }

        /* Set local address */
        let mut my_addr: libc::sockaddr_in = unsafe { mem::zeroed() };
        if !netlib::local_addr_rs(&mut my_addr, host, false) {
            continue;
        }

        /* We have to create socket again every time
         * we want to connect, since STREAM sockets
         * can be successfully connected only once.
         */
        let s = unsafe { libc::socket(libc::AF_INET,libc::SOCK_STREAM,0) };
        if s==-1 {
            let errno = errno::errno();
            let msg = format!("Can't create socket. {}", errno.to_string());
            syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
            continue;
        }

        /* Required when client is forced to bind to specific port */
        let opt: i32=1;
        unsafe { libc::setsockopt(s, libc::SOL_SOCKET, libc::SO_REUSEADDR, &opt as *const i32 as *const libc::c_void, size_of::<i32>() as libc::socklen_t); }

        if unsafe { libc::bind(s,(&my_addr as *const libc::sockaddr_in).cast(),size_of::<libc::sockaddr_in>() as libc::socklen_t) } != 0 {
            let errno = errno::errno();
            let msg = format!("Can't bind socket. {}", errno.to_string());
            syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
            continue;
        }

        /*
         * Clear speed and flags which will be supplied by server.
         */
        host.spd_in = 0;
        host.spd_out = 0;
        host.flags = host.flags & lfd_mod::VTUN_CLNT_MASK;

        linkfd::io_init();

        {
            let msg = format!("{} connecting to {}", unsafe { CStr::from_ptr(host.host) }.to_str().unwrap(), unsafe { CStr::from_ptr(ctx.vtun.svr_name) }.to_str().unwrap());
            setproctitle::set_title(msg.as_str());
        }
        if ctx.vtun.quiet == 0 {
            let msg = format!("Connecting to {}", unsafe { CStr::from_ptr(ctx.vtun.svr_name) }.to_str().unwrap());
            syslog::vtun_syslog(lfd_mod::LOG_INFO, msg.as_str());
        }

        if !netlib::connect_t(s, (&svr_addr as *const libc::sockaddr_in).cast(), host.timeout as libc::time_t) {
            let errno = errno::errno();
            if ctx.vtun.quiet == 0 || errno != errno::Errno(libc::ETIMEDOUT) {
                let msg = format!("Connect to {} failed. {}", unsafe { CStr::from_ptr(ctx.vtun.svr_name) }.to_str().unwrap(), errno.to_string());
                syslog::vtun_syslog(lfd_mod::LOG_INFO, msg.as_str());
            }
        } else {
            if auth::auth_client_rs(ctx, s, host) {
                let msg = format!("Session {}[{}] opened", unsafe { CStr::from_ptr(host.host) }.to_str().unwrap(), unsafe { CStr::from_ptr(ctx.vtun.svr_name) }.to_str().unwrap());
                syslog::vtun_syslog(lfd_mod::LOG_INFO,msg.as_str());

                host.rmt_fd = s;

                /* Start the tunnel */
                client_ctx.set_client_term(tunnel::tunnel(ctx, host));

                let msg = format!("Session {}[{}] closed", unsafe { CStr::from_ptr(host.host) }.to_str().unwrap(), unsafe { CStr::from_ptr(ctx.vtun.svr_name) }.to_str().unwrap());
                syslog::vtun_syslog(lfd_mod::LOG_INFO,msg.as_str());
            } else {
                let msg = format!("Connection denied by {}", unsafe { CStr::from_ptr(ctx.vtun.svr_name) }.to_str().unwrap());
                syslog::vtun_syslog(lfd_mod::LOG_INFO,msg.as_str());
            }
        }
        unsafe { libc::close(s); }
        libfuncs::free_sopt(&mut host.sopt);
    }

    match sigint_restore {
        Some(sig_restore) => low_level::unregister(sig_restore),
        None => false
    };
    match sigterm_restore {
        Some(sig_restore) => low_level::unregister(sig_restore),
        None => false
    };

    syslog::vtun_syslog(lfd_mod::LOG_INFO, "Exit");
    return;
}
