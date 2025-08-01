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
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;
use signal_hook::{low_level, SigId};
use crate::{auth, exitcode, lfd_mod, linkfd, mainvtun, netlib, setproctitle, syslog, tunnel, vtun_host};
use crate::filedes::FileDes;
use crate::vtun_host::VtunSopt;

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

fn register_signal(client_ctx: &Arc<ClientCtx>, signal_id: libc::c_int) -> Option<SigId>{
    let client_ctx = Arc::clone(&client_ctx);
    match unsafe { low_level::register(signal_id, move || {
        client_ctx.sig_term()
    }) } {
        Ok(id) => Some(id),
        Err(_) => None
    }
}

pub fn client_rs(ctx: &mut mainvtun::VtunContext, host: &mut vtun_host::VtunHost) -> Result<(), exitcode::ExitCode>
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
    let sigterm_restore = register_signal(&client_ctx, libc::SIGTERM);
    let sigint_restore = register_signal(&client_ctx, libc::SIGINT);


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

        let msg = format!("{} init initializing", match &host.host { Some(host) => host.as_str(), None => "<none>"});
        setproctitle::set_title(msg.as_str());

        /* Set server address */
        let mut svr_addr = unsafe { mem::zeroed() };
        if !netlib::server_addr(ctx, &mut svr_addr, host) {
            continue;
        }

        /* Set local address */
        let mut my_addr: libc::sockaddr_in = unsafe { mem::zeroed() };
        if !netlib::local_addr_rs(&mut my_addr, host, None) {
            continue;
        }

        /* We have to create socket again every time
         * we want to connect, since STREAM sockets
         * can be successfully connected only once.
         */
        let s = FileDes::socket(libc::AF_INET,libc::SOCK_STREAM,0);
        if !s.ok() {
            let errno = errno::errno();
            let msg = format!("Can't create socket. {}", errno.to_string());
            syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
            continue;
        }

        /* Required when client is forced to bind to specific port */
        s.set_so_reuseaddr(true);

        if !s.bind_sockaddr_in(&my_addr) {
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

        let linkfdctx = linkfd::LinkfdCtx::new();
        linkfdctx.io_init();

        {
            let msg = format!("{} connecting to {}",
                              match host.host { Some(ref host) => host.as_str(), None => "<none>" },
                              match ctx.vtun.svr_name { Some(ref svr_name) => svr_name.as_str(), None => "<none>" });
            setproctitle::set_title(msg.as_str());
        }
        if ctx.vtun.quiet == 0 {
            let msg = format!("Connecting to {}", match &ctx.vtun.svr_name { Some(svr_name) => svr_name.as_str(), None => "<none>" });
            syslog::vtun_syslog(lfd_mod::LOG_INFO, msg.as_str());
        }

        if !netlib::connect_t(&s, &svr_addr, host.timeout as libc::time_t) {
            let errno = errno::errno();
            if ctx.vtun.quiet == 0 || errno != errno::Errno(libc::ETIMEDOUT) {
                let msg = format!("Connect to {} failed. {}",
                                  match &ctx.vtun.svr_name { Some(svr_name) => svr_name.as_str(), None => "<none>" },
                                  errno.to_string());
                syslog::vtun_syslog(lfd_mod::LOG_INFO, msg.as_str());
            }
        } else {
            if auth::auth_client_rs(ctx, &linkfdctx, &s, host) {
                let msg = format!("Session {}[{}] opened",
                                  match host.host { Some(ref host) => host.as_str(), None => "<none>" },
                                  match ctx.vtun.svr_name { Some(ref svr_name) => svr_name.as_str(), None => "<none>" });
                syslog::vtun_syslog(lfd_mod::LOG_INFO,msg.as_str());

                /* Start the tunnel */
                let linkfdctx = Arc::new(linkfdctx);
                client_ctx.set_client_term(match tunnel::tunnel(ctx, &linkfdctx, host, s) {
                    Ok(client_term) => client_term,
                    Err(exitcode) => return Err(exitcode)
                });

                let msg = format!("Session {}[{}] closed",
                                  match &host.host { Some(host) => host.as_str(), None => "<none>" },
                                  match &ctx.vtun.svr_name { Some(svr_name) => svr_name.as_str(), None => "<none>" });
                syslog::vtun_syslog(lfd_mod::LOG_INFO,msg.as_str());
            } else {
                let msg = format!("Connection denied by {}", match &ctx.vtun.svr_name { Some(svr_name) => svr_name.as_str(), None => "<none>" });
                syslog::vtun_syslog(lfd_mod::LOG_INFO,msg.as_str());
            }
        }
        host.sopt = VtunSopt::new();
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
    Ok(())
}
