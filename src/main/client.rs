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
use crate::{auth2, challenge2, lfd_mod, linkfd, lowpriv, netlib, setproctitle, syslog, tunnel, vtun_host};
use crate::exitcode::ExitCode;
use crate::filedes::FileDes;
use crate::lfd_mod::VtunOpts;
use crate::mainvtun::VtunContext;
use crate::syslog::SyslogObject;
use crate::vtun_host::VtunSopt;

struct ClientCtx {
    log_to_syslog: bool,
    client_term: Arc<AtomicI32>
}

impl ClientCtx {
    fn new(opts: &VtunOpts) -> Self {
        Self {
            log_to_syslog: opts.log_to_syslog,
            client_term: Arc::new(AtomicI32::new(0))
        }
    }
    fn set_client_term(&self, client_term: i32) {
        self.client_term.store(client_term, Ordering::Relaxed);
    }
    fn sig_term(&self) {
        syslog::vtun_syslog(self.log_to_syslog, lfd_mod::LOG_INFO,"Terminated");
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

pub fn client_rs(ctx: &mut VtunContext, host: &mut vtun_host::VtunHost) -> Result<(), ExitCode>
{
    {
        let msg = format!("VTun client ver {} started", lfd_mod::VTUN_VER);
        ctx.syslog(lfd_mod::LOG_INFO, msg.as_str());
    }
    let client_ctx: Arc<ClientCtx> = Arc::new(ClientCtx::new(&ctx.vtun));

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
        if !netlib::local_addr_rs(ctx, &mut my_addr, host, None) {
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
            ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
            continue;
        }

        /* Required when client is forced to bind to specific port */
        s.set_so_reuseaddr(true);

        if !s.bind_sockaddr_in(&my_addr) {
            let errno = errno::errno();
            let msg = format!("Can't bind socket. {}", errno.to_string());
            ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
            continue;
        }

        /*
         * Clear speed and flags which will be supplied by server.
         */
        host.spd_in = 0;
        host.spd_out = 0;
        host.flags = host.flags & lfd_mod::VTUN_CLNT_MASK;

        let linkfdctx = linkfd::LinkfdCtx::new(ctx);
        linkfdctx.io_init();

        {
            let msg = format!("{} connecting to {}",
                              match host.host { Some(ref host) => host.as_str(), None => "<none>" },
                              match ctx.vtun.svr_name { Some(ref svr_name) => svr_name.as_str(), None => "<none>" });
            setproctitle::set_title(msg.as_str());
        }
        if ctx.vtun.quiet == 0 {
            let msg = format!("Connecting to {}", match &ctx.vtun.svr_name { Some(svr_name) => svr_name.as_str(), None => "<none>" });
            ctx.syslog(lfd_mod::LOG_INFO, msg.as_str());
        }

        if !netlib::connect_t(&s, &svr_addr, host.timeout as libc::time_t) {
            let errno = errno::errno();
            if ctx.vtun.quiet == 0 || errno != errno::Errno(libc::ETIMEDOUT) {
                let msg = format!("Connect to {} failed. {}",
                                  match &ctx.vtun.svr_name { Some(svr_name) => svr_name.as_str(), None => "<none>" },
                                  errno.to_string());
                ctx.syslog(lfd_mod::LOG_INFO, msg.as_str());
            }
        } else {
            let salt = challenge2::gen_digest_salt();
            let mut is_forked = false;
            match lowpriv::run_lowpriv_section(ctx, "authentication", &mut is_forked, &mut |ctx: &mut VtunContext| {
                match auth2::auth_client_rs(ctx, &linkfdctx, &s, host) {
                    Ok(_) => {
                        Ok(auth2::ClientAuthDecision{
                            values: auth2::ClientAuthValues {
                                flags: host.flags,
                                timeout: host.timeout,
                                spd_in: host.spd_in,
                                spd_out: host.spd_out,
                                zlevel: host.zlevel,
                                cipher: host.cipher
                            },
                            decision: auth2::AuthDecision {
                                service_name: match host.host {
                                    Some(ref name) => name.clone(),
                                    None => "".to_string()
                                },
                                passwd_digest: challenge2::digest_passwd(&salt, match host.passwd {
                                    Some(ref passwd) => passwd.as_str(),
                                    None => ""
                                })
                            }
                        })
                    },
                    Err(_) => Err(())
                }
            }) {
                Ok(decision) => {
                    if is_forked {
                        return Err(ExitCode::ok());
                    }
                    let chk_passwd = challenge2::digest_passwd(&salt, match host.passwd {
                        Some(ref passwd) => passwd.as_str(),
                        None => ""
                    });
                    {
                        let mut matching = chk_passwd.len() == decision.decision.passwd_digest.len();
                        if matching {
                            for i in 0..chk_passwd.len() {
                                if chk_passwd[i] != decision.decision.passwd_digest[i] {
                                    matching = false;
                                    break;
                                }
                            }
                        }
                        if match host.host {
                            Some(ref host) => { host != decision.decision.service_name.as_str() },
                            None => {"" != decision.decision.service_name.as_str()}
                        } || !matching {
                            ctx.syslog(lfd_mod::LOG_ERR,"Connection rejected due to invalid authentication result");
                            return Err(ExitCode::from_code(1));
                        }
                    }
                    host.flags = decision.values.flags;
                    host.timeout = decision.values.timeout;
                    host.spd_in = decision.values.spd_in;
                    host.spd_out = decision.values.spd_out;
                    host.zlevel = decision.values.zlevel;
                    host.cipher = decision.values.cipher;
                    let msg = format!("Session {}[{}] opened",
                                      match host.host { Some(ref host) => host.as_str(), None => "<none>" },
                                      match ctx.vtun.svr_name { Some(ref svr_name) => svr_name.as_str(), None => "<none>" });
                    ctx.syslog(lfd_mod::LOG_INFO,msg.as_str());

                    /* Start the tunnel */
                    let linkfdctx = Arc::new(linkfdctx);
                    client_ctx.set_client_term(match tunnel::tunnel(ctx, &linkfdctx, host, s) {
                        Ok(client_term) => client_term,
                        Err(exitcode) => return Err(exitcode)
                    });

                    let msg = format!("Session {}[{}] closed",
                                      match &host.host { Some(host) => host.as_str(), None => "<none>" },
                                      match &ctx.vtun.svr_name { Some(svr_name) => svr_name.as_str(), None => "<none>" });
                    ctx.syslog(lfd_mod::LOG_INFO,msg.as_str());
                },
                Err(code) => {
                    if is_forked {
                        return Err(code)
                    }
                    let msg = format!("Connection denied by {}", match &ctx.vtun.svr_name { Some(svr_name) => svr_name.as_str(), None => "<none>" });
                    ctx.syslog(lfd_mod::LOG_INFO,msg.as_str());
                }
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

    ctx.syslog(lfd_mod::LOG_INFO, "Exit");
    Ok(())
}
