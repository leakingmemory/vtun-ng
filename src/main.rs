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

#[path = "main/cfg_file.rs"]
mod cfg_file;
#[path = "main/server.rs"]
mod server;
#[path = "main/client.rs"]
mod client;
#[path = "main/challenge.rs"]
mod challenge;
#[path = "main/auth.rs"]
mod auth;
#[path = "main/lfd_mod.rs"]
mod lfd_mod;
#[path = "main/setproctitle.rs"]
mod setproctitle;
#[path = "main/lfd_encrypt.rs"]
mod lfd_encrypt;
#[path = "main/lfd_legacy_encrypt.rs"]
mod lfd_legacy_encrypt;
#[path = "main/lfd_lzo.rs"]
mod lfd_lzo;
#[path = "main/lfd_zlib.rs"]
mod lfd_zlib;
#[path = "main/lfd_shaper.rs"]
mod lfd_shaper;
#[path = "main/linkfd.rs"]
mod linkfd;
#[path = "main/driver.rs"]
mod driver;
#[path = "main/pipe_dev.rs"]
mod pipe_dev;
#[path = "main/pty_dev.rs"]
mod pty_dev;
#[path = "main/tun_dev.rs"]
mod tun_dev;
#[path = "main/tcp_proto.rs"]
mod tcp_proto;
#[path = "main/udp_proto.rs"]
mod udp_proto;
#[path = "main/tunnel.rs"]
mod tunnel;
#[path = "main/libfuncs.rs"]
mod libfuncs;
#[path = "main/lock.rs"]
mod lock;
#[path = "main/netlib.rs"]
mod netlib;
#[path = "main/vtun_host.rs"]
mod vtun_host;
#[path = "main/lexer.rs"]
mod lexer;
#[path = "main/mainvtun.rs"]
mod mainvtun;
#[path = "main/syslog.rs"]
mod syslog;
#[path = "main/filedes.rs"]
mod filedes;
#[path = "main/fdselect.rs"]
mod fdselect;
#[path = "main/exitcode.rs"]
mod exitcode;

use std::io::Write;
use std::{env};
use getopts::Options;
use crate::filedes::FileDes;

const VTUN_PORT: libc::c_int = 5000;
const VTUN_TIMEOUT: libc::c_int = 30;

const VTUN_CONFIG_FILE: &'static str = env!("VTUN_CONFIG_FILE");
const VTUN_PID_FILE: &'static str = env!("VTUN_PID_FILE");

fn main() -> Result<(), exitcode::ErrorCode>
{
    setproctitle::init_title();

    /* Configure default settings */
    let mut svr = false;
    let mut daemon = true;
    let mut sock: FileDes = FileDes::new();
    let mut dofork = true;

    let mut ctx: mainvtun::VtunContext = mainvtun::VtunContext {
        config: None,
        vtun: lfd_mod::VtunOpts::new(),
        is_rmt_fd_connected: true
    };
    {
        let cfg = format!("{}", VTUN_CONFIG_FILE);
        ctx.vtun.cfg_file = Some(cfg);
    }

    ctx.vtun.ppp = Some("/usr/sbin/pppd".to_string());
    ctx.vtun.ifcfg = Some("/sbin/ifconfig".to_string());
    ctx.vtun.route = Some("/sbin/route".to_string());
    ctx.vtun.fwall = Some("/sbin/ipchains".to_string());
    ctx.vtun.iproute = Some("/sbin/ip".to_string());

    ctx.vtun.bind_addr.port = -1;
    ctx.vtun.syslog   = libc::LOG_DAEMON;

    /* Start logging to syslog and stderr */
    unsafe { libc::openlog("vtund\0".as_ptr() as *mut libc::c_char, libc::LOG_PID | libc::LOG_NDELAY | libc::LOG_PERROR, libc::LOG_DAEMON); }

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("m", "mlockall", "mlockall() all memory");
    opts.optflag("i", "inetd", "run as inetd");
    opts.optflag("s", "server", "run as server");
    opts.optopt("P", "port", "listen port", "PORT");
    opts.optopt("L", "local", "local address", "ADDR");
    opts.optopt("f", "config", "config file", "FILE");
    opts.optopt("t", "timeout", "timeout", "SEC");
    opts.optflag("n", "no-daemon", "don't daemonize");
    opts.optflag("p", "persist", "persist mode");
    opts.optflag("q", "quiet", "quiet mode");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => {
            print_usage(&program, opts);
            return exitcode::ExitCode::from_code(1).get_exit_code();
        }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return Ok(());
    }
    if matches.opt_present("m") {
        unsafe {
            if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) < 0 {
                libc::perror("Unable to mlockall()\0".as_ptr() as *mut libc::c_char);
                return exitcode::ExitCode::from_code(1).get_exit_code();
            }
        }
    }
    if matches.opt_present("i") {
        ctx.vtun.svr_type = lfd_mod::VTUN_INETD;
        svr = true;
    }
    if matches.opt_present("s") {
        svr = true;
    }
    match matches.opt_str("L") {
        Some(str) => {
            ctx.vtun.svr_addr = Some(str);
        },
        None => {}
    }
    match matches.opt_str("P") {
        Some(str) => unsafe {
            let str = format!("{}\0", str);
            ctx.vtun.bind_addr.port = libc::atoi(str.as_ptr() as *const libc::c_char);
        },
        None => {}
    }
    match matches.opt_str("f") {
        Some(str) => {
            ctx.vtun.cfg_file = Some(str);
        },
        None => {}
    }
    match matches.opt_str("t") {
        Some(str) => unsafe {
            let str = format!("{}\0", str);
            ctx.vtun.timeout = libc::atoi(str.as_ptr() as *const libc::c_char);
        },
        None => {}
    }
    if matches.opt_present("n") {
        daemon = false;
    }
    if matches.opt_present("p") {
        ctx.vtun.persist = 1;
    }
    if matches.opt_present("q") {
        ctx.vtun.quiet = 1;
    }
    match mainvtun::reread_config(&mut ctx) {
        Ok(_) => {},
        Err(e) => return Err(e)
    };

    if ctx.vtun.syslog != libc::LOG_DAEMON {
        /* Restart logging to syslog using specified facility  */
        unsafe {
            libc::closelog();
            libc::openlog("vtund".as_ptr() as *mut libc::c_char, libc::LOG_PID | libc::LOG_NDELAY | libc::LOG_PERROR, ctx.vtun.syslog);
        }
    }

    match ctx.config {
        Some(ref mut config) => config.clear_nat_hack_flags(svr),
        None => {}
    };

    let mut host = None;
    if !svr {
        if matches.free.len() < 2 {
            print_usage(&program, opts);
            return exitcode::ExitCode::from_code(1).get_exit_code();
        }
        let hst = matches.free[0].clone();

        host = match match ctx.config {
            Some(ref config) => config.find_host(hst.as_str()),
            None => None
        } {
            Some(host) => Some(host.clone()),
            None => None
        };
        if host.is_none() {
            let msg = format!("Host {} not found in {}",
                              hst.as_str(),
                              match ctx.vtun.cfg_file {Some(ref s) => s.as_str(), None => "<none>"});
            syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
            return exitcode::ExitCode::from_code(1).get_exit_code();
        }

        ctx.vtun.svr_name = Some(matches.free[1].to_string());
    }

    /*
     * Now fill uninitialized fields of the options structure
     * with default values.
     */
    if ctx.vtun.bind_addr.port == -1 {
        ctx.vtun.bind_addr.port = VTUN_PORT;
    }
    if ctx.vtun.persist == -1 {
        ctx.vtun.persist = 0;
    }
    if ctx.vtun.timeout == -1 {
        ctx.vtun.timeout = VTUN_TIMEOUT;
    }

    match ctx.vtun.svr_type {
        lfd_mod::VTUN_INETD => {
            sock = FileDes::clone_stdin();
            dofork = false;
        },
        _ => {
            ctx.vtun.svr_type = lfd_mod::VTUN_STAND_ALONE;
        }
    }

    if daemon {
        if dofork && unsafe { libc::fork() } != 0 {
            return Ok(())
        }

        /* Direct stdin,stdout,stderr to '/dev/null' */
        let fd = unsafe { libc::open("/dev/null\0".as_ptr() as *mut libc::c_char, libc::O_RDWR) };
        unsafe {
            libc::close(0);
            libc::dup(fd);
            libc::close(1);
            libc::dup(fd);
            libc::close(2);
            libc::dup(fd);
            libc::close(fd);
        }

        unsafe { libc::setsid(); }

        unsafe { libc::chdir("/\0".as_ptr() as *mut libc::c_char); }
    }

    let result = if svr {

        setproctitle::set_title("vtunngd[s]: ");

        if ctx.vtun.svr_type == lfd_mod::VTUN_STAND_ALONE {
            write_pid();
        }

        server::server_rs(&mut ctx, sock)
    } else {
        setproctitle::set_title("vtunngd[c]: ");
        match match host {
            Some(ref mut host) => client::client_rs(&mut ctx, host),
            None => Ok(())
        } {
            Ok(_) => Ok(()),
            Err(exitcode) => exitcode.get_exit_code()
        }
    };

    unsafe { libc::closelog(); }

    result
}

/*
 * Very simple PID file creation function. Used by server.
 * Overrides existing file.
 */
fn write_pid()
{
    let mut f = match std::fs::File::create(VTUN_PID_FILE) {
        Ok(f) => f,
        Err(_) => {
            syslog::vtun_syslog(lfd_mod::LOG_ERR,"Can't write PID file");
            return;
        },
    };

    let pid = unsafe { libc::getpid() };
    let pid = format!("{}", pid);
    match f.write_all(pid.as_bytes()) {
        Ok(_) => {},
        Err(_) => {
            syslog::vtun_syslog(lfd_mod::LOG_ERR,"Can't write to PID file");
            return;
        }
    };
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage:\n server: {} -s [options]\n client: {} [options] CONFIGNAME REMOTEADDR\n", program, program);
    print!("{}", opts.usage(&brief));
}