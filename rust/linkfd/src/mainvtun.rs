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
use std::io::Write;
use std::ptr;
use crate::{cfg_file, client, lfd_mod, server};

const VTUN_PORT: libc::c_int = 5000;
const VTUN_TIMEOUT: libc::c_int = 30;

const OPTSTRING: &'static str = "mif:P:L:t:npq";
const SERVOPT_STRING: &'static str = "s";

const VTUN_CONFIG_FILE: &'static str = env!("VTUN_CONFIG_FILE");
const VTUN_PID_FILE: &'static str = env!("VTUN_PID_FILE");

extern "C" {
    #[no_mangle]
    pub static mut optind: libc::c_int;
    #[no_mangle]
    pub static mut optarg: *const libc::c_char;

    #[no_mangle]
    pub fn init_title_from_rs(argc: libc::c_int, argv: *const *const libc::c_char, env: *const *const libc::c_char, name: *const libc::c_char);
}

pub struct VtunContext {
    pub vtun: lfd_mod::VtunOpts,
    pub is_rmt_fd_connected: bool
}

#[no_mangle]
extern "C" fn main_rs(argc: libc::c_int, argv: *const *mut libc::c_char, env: *const *const libc::c_char) -> libc::c_int
{
    /* Configure default settings */
    let mut svr = false;
    let mut daemon = true;
    let mut sock: libc::c_int = 0;
    let mut dofork = true;

    let mut ctx: VtunContext = VtunContext {
        vtun: lfd_mod::VtunOpts::new(),
        is_rmt_fd_connected: true
    };
    {
        let cfg = format!("{}\0", VTUN_CONFIG_FILE);
        ctx.vtun.cfg_file = unsafe { libc::strdup(cfg.as_ptr() as *const libc::c_char) };
    }

    /* Dup strings because parser will try to free them */
    unsafe {
        ctx.vtun.ppp = libc::strdup("/usr/sbin/pppd\0".as_ptr() as *const libc::c_char);
        ctx.vtun.ifcfg = libc::strdup("/sbin/ifconfig\0".as_ptr() as *const libc::c_char);
        ctx.vtun.route = libc::strdup("/sbin/route\0".as_ptr() as *const libc::c_char);
        ctx.vtun.fwall = libc::strdup("/sbin/ipchains\0".as_ptr() as *const libc::c_char);
        ctx.vtun.iproute = libc::strdup("/sbin/ip\0".as_ptr() as *const libc::c_char);
    }

    ctx.vtun.bind_addr.port = -1;
    ctx.vtun.syslog   = libc::LOG_DAEMON;

    /* Start logging to syslog and stderr */
    unsafe { libc::openlog("vtund\0".as_ptr() as *mut libc::c_char, libc::LOG_PID | libc::LOG_NDELAY | libc::LOG_PERROR, libc::LOG_DAEMON); }

    let optstr = format!("{}{}\0", OPTSTRING, SERVOPT_STRING);
    loop {
        let mut opt = unsafe { libc::getopt(argc, argv, optstr.as_ptr() as *mut libc::c_char) };
        if opt == libc::EOF {
            break;
        }
        if opt < 0 || opt > 255 {
            opt = 0;
        }
        match opt as u8 {
            b'm' => unsafe {
                if (libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) < 0) {
                    libc::perror("Unable to mlockall()\0".as_ptr() as *mut libc::c_char);
                    libc::exit(-1);
                }
            },
            b'i' => {
                ctx.vtun.svr_type = lfd_mod::VTUN_INETD;
                svr = true;
            },
            b's' => {
                svr = true;
            },
            b'L' => unsafe {
                ctx.vtun.svr_addr = libc::strdup(optarg);
            },
            b'P' => unsafe {
                ctx.vtun.bind_addr.port = libc::atoi(optarg);
            },
            b'f' => unsafe {
                ctx.vtun.cfg_file = libc::strdup(optarg);
            },
            b'n' => {
                daemon = false;
            },
            b'p' => {
                ctx.vtun.persist = 1;
            },
            b't' => unsafe {
                ctx.vtun.timeout = libc::atoi(optarg);
            },
            b'q' => {
                ctx.vtun.quiet = 1;
            },
            _ => {
                usage();
                unsafe { libc::exit(1); }
            }
        }
    }
    reread_config(&mut ctx);

    if (ctx.vtun.syslog != libc::LOG_DAEMON) {
        /* Restart logging to syslog using specified facility  */
        unsafe {
            libc::closelog();
            libc::openlog("vtund".as_ptr() as *mut libc::c_char, libc::LOG_PID | libc::LOG_NDELAY | libc::LOG_PERROR, ctx.vtun.syslog);
        }
    }

    cfg_file::clear_nat_hack_flags(if svr {1} else {0});

    let mut host = ptr::null_mut();
    if(!svr){
        if( argc - unsafe { optind } < 2 ) {
            usage();
            unsafe { libc::exit(1); }
        }
        let hst = unsafe { *argv.add(optind as usize) };
        unsafe { optind = optind + 1; }

        host = cfg_file::find_host(hst);
        if host == ptr::null_mut() {
            let msg = format!("Host {} not found in {}\n\0", unsafe { CStr::from_ptr(hst) }.to_str().unwrap(), unsafe { CStr::from_ptr(ctx.vtun.cfg_file) }.to_str().unwrap());
            unsafe {
                lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, msg.as_ptr() as *mut libc::c_char);
                libc::exit(1);
            }
        }

        ctx.vtun.svr_name = unsafe { libc::strdup(*argv.add(optind as usize)) };
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
            sock = unsafe { libc::dup(0) };
            dofork = false;
        },
        _ => {
            ctx.vtun.svr_type = lfd_mod::VTUN_STAND_ALONE;
        }
    }

    if( daemon ) {
        if (dofork && unsafe { libc::fork() } != 0) {
            unsafe { libc::exit(0); }
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

    if svr {

        unsafe { init_title_from_rs(argc,argv as *const *const libc::c_char,env,"vtunngd[s]: \0".as_ptr() as *const libc::c_char); }

        if ctx.vtun.svr_type == lfd_mod::VTUN_STAND_ALONE {
            write_pid();
        }

        server::server_rs(&mut ctx, sock);
    } else {
        unsafe { init_title_from_rs(argc,argv as *const *const libc::c_char,env,"vtunngd[c]: \0".as_ptr() as *const libc::c_char); }
        client::client_rs(&mut ctx, unsafe { &mut *host });
    }

    unsafe { libc::closelog(); }

    0
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
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR,"Can't write PID file\n\0".as_ptr() as *mut libc::c_char); }
            return;
        },
    };

    let pid = unsafe { libc::getpid() };
    let pid = format!("{}", pid);
    match f.write_all(pid.as_bytes()) {
        Ok(_) => {},
        Err(_) => {
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR,"Can't write to PID file\n\0".as_ptr() as *mut libc::c_char); }
            return;
        }
    };
}

pub fn reread_config(ctx: &mut VtunContext)
{
    if cfg_file::read_config(ctx, ctx.vtun.cfg_file) == 0 {
        unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR,"No hosts defined\n\0".as_ptr() as *mut libc::c_char); }
        unsafe { libc::exit(1); }
    }
}

fn usage()
{
    println!("VTun ver {}\n", lfd_mod::VTUN_VER);
    println!("Usage: \n");
    println!("  Server:\n");
    println!("\tvtund <-s|-i> [-f file] [-P port] [-L local address]\n");
    println!("  Client:\n");
    /* I don't think these work. I'm disabling the suggestion - bish 20050601*/
    println!("{}{}", "\tvtund [-f file] ", /* [-P port] [-L local address] */
        "[-q] [-p] [-m] [-t timeout] <host profile> <server address>\n");
}
