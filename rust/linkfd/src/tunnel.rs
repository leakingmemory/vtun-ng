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
use crate::{driver, lfd_mod, linkfd, pipe_dev, pty_dev, tcp_proto, tun_dev, udp_proto};

extern "C" {
    #[no_mangle]
    fn set_title_str(title: *const libc::c_char);
    #[no_mangle]
    fn udp_session(host: *mut lfd_mod::VtunHost) -> libc::c_int;
    #[no_mangle]
    static mut is_rmt_fd_connected: libc::c_int;
}

/* Travel list from head to tail */
fn llist_trav(l: &mut lfd_mod::LList, f: extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> libc::c_int, u: *mut libc::c_void) -> *mut libc::c_void {
    let mut i = l.head;

    while !i.is_null() {
        if unsafe { f((*i).data, u) } != 0 {
            return unsafe { (*i).data };
        }
        i = unsafe { (*i).next };
    }
    std::ptr::null_mut()
}

pub(crate) fn set_title(title: &str) {
    let str = format!("{}\0", title);
    unsafe { set_title_str(str.as_ptr() as *const libc::c_char); }
}

/// Substitutes opt in place off '%X'. 
/// Returns new string.
fn subst_opt(str: &str, sopt: Option<&lfd_mod::VtunSopt>) -> Option<String> {
    if str.is_empty() {
        return None;
    }
    let dev = match sopt {
        Some(sopt) => {
            if !sopt.dev.is_null() {
                Some(unsafe { CStr::from_ptr(sopt.dev) }.to_str().unwrap().to_string())
            } else {
                None
            }
        },
        None => None
    };
    let laddr = match sopt {
        Some(sopt) => {
            if !sopt.laddr.is_null() {
                Some(unsafe { CStr::from_ptr(sopt.laddr) }.to_str().unwrap().to_string())
            } else {
                None
            }
        },
        None => None
    };
    let raddr = match sopt {
        Some(sopt) => {
            if !sopt.raddr.is_null() {
                Some(unsafe { CStr::from_ptr(sopt.raddr) }.to_str().unwrap().to_string())
            } else {
                None
            }
        },
        None => None
    };
    let host = match sopt {
        Some(sopt) => {
            if !sopt.host.is_null() {
                Some(unsafe { CStr::from_ptr(sopt.host) }.to_str().unwrap().to_string())
            } else {
                None
            }
        },
        None => None
    };
    let lport = match sopt {
        Some(sopt) => Some(sopt.lport.to_string()),
        None => None
    };
    let rport = match sopt {
        Some(sopt) => Some(sopt.rport.to_string()),
        None => None
    };

    let mut result = String::with_capacity(str.len());
    let mut chars = str.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '%' => {
                if let Some(next) = chars.next() {
                    let replacement = match next {
                        '%' | 'd' => match dev { Some(ref dev) => dev.clone(), None => "".to_string()},
                        'A' => match laddr { Some(ref laddr) => laddr.clone(), None => "".to_string()},
                        'P' => match lport { Some(ref lport) => lport.clone(), None => "".to_string()},
                        'a' => match raddr { Some(ref raddr) => raddr.clone(), None => "".to_string()},
                        'p' => match rport { Some(ref rport) => rport.clone(), None => "".to_string()},
                        'h' => match host { Some(ref host) => host.clone(), None => "".to_string()},
                        _ => {
                            result.push(c);
                            continue;
                        }
                    };
                    result.push_str(replacement.as_str());
                }
            }
            '\\' => {
                result.push(c);
                if let Some(next) = chars.next() {
                    result.push(next);
                }
            }
            _ => result.push(c)
        }
    }

    Some(result)
}

/// Split arguments string.
/// ' ' - group arguments
fn split_args(str: & String) -> Vec<String> {
    let mut argv = Vec::new();
    let mut mode = 0;
    let mut current_arg = String::new();
    let mut chars = str.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            ' ' => {
                if mode == 1 {
                    argv.push(current_arg.clone());
                    current_arg.clear();
                    mode = 0;
                }
            }

            '\'' => {
                if mode == 0 {
                    mode = 2;
                } else {
                    if mode == 1 {
                        mode = 2;
                    } else {
                        mode = 1;
                    }
                    current_arg.insert(0, '\'');
                }
            }

            '\\' => {
                if mode != 0 {
                    current_arg.insert(0, '\\');
                }
                if let Some(next) = chars.next() {
                    current_arg.push(next);
                }
                continue;
            }

            _ => {
                if mode == 0 {
                    mode = 1;
                }
                current_arg.push(c);
            }
        }
    }

    if mode == 1 || mode == 2 {
        argv.push(current_arg);
    }

    argv
}

#[repr(C)]
struct VtunCmd {
    prog: *mut libc::c_char,
    args: *mut libc::c_char,
    flags: libc::c_int,
}
extern "C" fn run_cmd_rs(d: *mut libc::c_void, opt: *mut libc::c_void) -> libc::c_int {
    let prog: Option<String>;
    let args: Option<String>;
    let flags: libc::c_int;
    {
        let cmd = unsafe { &*(d as *mut VtunCmd) };
        if !cmd.prog.is_null() {
            prog = Some(unsafe { CStr::from_ptr(cmd.prog).to_str().unwrap().to_string() });
        } else {
            prog = None;
        }
        if !cmd.args.is_null() {
            args = Some(unsafe { CStr::from_ptr(cmd.args).to_str().unwrap().to_string() });
        } else {
            args = None;
        }
        flags = cmd.flags;
    }

    let forkres = unsafe { libc::fork() };
    if forkres < 0 {
        unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR,"Couldn't fork()\n\0".as_ptr() as *mut libc::c_char); }
        return 0;
    }
    if forkres > 0 {
        if (flags & linkfd::VTUN_CMD_WAIT) != 0 {
            /* Wait for termination */
            let mut st: libc::c_int = 0;
            if unsafe { libc::waitpid(forkres, &mut st, 0) } > 0 && (libc::WIFEXITED(st) && libc::WEXITSTATUS(st) != 0) {
                unsafe {
                    let msg = format!("Command [{} {:.20}] error {}\n\0",
                                      prog.unwrap_or_else(|| "<unknown>".to_string()),
                                      args.unwrap_or_else(|| "<unknown>".to_string()),
                                      libc::WEXITSTATUS(st));
                    lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, msg.as_ptr() as *mut libc::c_char);
                }
            }
        }
        if (flags & linkfd::VTUN_CMD_DELAY ) != 0 {
            /* Small delay hack to sleep after pppd start.
             * Until I have no good solution for solving
             * PPP + route problem  */
            std::thread::sleep(std::time::Duration::from_secs(linkfd::VTUN_DELAY_SEC));
        }
        return 0;
    }

    let sopt;
    if !opt.is_null() {
        sopt = Some(unsafe {&*(opt as *const lfd_mod::VtunSopt)});
    } else {
        sopt = None;
    }
    let args_string =
        subst_opt(args.unwrap_or_else(|| "".to_string()).as_str(),
                  sopt).unwrap_or_else(|| "".to_string());
    let mut argv: [*mut libc::c_char; 50] = [std::ptr::null_mut(); 50];

    let run_prog;
    let mut split: Vec<String> = Vec::new();
    match prog {
        None => {
            // Run using shell
            run_prog = "/bin/sh".to_string();
            argv[0] = "sh\0".as_ptr() as *mut libc::c_char;
            argv[1] = "-c\0".as_ptr() as *mut libc::c_char;
            argv[2] = args_string.as_ptr() as *mut libc::c_char;
            argv[3] = std::ptr::null_mut();
        }
        Some(prog) => {
            run_prog = format!("{}\0", prog);
            argv[0] = run_prog.as_ptr() as *mut libc::c_char;
            let slit = split_args(&args_string);
            split.reserve(slit.len());
            for (i, arg) in slit.iter().enumerate() {
                split.push(format!("{}\0", arg));
                let arg = split[split.len() - 1].as_ptr() as *mut libc::c_char;
                argv[i + 1] = arg;
            }
            argv[split.len() + 1] = std::ptr::null_mut();
        }
    }

    unsafe { libc::execv(run_prog.as_ptr() as *const libc::c_char, argv.as_ptr() as *const *const libc::c_char) };
    let msg = format!("Couldn't exec program {}", run_prog);
    unsafe {
        lfd_mod::vtun_syslog(lfd_mod::LOG_ERR,msg.as_ptr() as *mut libc::c_char);
        libc::exit(1);
    }
}

fn tunnel_lfd(host: &mut lfd_mod::VtunHost, driver: &mut dyn driver::Driver, proto: &mut dyn driver::NetworkDriver, dev: &str, interface_already_open: bool) -> libc::c_int {
    /* TODO - Which platforms do not have fork? */
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
    }
    let retv = unsafe { libc::fork() };
    if retv < 0 {
        unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "Couldn't fork()\n\0".as_ptr() as *mut libc::c_char); }
        return 0;
    }
    if retv == 0 {
        /* do this only the first time when in persist = keep mode */
        if !interface_already_open {
            let typeflags = host.flags & linkfd::VTUN_TYPE_MASK;
            if typeflags == linkfd::VTUN_TTY || typeflags == linkfd::VTUN_PIPE {
                let fd2: i32;
                let mut owns_fd2: bool = false;
                if typeflags == linkfd::VTUN_TTY {
                    /* Open pty slave (becomes controlling terminal) */
                    fd2 = unsafe { libc::open(dev.as_ptr() as *const libc::c_char, libc::O_RDWR) };
                    if fd2 < 0 {
                        unsafe {
                            lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "Couldn't open slave pty\n\0".as_ptr() as *mut libc::c_char);
                            libc::exit(0);
                        }
                    }
                    owns_fd2 = true;
                } else {
                    fd2 = driver.second_pipe_fd();
                }
                /* Fall through */
                let null_fd = unsafe { libc::open("/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDWR) };
                driver.close_first_pipe_fd();
                unsafe {
                    libc::close(0);
                    libc::dup(fd2);
                    libc::close(1);
                    libc::dup(fd2);
                }
                driver.close_second_pipe_fd();
                if owns_fd2 {
                    unsafe { libc::close(fd2); }
                }

                /* Route stderr to /dev/null */
                unsafe {
                    libc::close(2);
                    libc::dup(null_fd);
                    libc::close(null_fd);
                }
            }
        }
        let msg = format!("{} running up commands", unsafe {CStr::from_ptr(host.host)}.to_str().unwrap());
        set_title(msg.as_str());
        unsafe {
            llist_trav(&mut (host.up), run_cmd_rs, &mut host.sopt as *mut lfd_mod::VtunSopt as *mut libc::c_void);

            libc::exit(0);
        }
    }
    {
        let mut st: libc::c_int = 0;
        if unsafe { libc::waitpid(retv, &mut st, 0) } <= 0 {
            unsafe {
                lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "Couldn't wait for child process\n\0".as_ptr() as *mut libc::c_char);
                return 0;
            }
        }
    }
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_IGN);
    }

    let typeflags = host.flags & linkfd::VTUN_TYPE_MASK;
    if typeflags == linkfd::VTUN_TTY {
        let msg = format!("{} tty\0", unsafe {CStr::from_ptr(host.host)}.to_str().unwrap());
        set_title(msg.as_str());
    } else if typeflags == linkfd::VTUN_PIPE {
        /* Close second end of the pipe */
        driver.close_second_pipe_fd();
        {
            let ttle = format!("{} pipe\0", unsafe {CStr::from_ptr(host.host)}.to_str().unwrap());
            set_title(ttle.as_str());
        }
    } else if typeflags == linkfd::VTUN_ETHER {
        let ttle = format!("{} ether {}\0", unsafe {CStr::from_ptr(host.host)}.to_str().unwrap(), dev);
        set_title(ttle.as_str());
    } else if typeflags == linkfd::VTUN_TUN {
        let ttle = format!("{} tun {}\0", unsafe {CStr::from_ptr(host.host)}.to_str().unwrap(), dev);
        set_title(ttle.as_str());
    }
    host.loc_fd = driver.io_fd();
    let linkfd_result = linkfd::linkfd(host as *mut lfd_mod::VtunHost, driver, proto);

    {
        let ttle = format!("{} running down commands\0", unsafe {CStr::from_ptr(host.host)}.to_str().unwrap());
        set_title(ttle.as_str());
    }
    llist_trav(&mut host.down, run_cmd_rs, &mut host.sopt as *mut lfd_mod::VtunSopt as *mut libc::c_void);

    // TODO - Not to close with 'keep'. (closing is automatic by destructors)
    if host.persist == lfd_mod::VTUN_PERSIST_KEEPIF {
        driver.detach();
    }

    /* Close all other fds */
    unsafe { libc::close(host.rmt_fd); }

    linkfd_result
}

fn tunnel_setup_proto(host: &mut lfd_mod::VtunHost, driver: &mut dyn driver::Driver, dev: &str, interface_already_open: bool) -> libc::c_int {
    if !host.sopt.host.is_null() {
        unsafe { libc::free(host.sopt.host as *mut libc::c_void); }
    }
    if !host.sopt.dev.is_null() {
        unsafe { libc::free(host.sopt.dev as *mut libc::c_void); }
    }
    host.sopt.host = unsafe { libc::strdup(host.host) };
    {
        let dev = format!("{}\0", dev);
        host.sopt.dev = unsafe { libc::strdup(dev.as_ptr() as *mut libc::c_char) };
    }

    /* Initialize protocol. */
    let protflags = host.flags & linkfd::VTUN_PROT_MASK;
    if protflags == linkfd::VTUN_TCP {
        {
            let opt: libc::c_int = 1;
            unsafe { libc::setsockopt(host.rmt_fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, &opt as *const libc::c_int as *const libc::c_void, size_of::<libc::c_int>() as libc::socklen_t); }
        }
        {
            let opt: libc::c_int = 1;
            unsafe { libc::setsockopt(host.rmt_fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, &opt as *const libc::c_int as *const libc::c_void, size_of::<libc::c_int>() as libc::socklen_t); }
        }

        let mut proto = tcp_proto::TcpProto {
            fd: host.rmt_fd
        };
        return tunnel_lfd(host, driver, &mut proto, dev, interface_already_open)
    } else if protflags == linkfd::VTUN_UDP {
        let opt = unsafe { udp_session(host as *mut lfd_mod::VtunHost) };
        if opt == -1 {
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR,"Can't establish UDP session\n\0".as_ptr() as *mut libc::c_char); }
            return 0;
        }

        let mut proto = udp_proto::UdpProto {
            fd: host.rmt_fd,
            is_rmt_fd_connected: unsafe { is_rmt_fd_connected } != 0
        };
        return tunnel_lfd(host, driver, &mut proto, dev, interface_already_open)
    }
    unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR,"Unknown network transport protocol\n\0".as_ptr() as *mut libc::c_char); }
    0
}

pub fn tunnel(host: &mut lfd_mod::VtunHost) -> libc::c_int
{
    let mut dev_specified: bool = false;
    let mut dev: &str = "";
    let mut interface_already_open: bool = false;

    if host.persist == lfd_mod::VTUN_PERSIST_KEEPIF &&
        host.loc_fd >= 0 {
        interface_already_open = true;
    }

    /* Initialize device. */
    if !host.dev.is_null() {
        dev = unsafe { CStr::from_ptr(host.dev) }.to_str().unwrap();
        dev_specified = true;
    }
    if ! interface_already_open {
        let typeflag = host.flags & linkfd::VTUN_TYPE_MASK;
        if typeflag == linkfd::VTUN_TTY {
            match pty_dev::PtyDev::new() {
                Some(ref mut driver) => {
                    let dev = *driver.ptyname.clone();
                    tunnel_setup_proto(host, driver, dev.as_str(), interface_already_open)
                },
                None => {
                    unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "Can't allocate pseudo tty.\n\0".as_ptr() as *mut libc::c_char); }
                    -1
                }
            }
        } else if typeflag == linkfd::VTUN_PIPE {
            match pipe_dev::PipeDev::new() {
                Some(ref mut driver) => {
                    tunnel_setup_proto(host, driver, "", interface_already_open)
                },
                None => {
                    unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "Can't allocate pipe.\n\0".as_ptr() as *mut libc::c_char); }
                    -1
                }
            }
        } else if typeflag == linkfd::VTUN_ETHER {
            let dev_opt: Option<&str>;
            let dev_type: tun_dev::TunDevType = tun_dev::TunDevType::Tap;
            if dev_specified {
                dev_opt = Some(dev);
            } else {
                dev_opt = None;
            }
            match tun_dev::TunDev::new(dev_opt, dev_type) {
                Some(ref mut driver) => {
                    let dev = match driver.get_name() {
                        Some(name) => (*name).to_string(),
                        None => "".to_string()
                    };
                    tunnel_setup_proto(host, driver, dev.as_str(), interface_already_open)
                },
                None => {
                    let msg: String;
                    if dev_specified {
                        msg = format!("Can't open tap device {}\n\0", dev);
                    } else {
                        msg = "Can't allocate tap device.\n\0".to_string();
                    }
                    unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, msg.as_ptr() as *mut libc::c_char); }
                    -1
                }
            }
        } else if typeflag == linkfd::VTUN_TUN {
            let dev_opt: Option<&str>;
            let dev_type = tun_dev::TunDevType::Tun;
            if dev_specified {
                dev_opt = Some(dev);
            } else {
                dev_opt = None;
            }
            match tun_dev::TunDev::new(dev_opt, dev_type) {
                Some(ref mut driver) => {
                    let dev = match driver.get_name() {
                        Some(name) => (*name).to_string(),
                        None => "".to_string()
                    };
                    tunnel_setup_proto(host, driver, dev.as_str(), interface_already_open)
                },
                None => {
                    let msg: String;
                    if dev_specified {
                        msg = format!("Can't open tun device {}\n\0", dev);
                    } else {
                        msg = "Can't allocate tun device.\n\0".to_string();
                    }
                    unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, msg.as_ptr() as *mut libc::c_char); }
                    -1
                }
            }
        }  else {
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "Unknown tunnel type.\n\0".as_ptr() as *mut libc::c_char); }
            -1
        }
    } else {
        let typeflag = host.flags & linkfd::VTUN_TYPE_MASK;
        if typeflag == linkfd::VTUN_TTY {
            let dev: String;
            if !host.sopt.dev.is_null() {
                dev = unsafe { CStr::from_ptr(host.sopt.dev) }.to_str().unwrap().to_string();
            } else {
                dev = "".to_string();
            }
            let mut driver = pty_dev::PtyDev::new_from_fd(host.loc_fd, dev.as_str());
            tunnel_setup_proto(host, &mut driver, dev.as_str(), interface_already_open)
        } else if typeflag == linkfd::VTUN_PIPE {
            let mut driver = pipe_dev::PipeDev::new_from_fd(host.loc_fd);
            tunnel_setup_proto(host, &mut driver, "", interface_already_open)
        } else if typeflag == linkfd::VTUN_ETHER {
            let dev: String;
            if !host.sopt.dev.is_null() {
                dev = unsafe { CStr::from_ptr(host.sopt.dev) }.to_str().unwrap().to_string();
            } else {
                dev = "".to_string();
            }
            let mut driver = tun_dev::TunDev::new_from_fd(host.loc_fd, dev.as_str());
            tunnel_setup_proto(host, &mut driver, dev.as_str(), interface_already_open)
        } else if typeflag == linkfd::VTUN_TUN {
            let dev: String;
            if !host.sopt.dev.is_null() {
                dev = unsafe { CStr::from_ptr(host.sopt.dev) }.to_str().unwrap().to_string();
            } else {
                dev = "".to_string();
            }
            let mut driver = tun_dev::TunDev::new_from_fd(host.loc_fd, dev.as_str());
            tunnel_setup_proto(host, &mut driver, dev.as_str(), interface_already_open)
        }  else {
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "Unknown tunnel type.\n\0".as_ptr() as *mut libc::c_char); }
            -1
        }
    }
}
