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
use std::sync::Arc;
use crate::{driver, exitcode, lfd_mod, linkfd, netlib, pipe_dev, pty_dev, tcp_proto, tun_dev, udp_proto, vtun_host};
use crate::exitcode::ExitCode;
use crate::filedes::FileDes;
use crate::lowpriv::run_lowpriv_section;
use crate::mainvtun::VtunContext;
use crate::setproctitle::set_title;
use crate::syslog::SyslogObject;

/// Substitutes opt in place off '%X'.
/// Returns new string.
fn subst_opt(str: &str, sopt: Option<&vtun_host::VtunSopt>) -> Option<String> {
    if str.is_empty() {
        return None;
    }
    let dev = match sopt {
        Some(sopt) => {
            match sopt.dev {
                Some(ref dev) => Some(dev.clone()),
                None => None
            }
        },
        None => None
    };
    let laddr = match sopt {
        Some(sopt) => {
            match sopt.laddr {
                Some(ref laddr) => Some(laddr.clone()),
                None => None
            }
        },
        None => None
    };
    let raddr = match sopt {
        Some(sopt) => {
            match sopt.raddr {
                Some(ref raddr) => Some(raddr.clone()),
                None => None
            }
        },
        None => None
    };
    let host = match sopt {
        Some(sopt) => {
            match sopt.host {
                Some(ref host) => Some(host.clone()),
                None => None
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

#[derive(Clone)]
pub(crate) struct VtunCmd {
    pub(crate) prog: Option<String>,
    pub(crate) args: Option<String>,
    pub(crate) flags: libc::c_int,
}
fn run_cmd_rs(ctx: &VtunContext, cmd: &VtunCmd, sopt: Option<&vtun_host::VtunSopt>) -> Result<(),exitcode::ErrorCode> {
    let mut prog = match cmd.prog {
        Some(ref prog) => Some(prog.clone()),
        None => None
    };
    let args = match cmd.args {
        Some(ref args) => Some(args.clone()),
        None => None
    };
    let flags = cmd.flags;

    let forkres = unsafe { libc::fork() };
    if forkres < 0 {
        ctx.syslog(lfd_mod::LOG_ERR,"Couldn't fork()");
        return ExitCode::from_code(1).get_exit_code();
    }
    if forkres > 0 {
        if (flags & linkfd::VTUN_CMD_WAIT) != 0 {
            /* Wait for termination */
            let mut st: libc::c_int = 0;
            if unsafe { libc::waitpid(forkres, &mut st, 0) } > 0 && (libc::WIFEXITED(st) && libc::WEXITSTATUS(st) != 0) {
                let msg = format!("Command [{} {:.20}] error {}\n\0",
                                  prog.unwrap_or_else(|| "<unknown>".to_string()),
                                  args.unwrap_or_else(|| "<unknown>".to_string()),
                                  libc::WEXITSTATUS(st));
                ctx.syslog(lfd_mod::LOG_INFO, msg.as_str());
            }
        }
        if (flags & linkfd::VTUN_CMD_DELAY ) != 0 {
            /* Small delay hack to sleep after pppd start.
             * Until I have no good solution for solving
             * PPP + route problem  */
            std::thread::sleep(std::time::Duration::from_secs(linkfd::VTUN_DELAY_SEC));
        }
        return Ok(());
    }

    let args_string =
        subst_opt(args.unwrap_or_else(|| "".to_string()).as_str(),
                  sopt).unwrap_or_else(|| "".to_string());
    let mut argv: [*mut libc::c_char; 50] = [std::ptr::null_mut(); 50];

    let run_prog;
    let mut shell: String = "/bin/sh".to_string();
    let mut split: Vec<String> = Vec::new();
    if (flags & linkfd::VTUN_CMD_SHELL) != 0 {
        prog = match prog {
            None => None,
            Some(ref prog) => {
                shell = prog.clone();
                None
            }
        }
    }
    match prog {
        None => {
            // Run using shell
            run_prog = shell;
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
    ctx.syslog(lfd_mod::LOG_ERR,msg.as_str());
    ExitCode::from_code(1).get_exit_code()
}

fn tunnel_lfd(ctx: &mut VtunContext, linkfdctx: &Arc<linkfd::LinkfdCtx>, host: &mut vtun_host::VtunHost, driver: &mut dyn driver::Driver, proto: &mut dyn driver::NetworkDriver, dev: &str, interface_already_open: bool) -> Result<libc::c_int, ExitCode> {
    /* TODO - Which platforms do not have fork? */
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
    }
    let retv = unsafe { libc::fork() };
    if retv < 0 {
        ctx.syslog(lfd_mod::LOG_ERR, "Couldn't fork()");
        return Err(ExitCode::from_code(1));
    }
    if retv == 0 {
        /* do this only the first time when in persist = keep mode */
        if !interface_already_open {
            let typeflags = host.flags & linkfd::VTUN_TYPE_MASK;
            if typeflags == linkfd::VTUN_TTY || typeflags == linkfd::VTUN_PIPE {
                let mut fd2: FileDes;
                let mut owns_fd2: bool = false;
                if typeflags == linkfd::VTUN_TTY {
                    /* Open pty slave (becomes controlling terminal) */
                    fd2 = FileDes::open_m(dev, libc::O_RDWR);
                    if !fd2.ok() {
                        ctx.syslog(lfd_mod::LOG_ERR, "Couldn't open slave pty");
                        return Err(ExitCode::from_code(1));
                    }
                    owns_fd2 = true;
                } else {
                    fd2 = driver.clone_second_pipe_fd();
                }
                /* Fall through */
                let null_fd = FileDes::open_m("/dev/null", libc::O_RDWR);
                driver.close_first_pipe_fd();
                fd2.replace_stdin();
                fd2.replace_stdout();
                driver.close_second_pipe_fd();
                if owns_fd2 {
                    fd2.close();
                }

                /* Route stderr to /dev/null */
                null_fd.replace_stderr();
            }
        }
        let msg = format!("{} running up commands", match host.host { Some(ref host) => host.as_str(), None => "<none>"});
        set_title(msg.as_str());
        for cmd in &host.up {
            match run_cmd_rs(ctx, cmd, Some(&host.sopt)) {
                Ok(_) => {},
                Err(ref e) => return Err(ExitCode::from_error_code(e))
            }
        }
        return Err(ExitCode::ok());
    }
    {
        let mut st: libc::c_int = 0;
        if unsafe { libc::waitpid(retv, &mut st, 0) } <= 0 {
            ctx.syslog(lfd_mod::LOG_ERR, "Couldn't wait for child process");
            return Err(ExitCode::from_code(1));
        }
    }

    let typeflags = host.flags & linkfd::VTUN_TYPE_MASK;
    let proc_title;
    if typeflags == linkfd::VTUN_TTY {
        proc_title = format!("{} tty", match host.host {Some(ref host) => host.as_str(), None => "<none>"});
    } else if typeflags == linkfd::VTUN_PIPE {
        /* Close second end of the pipe */
        driver.close_second_pipe_fd();
        proc_title = format!("{} pipe", match host.host {Some(ref host) => host.as_str(), None => "<none>"});
    } else if typeflags == linkfd::VTUN_ETHER {
        proc_title = format!("{} ether {}", match host.host {Some(ref host) => host.as_str(), None => "<none>"}, dev);
    } else if typeflags == linkfd::VTUN_TUN {
        proc_title = format!("{} tun {}", match host.host {Some(ref host) => host.as_str(), None => "<none>"}, dev);
    } else {
        proc_title = format!("{} unknown", match host.host {Some(ref host) => host.as_str(), None => "<none>"});
    }
    let mut is_forked: bool = false;
    let linkfd_result = run_lowpriv_section(ctx, proc_title.as_str(), &mut is_forked,&mut |ctx: &mut VtunContext| -> Result<i32,()> {
        unsafe {
            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
        }
        linkfd::linkfd(ctx, linkfdctx, host, driver, proto)
    });
    if is_forked {
        return linkfd_result;
    }

    {
        let ttle = format!("{} running down commands", match host.host {Some(ref host) => host.as_str(), None => "<none>"});
        set_title(ttle.as_str());
    }
    for cmd in &host.down {
        match run_cmd_rs(ctx, cmd, Some(&host.sopt)) {
            Ok(_) => {},
            Err(ref e) => {
                return Err(ExitCode::from_error_code(e));
            }
        }
    }

    // TODO - Not to close with 'keep'. (closing is automatic by destructors)
    if host.persist == lfd_mod::VTUN_PERSIST_KEEPIF {
        host.loc_fd = driver.detach();
    }

    match linkfd_result {
        Ok(linkfd_result) => Ok(linkfd_result),
        Err(_) => Err(ExitCode::from_code(1))
    }
}

fn tunnel_setup_proto(ctx: &mut VtunContext, linkfdctx: &Arc<linkfd::LinkfdCtx>, host: &mut vtun_host::VtunHost, driver: &mut dyn driver::Driver, dev: &str, interface_already_open: bool, rmt_fd_in: FileDes) -> Result<libc::c_int, ExitCode> {
    let mut rmt_fd = rmt_fd_in;
    host.sopt.host = match host.host {
        Some(ref host) => Some(host.clone()),
        None => None
    };
    {
        host.sopt.dev = Some(dev.to_string());
    }

    /* Initialize protocol. */
    let protflags = host.flags & linkfd::VTUN_PROT_MASK;
    if protflags == linkfd::VTUN_TCP {
        rmt_fd.set_so_keepalive(true);
        rmt_fd.set_tcp_nodelay(true);

        let mut proto = tcp_proto::TcpProto {
            fd: rmt_fd
        };
        return tunnel_lfd(ctx, linkfdctx, host, driver, &mut proto, dev, interface_already_open)
    } else if protflags == linkfd::VTUN_UDP {
        let opt = netlib::udp_session(ctx, linkfdctx, host, &mut rmt_fd);
        if opt == false {
            ctx.syslog(lfd_mod::LOG_ERR,"Can't establish UDP session");
            return Ok(0);
        }

        let mut proto = udp_proto::UdpProto {
            fd: rmt_fd
        };
        return tunnel_lfd(ctx, linkfdctx, host, driver, &mut proto, dev, interface_already_open)
    }
    ctx.syslog(lfd_mod::LOG_ERR,"Unknown network transport protocol");
    Err(ExitCode::from_code(1))
}

pub fn tunnel(ctx: &mut VtunContext, linkfdctx: &Arc<linkfd::LinkfdCtx>, host: &mut vtun_host::VtunHost, rmt_fd: FileDes) -> Result<libc::c_int, ExitCode>
{
    let mut dev_specified: bool = false;
    let mut dev: &str = "";
    let mut interface_already_open: bool = false;

    if host.persist == lfd_mod::VTUN_PERSIST_KEEPIF &&
        host.loc_fd.ok() {
        interface_already_open = true;
    }

    /* Initialize device. */
    match host.dev {
        Some(ref d) => {
            dev = d.as_str();
            dev_specified = true;
        }
        None => {}
    };
    if ! interface_already_open {
        let typeflag = host.flags & linkfd::VTUN_TYPE_MASK;
        if typeflag == linkfd::VTUN_TTY {
            match pty_dev::PtyDev::new() {
                Some(ref mut driver) => {
                    let dev = *driver.ptyname.clone();
                    tunnel_setup_proto(ctx, linkfdctx, host, driver, dev.as_str(), interface_already_open, rmt_fd)
                },
                None => {
                    ctx.syslog(lfd_mod::LOG_ERR, "Can't allocate pseudo tty.");
                    Err(ExitCode::from_code(1))
                }
            }
        } else if typeflag == linkfd::VTUN_PIPE {
            match pipe_dev::PipeDev::new() {
                Some(ref mut driver) => {
                    tunnel_setup_proto(ctx, linkfdctx, host, driver, "", interface_already_open, rmt_fd)
                },
                None => {
                    ctx.syslog(lfd_mod::LOG_ERR, "Can't allocate pipe.");
                    Err(ExitCode::from_code(1))
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
            match tun_dev::TunDev::new(ctx, dev_opt, dev_type) {
                Some(ref mut driver) => {
                    let dev = match driver.get_name() {
                        Some(name) => (*name).to_string(),
                        None => "".to_string()
                    };
                    tunnel_setup_proto(ctx, linkfdctx, host, driver, dev.as_str(), interface_already_open, rmt_fd)
                },
                None => {
                    let msg: String;
                    if dev_specified {
                        msg = format!("Can't open tap device {}", dev);
                    } else {
                        msg = "Can't allocate tap device.".to_string();
                    }
                    ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                    Err(ExitCode::from_code(1))
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
            match tun_dev::TunDev::new(ctx, dev_opt, dev_type) {
                Some(ref mut driver) => {
                    let dev = match driver.get_name() {
                        Some(name) => (*name).to_string(),
                        None => "".to_string()
                    };
                    tunnel_setup_proto(ctx, linkfdctx, host, driver, dev.as_str(), interface_already_open, rmt_fd)
                },
                None => {
                    let msg: String;
                    if dev_specified {
                        msg = format!("Can't open tun device {}", dev);
                    } else {
                        msg = "Can't allocate tun device.".to_string();
                    }
                    ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                    Err(ExitCode::from_code(1))
                }
            }
        }  else {
            ctx.syslog(lfd_mod::LOG_ERR, "Unknown tunnel type.");
            Err(ExitCode::from_code(1))
        }
    } else {
        let typeflag = host.flags & linkfd::VTUN_TYPE_MASK;
        if typeflag == linkfd::VTUN_TTY {
            let dev: String = match host.sopt.dev {
                Some(ref d) => d.clone(),
                None => "".to_string()
            };
            let mut driver = pty_dev::PtyDev::new_from_fd(host.loc_fd.move_out(), dev.as_str());
            tunnel_setup_proto(ctx, linkfdctx, host, &mut driver, dev.as_str(), interface_already_open, rmt_fd)
        } else if typeflag == linkfd::VTUN_PIPE {
            let mut driver = pipe_dev::PipeDev::new_from_fd(host.loc_fd.move_out());
            tunnel_setup_proto(ctx, linkfdctx, host, &mut driver, "", interface_already_open, rmt_fd)
        } else if typeflag == linkfd::VTUN_ETHER {
            let dev: String = match host.sopt.dev {
                Some(ref d) => d.clone(),
                None => "".to_string()
            };
            let mut driver = tun_dev::TunDev::new_from_fd(ctx, host.loc_fd.move_out(), dev.as_str());
            tunnel_setup_proto(ctx, linkfdctx, host, &mut driver, dev.as_str(), interface_already_open, rmt_fd)
        } else if typeflag == linkfd::VTUN_TUN {
            let dev: String = match host.sopt.dev {
                Some(ref d) => d.clone(),
                None => "".to_string()
            };
            let mut driver = tun_dev::TunDev::new_from_fd(ctx, host.loc_fd.move_out(), dev.as_str());
            tunnel_setup_proto(ctx, linkfdctx, host, &mut driver, dev.as_str(), interface_already_open, rmt_fd)
        }  else {
            ctx.syslog(lfd_mod::LOG_ERR, "Unknown tunnel type.");
            Err(ExitCode::from_code(1))
        }
    }
}
