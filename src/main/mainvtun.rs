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

use crate::{cfg_file, exitcode, lfd_mod};
use crate::syslog::SyslogObject;

pub struct VtunContext {
    pub config: Option<cfg_file::VtunConfigRoot>,
    pub vtun: lfd_mod::VtunOpts,
    pub is_rmt_fd_connected: bool
}

pub fn reread_config(ctx: &mut VtunContext) -> Result<(), exitcode::ErrorCode>
{
    let cfg_file = match ctx.vtun.cfg_file {
        Some(ref cfg_file) => cfg_file.clone(),
        None => {
            ctx.syslog(lfd_mod::LOG_ERR,"No config file specified");
            return exitcode::ExitCode::from_code(1).get_exit_code();
        }
    };
    ctx.config = match cfg_file::VtunConfigRoot::new(ctx, cfg_file.as_str()) {
        Some(config) => Some(config),
        None => {
            ctx.syslog(lfd_mod::LOG_ERR,"No hosts defined");
            return exitcode::ExitCode::from_code(1).get_exit_code();
        }
    };
    Ok(())
}
