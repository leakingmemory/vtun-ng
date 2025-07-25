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
use crate::lfd_mod;
use crate::lfd_mod::VTUN_MULTI_DENY;

const VTUN_LOCK_DIR: &str = env!("VTUN_LOCK_DIR");

fn create_lock_rs(file: &str) -> bool  {
    let pid = unsafe { libc::getpid() };
    let mut success = true;

    /* Create temp file */
    let tmp_file = format!("{}_{}_tmp", file, pid);
    let tmp_file_nullterm = format!("{}\0", tmp_file);
    let fd = unsafe { libc::open(tmp_file_nullterm.as_ptr() as *const libc::c_char, libc::O_WRONLY|libc::O_CREAT|libc::O_TRUNC, 0644) };
    if fd < 0 {
        let msg = format!("Can't create temp lock file {}\n\0", file);
        unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, msg.as_ptr() as *mut libc::c_char); }
        return false;
    }

    let str = format!("{}", pid);
    if unsafe { libc::write(fd, str.as_ptr() as *const libc::c_void, str.len()) } == str.len() as libc::ssize_t {
        /* Create lock file */
        let file_nullterm = format!("{}\0", file);
        if unsafe { libc::link(tmp_file_nullterm.as_ptr() as *const libc::c_char, file_nullterm.as_ptr() as *const libc::c_char) } < 0 {
            /* Oops, already locked */
            success = false;
        }
    } else {
        let msg = format!("Can't write to {}\n\0", tmp_file);
        unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, msg.as_ptr() as *mut libc::c_char); }
        success = false;
    }
    unsafe { libc::close(fd); }

    /* Remove temp file */
    unsafe { libc::unlink(tmp_file_nullterm.as_ptr() as *const libc::c_char); }

    success
}

pub fn read_lock_rs(file: &str) -> libc::pid_t {
    /* Read PID from existing lock */
    let fd;
    {
        let filen = format!("{}\0", file);
        fd = unsafe { libc::open(filen.as_ptr() as *const libc::c_char, libc::O_RDONLY) };
    }
    if fd < 0 {
        return -1;
    }

    let buf = [0u8; 20];
    let rdres = unsafe { libc::read(fd,buf.as_ptr() as *mut libc::c_void,buf.len() - 1) };
    unsafe { libc::close(fd); }
    if rdres <= 0  {
        return -1;
    }

    let pid = unsafe { libc::strtol(buf.as_ptr() as *const i8, std::ptr::null_mut(), 10) };
    if pid == 0 || errno::errno() == errno::Errno(libc::ERANGE) {
        /* Broken lock file */
        let filen = format!("{}\0", file);
        if unsafe { libc::unlink(filen.as_ptr() as *mut libc::c_char) } < 0 {
            let msg = format!("Unable to remove broken lock {}\n\0", file);
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, msg.as_ptr() as *mut libc::c_char); }
        }
        return -1;
    }

    /* Check if process is still alive */
    if unsafe { libc::kill(pid as libc::pid_t, 0) } < 0 && errno::errno() == errno::Errno(libc::ESRCH) {
        /* Process is dead. Remove stale lock. */
        let filen = format!("{}\0", file);
        if unsafe { libc::unlink(filen.as_ptr() as *mut libc::c_char) } < 0 {
            let msg = format!("Unable to remove stale lock {}", file);
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, msg.as_ptr() as *mut libc::c_char); }
        }
        return -1;
    }

    pid as libc::pid_t
}

pub fn lock_host_rs(host: &lfd_mod::VtunHost) -> bool {
    if host.multi == lfd_mod::VTUN_MULTI_ALLOW {
        return true;
    }

    let lock_file = format!("{}/{}", VTUN_LOCK_DIR, unsafe { CStr::from_ptr(host.host) }.to_str().unwrap());

    /* Check if lock already exists. */
    let pid = read_lock_rs(&lock_file);
    if pid > 0 {
        /* Old process is alive */
        if host.multi == lfd_mod::VTUN_MULTI_KILL {
            {
                let msg = format!("Killing old connection (process {})\n\0", pid);
                unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, msg.as_ptr() as *mut libc::c_char); }
            }
            if unsafe { libc::kill(pid, libc::SIGTERM) } < 0 {
                let errno = errno::errno();
                if errno != errno::Errno(libc::ESRCH) {
                    let msg = format!("Can't kill process {}. {}\n\0", pid, errno.to_string());
                    unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, msg.as_ptr() as *mut libc::c_char); }
                    return false;
                }
            }
            /* Give it a time(up to 5 secs) to terminate */
            for _ in 0..10 {
                if unsafe { libc::kill(pid, 0) } != 0 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }

            /* Make sure it's dead */
            if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
                let msg = format!("Killed old connection (process {})\n\0", pid);
                unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, msg.as_ptr() as *mut libc::c_char); }
            }
            /* Remove lock */
            let lock_file_nullterm = format!("{}\0", lock_file);
            if unsafe { libc::unlink(lock_file_nullterm.as_ptr() as *const libc::c_char) } < 0 {
                let msg = format!("Unable to remove lock {}\n\0", lock_file);
                unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, msg.as_ptr() as *mut libc::c_char); }
            }
        } else if host.multi == VTUN_MULTI_DENY {
            return false;
        }
    }
    create_lock_rs(lock_file.as_str())
}

#[no_mangle]
pub extern "C" fn read_lock(host: *const libc::c_char) -> libc::pid_t {
    let host = unsafe { CStr::from_ptr(host) }.to_str().unwrap();
    read_lock_rs(host)
}
#[no_mangle]
pub extern "C" fn create_lock(host: *const libc::c_char) -> libc::c_int {
    let host = unsafe { CStr::from_ptr(host) }.to_str().unwrap();
    if create_lock_rs(host) {
        0
    } else {
        -1
    }
}
#[no_mangle]
pub extern "C" fn lock_host(host: *mut lfd_mod::VtunHost) -> libc::c_int {
    let host = unsafe { &mut *host };
    if lock_host_rs(host) {
        0
    } else {
        -1
    }
}
