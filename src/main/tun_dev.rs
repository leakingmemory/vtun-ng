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
use std::cmp::PartialEq;
use crate::{driver, lfd_mod, syslog};
use crate::filedes::FileDes;

pub(crate) enum TunDevType {
    Tun, Tap
}

impl Clone for TunDevType {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for TunDevType {
}

pub(crate) struct TunDev {
    pub name: Option<Box<String>>,
    pub fd: Option<FileDes>
}

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct TunIfreq {
    pub ifr_name: [libc::c_char; libc::IFNAMSIZ],
    pub ifr_flags: libc::c_short,
    pub ifr_pad: [u8; 22]
}

impl PartialEq<TunDevType> for &TunDevType {
    fn eq(&self, other: &TunDevType) -> bool {
        self == other
    }
}

impl TunDev {
    pub fn new(opt_name: Option<&str>, dev_type: TunDevType) -> Option<TunDev> {
        match opt_name {
            Some(name) => {
                let mut dev = TunDev {
                    name: None,
                    fd: None
                };
                if cfg!(target_os = "linux") {
                    if dev.open("/dev/net/tun", dev_type.clone()) {
                        if dev.linux_prep(Some(name), dev_type) {
                            dev.log_open();
                            return Some(dev);
                        }
                    }
                }
                if dev.open(name, dev_type) {
                    dev.log_open();
                    return Some(dev);
                }
                None
            }
            None => {
                let mut dev = TunDev {
                    name: None,
                    fd: None
                };
                if cfg!(target_os = "linux") {
                    if dev.open("/dev/net/tun", dev_type) {
                        if dev.linux_prep(None, dev_type) {
                            dev.log_open();
                            return Some(dev);
                        }
                    }
                }
                for i in 0..255 {
                    let name;
                    if matches!(dev_type, TunDevType::Tun) {
                        name = format!("tun{}", i);
                    } else {
                        name = format!("tap{}", i);
                    }
                    let path = format!("/dev/{}", &name);
                    if dev.open(path.as_str(), dev_type) {
                        dev.name = Some(Box::new(name));
                        dev.log_open();
                        return Some(dev);
                    }
                }
                None
            }
        }
    }
    pub fn new_from_fd(fd: FileDes, dev: &str) -> TunDev {
        let tun = TunDev { name: Some(Box::new(dev.to_string())), fd: Some(fd) };
        tun.log_open();
        tun
    }
    pub fn log_open(&self) {
        let name = match &self.name {
            None => "none".to_string(),
            Some(ref name) => name.to_string()
        };
        let msg = format!("Opened device endpoint {}", name);
        syslog::vtun_syslog(lfd_mod::LOG_INFO, msg.as_str());
    }

    #[cfg(not(target_os = "linux"))]
    fn linux_prep(&mut self, _name: Option<&str>, _dev_type: TunDevType) -> bool {
        false
    }
    #[cfg(target_os = "linux")]
    fn linux_prep(&mut self, name: Option<&str>, dev_type: TunDevType) -> bool {
        let mut ifr_flags: libc::c_short;
        if matches!(dev_type, TunDevType::Tun) {
            ifr_flags = libc::IFF_TUN as libc::c_short;
        } else {
            ifr_flags = libc::IFF_TAP as libc::c_short;
        }
        ifr_flags = ifr_flags | libc::IFF_NO_PI as libc::c_short;
        let mut ifreq: TunIfreq = TunIfreq {
            ifr_name: [0 as libc::c_char; 16],
            ifr_flags,
            ifr_pad: [0u8; 22]
        };
        if !name.is_none() {
            if name.unwrap().len() > 15 {
                return false;
            }
            {
                let nam = name.unwrap().as_bytes();
                for i in 0..nam.len() {
                    ifreq.ifr_name[i] = nam[i] as libc::c_char;
                }
            }
            self.name = Some(Box::new(name.unwrap().to_string()));
        }
        if let Some(ref fd) = self.fd {
            match unsafe {
                fd.ioctl(libc::TUNSETIFF, &ifreq as *const TunIfreq)
            } {
                Ok(_) => {},
                Err(_) => {
                    /* TODO - what kernels is this actually needed on?
                    if errno::errno() == libc::EBADFFD {
                        match unsafe {
                            fd.ioctl(libc::OTUNSETIFF, &ifreq as *const libc::c_ifreq)
                        } { Ok(res) => res, Err(_) => return false };
                    } else {
                        return false;
                    }
                    */
                    return false;
                }
            }
        } else {
            return false;
        }
        if name.is_none() {
            let mut len = 16;
            let mut nm: [u8; 16] = [0u8; 16];
            for i in 0..len {
                if ifreq.ifr_name[i] == 0 {
                    len = i;
                    break;
                }
                nm[i] = ifreq.ifr_name[i] as u8;
            }
            self.name = Some(Box::new(String::from_utf8_lossy(&nm[0..len]).to_string()));
        }
        true
    }
    pub fn open(&mut self, name: &str, dev_type: TunDevType) -> bool {
        self.close();
        let fd = FileDes::open_m(name, libc::O_RDWR);
        if fd.ok() {
            if cfg!(target_os = "freebsd") {
                if matches!(dev_type, TunDevType::Tun) {
                    /* Disable extended modes */
                    match unsafe { fd.ioctl_mut_ulong(93, 0) } {
                        Ok(_) => {}
                        Err(_) => return false
                    };
                    match unsafe { fd.ioctl_mut_ulong(96, 0) } {
                        Ok(_) => {}
                        Err(_) => return false
                    };
                }
            }
            self.fd = Some(fd);
            self.name = Some(Box::new(name.to_string()));
            true
        } else {
            self.fd = None;
            self.name = None;
            false
        }
    }
    pub fn close(&mut self) {
        match self.fd {
            Some(ref mut fd) => {
                fd.close();
                self.fd = None;
            },
            None => {}
        };
        self.name = None;
    }
    pub(crate) fn get_name(&self) -> Option<Box<String>> {
        match self.name {
            Some(ref name) => {
                let name = (**name).clone();
                Some(Box::new(name))
            },
            None => None
        }
    }
}

impl Drop for TunDev {
    fn drop(&mut self) {
        self.close();
    }
}

impl driver::Driver for TunDev {
    #[cfg(not(target_os = "openbsd"))]
    fn write(&self, buf: &[u8]) -> Option<usize> {
        match self.fd {
            None => None,
            Some(ref fd) => {
                match fd.write(buf) {
                    Ok(res) => Some(res),
                    Err(_) => None
                }
            }
        }
    }
    #[cfg(target_os = "openbsd")]
    fn write(&self, buf: &[u8]) -> Option<usize> {
        match self.fd {
            None => false,
            Some(fd) => {
                let tp: u32 = libc::htonl(libc::AF_INET);
                let iov: [libc::iovec; 2] = [
                    libc::iovec { iov_base: &mut tp as *mut u32 as *mut libc::c_void, iov_len: 4 },
                    libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: len }
                ];
                let res = libc::writev(fd, iov.as_ptr(), 2);
                if (res >= 0) {
                    Some(res as usize)
                } else {
                    None
                }
            }
        }
    }
    #[cfg(not(target_os = "openbsd"))]
    fn read(&self, buf: &mut Vec<u8>, len: usize) -> bool {
        match self.fd {
            None => false,
            Some(ref fd) => {
                if buf.len() != len {
                    buf.resize(len, 0);
                }
                match fd.read(buf) {
                    Ok(res) => {
                        buf.truncate(res);
                        true
                    },
                    Err(_) => false
                }
            }
        }
    }
    #[cfg(target_os = "openbsd")]
    fn read(&self, buf: &mut Vec<u8>, len: usize) -> bool {
        match self.fd {
            None => false,
            Some(fd) => {
                if (buf.len() < len) {
                    buf.resize(len, 0);
                }
                let mut tp: u32 = 0;
                let iov: [libc::iovec; 2] = [
                    libc::iovec { iov_base: &mut tp as *mut u32 as *mut libc::c_void, iov_len: 4 },
                    libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: len }
                ];
                let res = unsafe { libc::readv(fd, iov.as_ptr(), 2) };
                if res >= 4 {
                    buf.truncate((res - 4) as usize);
                    true
                } else {
                    false
                }
            }
        }
    }
    fn io_fd(&self) -> Option<&FileDes> {
        match self.fd {
            Some(ref fd) => Some(fd),
            None => None
        }
    }
    fn detach(&mut self) -> FileDes {
        match self.fd {
            Some(ref mut fd) => fd.move_out(),
            None => FileDes::new()
        }
    }
}
