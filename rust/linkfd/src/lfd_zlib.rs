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

/* ZLIB compression module */
use std::io::Write;
use crate::{lfd_mod};
use crate::linkfd::{LfdMod, LfdModFactory};

struct LfdZlib {
    pub encoder: flate2::write::ZlibEncoder<Vec<u8>>,
    pub decoder: flate2::write::ZlibDecoder<Vec<u8>>
}

impl LfdZlib {
    pub fn new(host: &lfd_mod::VtunHost) -> LfdZlib {
        unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "ZLIB compression initialized\n\0".as_ptr() as *mut libc::c_char); }
        LfdZlib {
            encoder: flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(host.zlevel as u32)),
            decoder: flate2::write::ZlibDecoder::new(Vec::new())
        }
    }
}

pub(crate) struct LfdZlibFactory {
}

impl LfdZlibFactory {
    pub fn new() -> LfdZlibFactory {
        LfdZlibFactory {
        }
    }
}
impl LfdModFactory for LfdZlibFactory {
    fn create(&self, host: &mut lfd_mod::VtunHost) -> Option<Box<dyn LfdMod>> {
        Some(Box::new(LfdZlib::new(host)))
    }
}

impl LfdMod for LfdZlib {
    fn encode(&mut self, buf: &mut Vec<u8>) -> bool {
        match self.encoder.write_all(buf) {
            Ok(_) => (),
            Err(_) => {
                unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "ZLIB compression error\n\0".as_ptr() as *mut libc::c_char); }
                return false
            }
        };
        match self.encoder.flush() {
            Ok(()) => {},
            Err(_) => return false,
        };
        buf.resize(self.encoder.get_ref().len(), 0u8);
        for i in 0..buf.len() {
            buf[i] = self.encoder.get_ref()[i];
        }
        self.encoder.get_mut().clear();
        true
    }
    fn decode(&mut self, buf: &mut Vec<u8>) -> bool {
        match self.decoder.write_all(buf) {
            Ok(_) => (),
            Err(_) => {
                unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "ZLIB decompression error\n\0".as_ptr() as *mut libc::c_char); }
                return false;
            }
        };
        match self.decoder.flush() {
            Ok(()) => {},
            Err(_) => return false,
        };
        buf.resize(self.decoder.get_ref().len(), 0u8);
        for i in 0..buf.len() {
            buf[i] = self.decoder.get_ref()[i];       
        }
        self.decoder.get_mut().clear();
        true
    }
}
