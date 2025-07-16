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
use crate::{lfd_mod, linkfd};
use crate::linkfd::{LfdMod, LfdModFactory};

struct LfdZlib {
    pub compressor: flate2::Compression,
    pub encoder: flate2::write::ZlibEncoder<Vec<u8>>,
    pub decoder: flate2::write::ZlibDecoder<Vec<u8>>,
    pub returned_comp_buf: Vec<u8>,
    pub returned_decomp_buf: Vec<u8>
}

impl LfdZlib {
    pub fn new(host: &lfd_mod::VtunHost) -> LfdZlib {
        unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "ZLIB compression initialized\n\0".as_ptr() as *mut libc::c_char); }
        return LfdZlib {
            compressor: flate2::Compression::new(host.zlevel as u32),
            encoder: flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(host.zlevel as u32)),
            decoder: flate2::write::ZlibDecoder::new(Vec::new()),
            returned_comp_buf: Vec::new(),
            returned_decomp_buf: Vec::new()
        };
    }
}

pub(crate) struct LfdZlibFactory {
}

impl LfdZlibFactory {
    pub fn new() -> LfdZlibFactory {
        return LfdZlibFactory {
        };
    }
}
impl LfdModFactory for LfdZlibFactory {
    fn name(&self) -> &'static str {
        return "zlib";
    }
    fn create(&self, host: &mut lfd_mod::VtunHost) -> Option<Box<dyn LfdMod>> {
        return Some(Box::new(LfdZlib::new(host)));
    }
}

impl linkfd::LfdMod for LfdZlib {
    fn can_encode_inplace(&mut self) -> bool {
        false
    }
    fn encode(&mut self, src: &[u8]) -> Option<Box<Vec<u8>>> {
        match self.encoder.write_all(src) {
            Ok(_) => (),
            Err(_) => {
                unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "ZLIB compression error\n\0".as_ptr() as *mut libc::c_char); }
                return None
            }
        };
        match self.encoder.flush() {
            Ok(()) => {},
            Err(_) => return None,
        };
        let result = self.encoder.get_mut().clone();
        self.encoder.get_mut().clear();
        return Some(Box::new(result));
    }
    fn can_decode_inplace(&mut self) -> bool {
        false
    }
    fn decode(&mut self, src: &[u8]) -> Option<Box<Vec<u8>>> {
        match self.decoder.write_all(src) {
            Ok(_) => (),
            Err(_) => {
                unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "ZLIB decompression error\n\0".as_ptr() as *mut libc::c_char); }
                return None;
            }
        };
        match self.decoder.flush() {
            Ok(()) => {},
            Err(_) => return None,
        };
        let result = self.decoder.get_mut().clone();
        self.decoder.get_mut().clear();
        return Some(Box::new(result));
    }
}
