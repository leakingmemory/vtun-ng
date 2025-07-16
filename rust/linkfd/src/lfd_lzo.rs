/*
    VTun-ng - Forked from VTun in 2025
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

/* LZO compression module */

use rust_lzo::{worst_compress, LZOContext, LZOError};
use crate::{lfd_mod, linkfd};
use crate::lfd_mod::VtunHost;
use crate::linkfd::LfdMod;

struct LfdLzo {
    pub compress_ctx: LZOContext,
}

impl LfdLzo {
    pub fn new(_host: &VtunHost) -> LfdLzo {
        unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "LZO compression initialized\n\0".as_ptr() as *mut libc::c_char); }
        LfdLzo {
            compress_ctx: LZOContext::new()
        }
    }
}

pub(crate) struct LfdLzoFactory {
}

impl LfdLzoFactory {
    pub fn new() -> LfdLzoFactory {
        LfdLzoFactory {
        }
    }
}

impl linkfd::LfdModFactory for LfdLzoFactory {
    fn name(&self) -> &'static str {
        "LZO"
    }

    fn create(&self, host: &mut VtunHost) -> Option<Box<dyn LfdMod>> {
        Some(Box::new(LfdLzo::new(host)))
    }
}

impl LfdMod for LfdLzo {
    fn encode(&mut self, buf: &mut Vec<u8>) -> bool {
        let mut compressed: Vec<u8> = Vec::new();
        compressed.reserve(worst_compress(buf.len()));
        let err = self.compress_ctx.compress(buf, &mut compressed);
        if err == LZOError::OK {
            buf.resize(compressed.len(), 0u8);
            for i in 0..compressed.len() {
                buf[i] = compressed[i];
            }
            true
        } else {
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "LZO compression failed\n\0".as_ptr() as *mut libc::c_char)}
            false
        }
    }
    fn decode(&mut self, buf: &mut Vec<u8>) -> bool {
        let mut decompressed: Vec<u8> = Vec::new();
        decompressed.resize(buf.len() * 4, 0u8);
        let (result, err) = LZOContext::decompress_to_slice(&buf, &mut decompressed);
        if err == LZOError::OK {
            buf.resize(result.len(), 0u8);
            for i in 0..result.len() {
                buf[i] = result[i];
            }
            true
        } else {
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "LZO decompression failed\n\0".as_ptr() as *mut libc::c_char)}
            false
        }
    }
}
