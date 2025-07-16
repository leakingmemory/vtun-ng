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
    pub returned_comp_buf: Vec<u8>,
    pub returned_decomp_buf: Vec<u8>
}

impl LfdLzo {
    pub fn new(host: &lfd_mod::VtunHost) -> LfdLzo {
        unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "LZO compression initialized\n\0".as_ptr() as *mut libc::c_char); }
        return LfdLzo {
            compress_ctx: LZOContext::new(),
            returned_comp_buf: Vec::new(),
            returned_decomp_buf: Vec::new()
        };
    }
}

pub(crate) struct LfdLzoFactory {
}

impl LfdLzoFactory {
    pub fn new() -> LfdLzoFactory {
        return LfdLzoFactory {
        };
    }
}

impl linkfd::LfdModFactory for LfdLzoFactory {
    fn name(&self) -> &'static str {
        return "LZO";
    }

    fn create(&self, host: &mut VtunHost) -> Option<Box<dyn LfdMod>> {
        return Some(Box::new(LfdLzo::new(host)));
    }
}

impl linkfd::LfdMod for LfdLzo {
    fn can_encode_inplace(&mut self) -> bool {
        false
    }
    fn encode(&mut self, src: &[u8]) -> Option<Box<Vec<u8>>> {
        let mut compressed: Vec<u8> = Vec::new();
        compressed.reserve(worst_compress(src.len()));
        let err = self.compress_ctx.compress(src, &mut compressed);
        if (err == LZOError::OK) {
            return Some(Box::new(compressed));
        } else {
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "LZO compression failed\n\0".as_ptr() as *mut libc::c_char)}
            return None;
        }
    }
    fn can_decode_inplace(&mut self) -> bool {
        false
    }
    fn decode(&mut self, src: &[u8]) -> Option<Box<Vec<u8>>> {
        let mut decompressed: Vec<u8> = Vec::new();
        decompressed.resize(src.len() * 4, 0u8);
        let (result, err) = LZOContext::decompress_to_slice(&src, &mut decompressed);
        if (err == LZOError::OK) {
            let mut resvec: Vec<u8> = Vec::new();
            resvec.resize(result.len(), 0u8);
            for i in 0..result.len() {
                resvec[i] = result[i];
            }
            return Some(Box::new(resvec));
        } else {
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "LZO decompression failed\n\0".as_ptr() as *mut libc::c_char)}
            return None;
        }
    }
}
