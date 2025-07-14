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
use crate::lfd_mod;

struct LfdLzo {
    pub compress_ctx: LZOContext,
    pub returned_comp_buf: Vec<u8>,
    pub returned_decomp_buf: Vec<u8>
}

impl LfdLzo {
    pub fn alloc(host: &lfd_mod::VtunHost) -> LfdLzo {
        unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "LZO compression initialized\n\0".as_ptr() as *mut libc::c_char); }
        return LfdLzo {
            compress_ctx: LZOContext::new(),
            returned_comp_buf: Vec::new(),
            returned_decomp_buf: Vec::new()
        };
    }
    pub fn compress(&mut self, src: &[u8]) -> Option<Vec<u8>> {
        let mut compressed: Vec<u8> = Vec::new();
        compressed.reserve(worst_compress(src.len()));
        let err = self.compress_ctx.compress(src, &mut compressed);
        if (err == LZOError::OK) {
            return Some(compressed);
        } else {
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "LZO compression failed\n\0".as_ptr() as *mut libc::c_char)}
            return None;
        }
    }
    pub fn decompress(&self, src: &[u8]) -> Option<Vec<u8>> {
        let mut decompressed: Vec<u8> = Vec::new();
        decompressed.resize(src.len() * 4, 0u8);
        let (result, err) = LZOContext::decompress_to_slice(&src, &mut decompressed);
        if (err == LZOError::OK) {
            let mut resvec: Vec<u8> = Vec::new();
            resvec.resize(result.len(), 0u8);
            for i in 0..result.len() {
                resvec[i] = result[i];
            }
            return Some(resvec);
        } else {
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "LZO decompression failed\n\0".as_ptr() as *mut libc::c_char)}
            return None;
        }
    }
}

pub static mut LFD_LZO: Option<LfdLzo> = None;

#[no_mangle]
pub extern "C" fn alloc_lzo(host: *const lfd_mod::VtunHost) -> libc::c_int
{
    unsafe {
        LFD_LZO = Some(LfdLzo::alloc(&*host));
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn free_lzo() -> libc::c_int
{
    unsafe { LFD_LZO = None; }
    return 0;
}

/*
 * This functions _MUST_ consume all incoming bytes in one pass,
 * that's why we expand buffer dynamicly.
 */
#[no_mangle]
pub extern "C" fn comp_lzo(len: libc::c_int, inptr: *const libc::c_char, outptr: *mut *mut libc::c_char) -> libc::c_int
{
    unsafe {
        match LFD_LZO {
            Some(ref mut lfdLzo) => {
                let inbuf = unsafe { std::slice::from_raw_parts(inptr as *const u8, len as usize) };
                let outbuf = match lfdLzo.compress(inbuf) {
                    Some(outbuf) => outbuf,
                    None => return -1
                };
                let outlen = outbuf.len();
                lfdLzo.returned_comp_buf.reserve(outlen + lfd_mod::LINKFD_FRAME_RESERV + lfd_mod::LINKFD_FRAME_APPEND);
                lfdLzo.returned_comp_buf.resize(lfd_mod::LINKFD_FRAME_RESERV + outlen, 0);
                for i in 0..outlen {
                    lfdLzo.returned_comp_buf[i + lfd_mod::LINKFD_FRAME_RESERV] = outbuf[i];
                }
                lfdLzo.returned_comp_buf.resize(lfdLzo.returned_comp_buf.len() + lfd_mod::LINKFD_FRAME_APPEND, 0);
                *outptr = lfdLzo.returned_comp_buf.as_ptr() as *mut libc::c_char;
                *outptr = (*outptr).add(lfd_mod::LINKFD_FRAME_RESERV);
                return outlen as libc::c_int;
            },
            None => {
                return -1;
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn decomp_lzo(len: libc::c_int, inptr: *const libc::c_char, outptr: *mut *mut libc::c_char) -> libc::c_int
{
    unsafe {
        match LFD_LZO {
            Some(ref mut lfdLzo) => {
                let inbuf = unsafe { std::slice::from_raw_parts(inptr as *const u8, len as usize) };
                let outbuf = match lfdLzo.decompress(inbuf) {
                    Some(outbuf) => outbuf,
                    None => return -1
                };
                lfdLzo.returned_decomp_buf = Vec::new();
                let outlen = outbuf.len();
                lfdLzo.returned_decomp_buf.reserve(outlen + lfd_mod::LINKFD_FRAME_RESERV + lfd_mod::LINKFD_FRAME_APPEND);
                lfdLzo.returned_decomp_buf.resize(lfd_mod::LINKFD_FRAME_RESERV + outlen, 0);
                for i in 0..outlen {
                    lfdLzo.returned_decomp_buf[lfd_mod::LINKFD_FRAME_RESERV + i] = outbuf[i];
                }
                lfdLzo.returned_decomp_buf.resize(lfdLzo.returned_decomp_buf.len() + lfd_mod::LINKFD_FRAME_APPEND, 0);
                *outptr = lfdLzo.returned_decomp_buf.as_ptr() as *mut libc::c_char;
                *outptr = (*outptr).add(lfd_mod::LINKFD_FRAME_RESERV);
                return outlen as libc::c_int;
            },
            None => {
                return -1;
            }
        }
    }
}
