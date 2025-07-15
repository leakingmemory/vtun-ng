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
use crate::lfd_mod;

struct LfdZlib {
    pub compressor: flate2::Compression,
    pub encoder: flate2::write::ZlibEncoder<Vec<u8>>,
    pub decoder: flate2::write::ZlibDecoder<Vec<u8>>,
    pub returned_comp_buf: Vec<u8>,
    pub returned_decomp_buf: Vec<u8>
}

impl LfdZlib {
    pub fn alloc(host: &lfd_mod::VtunHost) -> LfdZlib {
        unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "ZLIB compression initialized\n\0".as_ptr() as *mut libc::c_char); }
        return LfdZlib {
            compressor: flate2::Compression::new(host.zlevel as u32),
            encoder: flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(host.zlevel as u32)),
            decoder: flate2::write::ZlibDecoder::new(Vec::new()),
            returned_comp_buf: Vec::new(),
            returned_decomp_buf: Vec::new()
        };
    }
    pub fn compress(&mut self, src: &[u8]) -> Option<Vec<u8>> {
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
        return Some(result);
    }
    pub fn decompress(&mut self, src: &[u8]) -> Option<Vec<u8>> {
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
        return Some(result)
    }
}

pub static mut LFD_ZLIB: Option<LfdZlib> = None;

#[no_mangle]
pub extern "C" fn zlib_alloc(host: *const lfd_mod::VtunHost) -> libc::c_int
{
    unsafe {
        LFD_ZLIB = Some(LfdZlib::alloc(&*host));
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn zlib_free() -> libc::c_int
{
    unsafe { LFD_ZLIB = None; }
    return 0;
}

/*
 * This functions _MUST_ consume all incoming bytes in one pass,
 * that's why we expand buffer dynamicly.
 */
#[no_mangle]
pub extern "C" fn zlib_comp(len: libc::c_int, inptr: *const libc::c_char, outptr: *mut *mut libc::c_char) -> libc::c_int
{
    unsafe {
        match LFD_ZLIB {
            Some(ref mut lfdZlib) => {
                let inbuf = unsafe { std::slice::from_raw_parts(inptr as *const u8, len as usize) };
                let outbuf = match lfdZlib.compress(inbuf) {
                    Some(outbuf) => outbuf,
                    None => return -1
                };
                let outlen = outbuf.len();
                lfdZlib.returned_comp_buf.reserve(outlen + lfd_mod::LINKFD_FRAME_RESERV + lfd_mod::LINKFD_FRAME_APPEND);
                lfdZlib.returned_comp_buf.resize(lfd_mod::LINKFD_FRAME_RESERV + outlen, 0);
                for i in 0..outlen {
                    lfdZlib.returned_comp_buf[i + lfd_mod::LINKFD_FRAME_RESERV] = outbuf[i];
                }
                lfdZlib.returned_comp_buf.resize(lfdZlib.returned_comp_buf.len() + lfd_mod::LINKFD_FRAME_APPEND, 0);
                *outptr = lfdZlib.returned_comp_buf.as_ptr() as *mut libc::c_char;
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
pub extern "C" fn zlib_decomp(len: libc::c_int, inptr: *const libc::c_char, outptr: *mut *mut libc::c_char) -> libc::c_int
{
    unsafe {
        match LFD_ZLIB {
            Some(ref mut lfdZlib) => {
                let inbuf = unsafe { std::slice::from_raw_parts(inptr as *const u8, len as usize) };
                let outbuf = match lfdZlib.decompress(inbuf) {
                    Some(outbuf) => outbuf,
                    None => return -1
                };
                lfdZlib.returned_decomp_buf = Vec::new();
                let outlen = outbuf.len();
                lfdZlib.returned_decomp_buf.reserve(outlen + lfd_mod::LINKFD_FRAME_RESERV + lfd_mod::LINKFD_FRAME_APPEND);
                lfdZlib.returned_decomp_buf.resize(lfd_mod::LINKFD_FRAME_RESERV + outlen, 0);
                for i in 0..outlen {
                    lfdZlib.returned_decomp_buf[lfd_mod::LINKFD_FRAME_RESERV + i] = outbuf[i];
                }
                lfdZlib.returned_decomp_buf.resize(lfdZlib.returned_decomp_buf.len() + lfd_mod::LINKFD_FRAME_APPEND, 0);
                *outptr = lfdZlib.returned_decomp_buf.as_ptr() as *mut libc::c_char;
                *outptr = (*outptr).add(lfd_mod::LINKFD_FRAME_RESERV);
                return outlen as libc::c_int;
            },
            None => {
                return -1;
            }
        }
    }
}
