/*
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2016  Maxim Krasnyansky <max_mk@yahoo.com>
    Copyright (C) 2025  Jan-Espen Oversand <sigsegv@radiotube.org>

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

/*
 * From lfd_legacy_encrypt.c:
 * $Id: lfd_legacy_encrypt.c,v 1.1.4.4 2016/10/01 21:27:51 mtbishop Exp $
 * Code added wholesale temporarily from lfd_encrypt 1.2.2.8
 */

/*
 * From lfd_legacy_encrypt.c:
   Encryption module uses software developed by the OpenSSL Project
   for use in the OpenSSL Toolkit. (http://www.openssl.org/)
   Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
 */

/*
 * From lfd_legacy_encrypt.c:
 * This lfd_encrypt module uses MD5 to create 128 bits encryption
 * keys and BlowFish for actual data encryption.
 * It is based on code written by Chris Todd<christ@insynq.com> with
 * several improvements and modifications.
 */
use openssl::cipher_ctx::CipherCtx;
use openssl::cipher::{Cipher};
use openssl::hash::hash;
use crate::lfd_mod;
use crate::lfd_mod::VtunHost;

pub struct LfdLegacyEncrypt {
    pub ctx_enc: CipherCtx,
    pub ctx_dec: CipherCtx,
    pub returned_enc_buffer: Vec<u8>,
    pub returned_dec_buffer: Vec<u8>,
}

static mut LFD_LEGACY_ENCRYPT: Option<LfdLegacyEncrypt> = None;

static LEGACY: once_cell::sync::Lazy<Vec<openssl::provider::Provider>> = once_cell::sync::Lazy::new(|| {
    openssl::init();
    let mut vec: Vec<openssl::provider::Provider> = Vec::new();
    vec.push(openssl::provider::Provider::load(None, "default").expect("default"));
    vec.push(openssl::provider::Provider::load(None, "legacy").expect("legacy"));
    return vec;
});

impl LfdLegacyEncrypt {
    pub fn alloc(host: *mut VtunHost) -> Option<LfdLegacyEncrypt> {
        once_cell::sync::Lazy::force(&LEGACY);
        let mut lfdLegacyEncrypt = LfdLegacyEncrypt {
            ctx_enc: CipherCtx::new().unwrap(),
            ctx_dec: CipherCtx::new().unwrap(),
            returned_enc_buffer: Vec::new(),
            returned_dec_buffer: Vec::new(),
        };
        let passwd = unsafe { std::ffi::CStr::from_ptr((*host).passwd).to_str().unwrap() };
        let hs = hash(openssl::hash::MessageDigest::md5(), passwd.as_bytes());
        match hs {
            Err(err) => return None,
            Ok(key) => {
                lfdLegacyEncrypt.ctx_enc.encrypt_init(Some(Cipher::bf_ecb()), Some(&key[0..16]), None).unwrap();
                lfdLegacyEncrypt.ctx_dec.decrypt_init(Some(Cipher::bf_ecb()), Some(&key[0..16]), None).unwrap();
            }
        }
        lfdLegacyEncrypt.ctx_enc.set_padding(false);
        lfdLegacyEncrypt.ctx_dec.set_padding(false);

        unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "BlowFish legacy encryption initialized\n\0".as_ptr() as *mut libc::c_char); }

        return Some(lfdLegacyEncrypt);
    }
    pub fn encrypt(&mut self, buf: &mut[u8]) -> Option<Vec<u8>> {
        let pad = ((!(buf.len())) & 0x07) + 1;
        let p = 8 - pad;

        let mut output: Vec<u8> = Vec::new();
        output.reserve(buf.len() + pad + 8);
        output.push(pad as u8);
        output.resize(pad, 0u8);
        for i in 0..buf.len() {
            output.push(buf[i]);
        }
        let len = output.len();
        output.resize(len + 8, 0u8);
        match self.ctx_enc.cipher_update_inplace(&mut *output, len) {
            Err(_) => return None,
            Ok(reslen) => {
                output.resize(reslen, 0u8);
            }
        }
        let mut fdbuf: Vec<u8> = Vec::new();
        fdbuf.reserve(output.len() + lfd_mod::LINKFD_FRAME_RESERV + lfd_mod::LINKFD_FRAME_APPEND);
        fdbuf.resize(lfd_mod::LINKFD_FRAME_RESERV, 0u8);
        fdbuf.append(&mut output);
        fdbuf.resize(fdbuf.len() + lfd_mod::LINKFD_FRAME_APPEND, 0u8);
        return Some(fdbuf);
    }

    pub fn decrypt(&mut self, buf: &mut[u8]) -> Option<Vec<u8>> {
        let mut output: Vec<u8> = Vec::new();
        output.resize(buf.len() + 8, 0u8);
        match self.ctx_dec.cipher_update(buf, Some(&mut *output)) {
            Err(_) => return None,
            Ok(reslen) => {
                output.resize(reslen, 0u8);
            }
        }
        let p = output[0];
        if (p < 1 || p > 8) {
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "legacy_decrypt_buf: bad pad length\n\0".as_ptr() as *mut libc::c_char); }
            return None;
        }

        let mut fdbuf: Vec<u8> = Vec::new();
        fdbuf.reserve(output.len() + lfd_mod::LINKFD_FRAME_RESERV + lfd_mod::LINKFD_FRAME_APPEND);
        let payload = output.len() - (p as usize);
        fdbuf.resize(lfd_mod::LINKFD_FRAME_RESERV + payload, 0u8);
        for i in 0..payload {
            fdbuf[lfd_mod::LINKFD_FRAME_RESERV + i] = output[i + (p as usize)];
        }
        fdbuf.resize(fdbuf.len() + lfd_mod::LINKFD_FRAME_APPEND, 0u8);
        return Some(fdbuf);
    }
}

#[no_mangle]
pub extern "C" fn alloc_legacy_encrypt(host: *mut VtunHost) -> libc::c_int
{
    unsafe {
        LFD_LEGACY_ENCRYPT = LfdLegacyEncrypt::alloc(host);
        if (LFD_LEGACY_ENCRYPT.is_some()) {
            return 0;
        }
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn free_legacy_encrypt() -> libc::c_int {
    unsafe { LFD_LEGACY_ENCRYPT = None; }
    return 0;
}

#[no_mangle]
pub extern "C" fn legacy_encrypt_buf(len: libc::c_int, in_ptr: *mut libc::c_char, out_ptr: *mut *mut libc::c_char) -> libc::c_int {
    if in_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }

    let slice = unsafe {
        std::slice::from_raw_parts_mut(in_ptr as *mut u8, len as usize)
    };

    let output = unsafe { match &mut LFD_LEGACY_ENCRYPT {
        Some(ref mut lfdLegacyEncrypt) => lfdLegacyEncrypt.encrypt(slice),
        None => return -1
    } };

    unsafe {
        match &mut LFD_LEGACY_ENCRYPT {
            Some(ref mut lfdLegacyEncrypt) => {
                match output {
                    Some(outp) => {
                        lfdLegacyEncrypt.returned_enc_buffer = outp;
                        let len = lfdLegacyEncrypt.returned_enc_buffer.len() - lfd_mod::LINKFD_FRAME_RESERV - lfd_mod::LINKFD_FRAME_APPEND;
                        *out_ptr = *&lfdLegacyEncrypt.returned_enc_buffer.as_ptr() as *mut libc::c_char;
                        *out_ptr = (*out_ptr).add(lfd_mod::LINKFD_FRAME_RESERV);
                        return len as libc::c_int;
                    },
                    None => return -1
                }
            },
            None => return -1
        }
    }
}

#[no_mangle]
pub extern "C" fn legacy_decrypt_buf(len: libc::c_int, in_ptr: *mut libc::c_char, out_ptr: *mut *mut libc::c_char) -> libc::c_int {
    if in_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }

    let slice = unsafe {
        std::slice::from_raw_parts_mut(in_ptr as *mut u8, len as usize)
    };

    let output = unsafe { match &mut LFD_LEGACY_ENCRYPT {
        Some(ref mut lfdLegacyEncrypt) => lfdLegacyEncrypt.decrypt(slice),
        None => return -1
    } };

    unsafe {
        match &mut LFD_LEGACY_ENCRYPT {
            Some(ref mut lfdLegacyEncrypt) => {
                match output {
                    Some(outp) => {
                        lfdLegacyEncrypt.returned_dec_buffer = outp;
                        let len = lfdLegacyEncrypt.returned_dec_buffer.len() - lfd_mod::LINKFD_FRAME_RESERV - lfd_mod::LINKFD_FRAME_APPEND;
                        *out_ptr = *&lfdLegacyEncrypt.returned_dec_buffer.as_ptr() as *mut libc::c_char;
                        *out_ptr = (*out_ptr).add(lfd_mod::LINKFD_FRAME_RESERV);
                        return len as libc::c_int;
                    },
                    None => return 0
                }
            },
            None => return -1
        }
    }
}
