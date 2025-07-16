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
use crate::{lfd_mod, linkfd};
use crate::lfd_mod::VtunHost;
use crate::linkfd::{LfdMod, LfdModFactory};

pub struct LfdLegacyEncrypt {
    pub ctx_enc: CipherCtx,
    pub ctx_dec: CipherCtx,
    pub returned_enc_buffer: Vec<u8>,
    pub returned_dec_buffer: Vec<u8>,
}

static LEGACY: once_cell::sync::Lazy<Vec<openssl::provider::Provider>> = once_cell::sync::Lazy::new(|| {
    openssl::init();
    let mut vec: Vec<openssl::provider::Provider> = Vec::new();
    vec.push(openssl::provider::Provider::load(None, "default").expect("default"));
    vec.push(openssl::provider::Provider::load(None, "legacy").expect("legacy"));
    return vec;
});

impl LfdLegacyEncrypt {
    pub fn new(host: *mut VtunHost) -> Option<LfdLegacyEncrypt> {
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
        let mut output = match self.encode(buf) {
            None => return None,
            Some(output) => *output,
        };
        let mut fdbuf: Vec<u8> = Vec::new();
        fdbuf.reserve(output.len() + lfd_mod::LINKFD_FRAME_RESERV + lfd_mod::LINKFD_FRAME_APPEND);
        fdbuf.resize(lfd_mod::LINKFD_FRAME_RESERV, 0u8);
        fdbuf.append(&mut output);
        fdbuf.resize(fdbuf.len() + lfd_mod::LINKFD_FRAME_APPEND, 0u8);
        return Some(fdbuf);
    }

    pub fn decrypt(&mut self, buf: &mut[u8]) -> Option<Vec<u8>> {
        let mut output = match self.decode(buf) {
            None => return None,
            Some(output) => *output,
        };

        let mut fdbuf: Vec<u8> = Vec::new();
        fdbuf.reserve(output.len() + lfd_mod::LINKFD_FRAME_RESERV + lfd_mod::LINKFD_FRAME_APPEND);
        let payload = output.len();
        fdbuf.resize(lfd_mod::LINKFD_FRAME_RESERV + payload, 0u8);
        for i in 0..payload {
            fdbuf[lfd_mod::LINKFD_FRAME_RESERV + i] = output[i];
        }
        fdbuf.resize(fdbuf.len() + lfd_mod::LINKFD_FRAME_APPEND, 0u8);
        return Some(fdbuf);
    }
}

pub(crate) struct LfdLegacyEncryptFactory {
}

impl LfdLegacyEncryptFactory {
    pub fn new() -> LfdLegacyEncryptFactory {
        LfdLegacyEncryptFactory {
        }
    }
}

impl LfdModFactory for LfdLegacyEncryptFactory {
    fn name(&self) -> &'static str {
        "Encryptor"
    }
    fn create(&self, host: &mut VtunHost) -> Option<Box<dyn linkfd::LfdMod>> {
        return match LfdLegacyEncrypt::new(host) {
            None => None,
            Some(lfdEncryptMod) => Some(Box::new(lfdEncryptMod))
        };
    }
}

impl linkfd::LfdMod for LfdLegacyEncrypt {
    fn can_encode_inplace(&mut self) -> bool {
        false
    }
    fn encode(&mut self, buf: &[u8]) -> Option<Box<Vec<u8>>> {
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
        return Some(Box::new(output));
    }

    fn can_decode_inplace(&mut self) -> bool {
        false
    }

    fn decode(&mut self, buf: &[u8]) -> Option<Box<Vec<u8>>> {
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

        for i in 0..(output.len() - (p as usize)) {
            output[i] = output[i + (p as usize)];
        }
        output.resize(output.len() - p as usize, 0u8);
        return Some(Box::new(output));
    }
}
