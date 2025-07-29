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
use blowfish::Blowfish;
use cipher::{Block, BlockDecryptMut, BlockEncryptMut, KeyInit};
use ecb::{Decryptor, Encryptor};
use crate::{lfd_mod, linkfd, vtun_host};
use crate::linkfd::{LfdModFactory};

pub struct LfdLegacyEncrypt {
    pub ctx_enc: Encryptor<Blowfish>,
    pub ctx_dec: Decryptor<Blowfish>,
}

type BlowfishEcbEnc = Encryptor<Blowfish>;
type BlowfishEcbDec = Decryptor<Blowfish>;

impl LfdLegacyEncrypt {
    pub fn new(host: *mut vtun_host::VtunHost) -> Option<LfdLegacyEncrypt> {
        let passwd = unsafe { std::ffi::CStr::from_ptr((*host).passwd).to_str().unwrap() };
        let k = md5::compute(passwd.as_bytes());
        let mut key: [u8; 16] = [0u8; 16];
        for i in 0..16 {
            key[i] = k[i];
        }
        let lfd_legacy_encrypt = LfdLegacyEncrypt {
            ctx_enc: BlowfishEcbEnc::new_from_slice(&key).unwrap(),
            ctx_dec: BlowfishEcbDec::new_from_slice(&key).unwrap()
        };

        unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "BlowFish legacy encryption initialized\n\0".as_ptr() as *mut libc::c_char); }

        Some(lfd_legacy_encrypt)
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
    fn create(&self, host: &mut vtun_host::VtunHost) -> Option<Box<dyn linkfd::LfdMod>> {
        match LfdLegacyEncrypt::new(host) {
            None => None,
            Some(lfd_encrypt_mod) => Some(Box::new(lfd_encrypt_mod))
        }
    }
}

impl linkfd::LfdMod for LfdLegacyEncrypt {
    fn encode(&mut self, buf: &mut Vec<u8>) -> bool {
        let pad = ((!buf.len()) & 0x07) + 1;

        let inputlen = buf.len();
        buf.resize(buf.len() + pad, 0u8);
        for i in 0..inputlen {
            buf[inputlen + pad - 1 - i] = buf[inputlen - 1 - i];
        }
        buf[0] = pad as u8;
        for i in 1..pad {
            buf[i] = 0u8;
        }
        const BLOCKSIZE: usize = 8;
        for i in 0..buf.len()/ BLOCKSIZE {
            let mut data: [u8; BLOCKSIZE] = [0u8; BLOCKSIZE];
            for j in 0..BLOCKSIZE {
                data[j] = buf[i* BLOCKSIZE +j];
            }
            let mut block = Block::<BlowfishEcbEnc>::from(data);
            self.ctx_enc.encrypt_block_mut(&mut block);
            for j in 0..BLOCKSIZE {
                buf[i* BLOCKSIZE +j] = block[j];
            }
        }
        true
    }

    fn decode(&mut self, buf: &mut Vec<u8>) -> bool {
        const BLOCKSIZE: usize = 8;
        for i in 0..buf.len()/ BLOCKSIZE {
            let mut data: [u8; BLOCKSIZE] = [0u8; BLOCKSIZE];
            for j in 0..BLOCKSIZE {
                data[j] = buf[i* BLOCKSIZE +j];
            }
            let mut block = Block::<BlowfishEcbDec>::from(data);
            self.ctx_dec.decrypt_block_mut(&mut block);
            for j in 0..BLOCKSIZE {
                buf[i* BLOCKSIZE +j] = block[j];
            }
        }
        let p = buf[0];
        if p < 1 || p > 8 {
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "legacy_decrypt_buf: bad pad length\n\0".as_ptr() as *mut libc::c_char); }
            return false;
        }

        for i in 0..(buf.len() - (p as usize)) {
            buf[i] = buf[i + (p as usize)];
        }
        buf.resize(buf.len() - p as usize, 0u8);
        true
    }
}
