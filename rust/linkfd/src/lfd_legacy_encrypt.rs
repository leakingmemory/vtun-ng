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
use crate::{lfd_mod, linkfd};
use crate::lfd_mod::VtunHost;
use crate::linkfd::{LfdMod, LfdModFactory};

pub struct LfdLegacyEncrypt {
    pub ctx_enc: Encryptor<Blowfish>,
    pub ctx_dec: Decryptor<Blowfish>,
}

type BlowfishEcbEnc = ecb::Encryptor<Blowfish>;
type BlowfishEcbDec = ecb::Decryptor<Blowfish>;

impl LfdLegacyEncrypt {
    pub fn new(host: *mut VtunHost) -> Option<LfdLegacyEncrypt> {
        let passwd = unsafe { std::ffi::CStr::from_ptr((*host).passwd).to_str().unwrap() };
        let k = md5::compute(passwd.as_bytes());
        let mut key: [u8; 16] = [0u8; 16];
        for i in 0..16 {
            key[i] = k[i];
        }
        let mut lfdLegacyEncrypt = LfdLegacyEncrypt {
            ctx_enc: BlowfishEcbEnc::new_from_slice(&key).unwrap(),
            ctx_dec: BlowfishEcbDec::new_from_slice(&key).unwrap()
        };

        unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "BlowFish legacy encryption initialized\n\0".as_ptr() as *mut libc::c_char); }

        return Some(lfdLegacyEncrypt);
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
        output.reserve(buf.len() + pad);
        output.push(pad as u8);
        output.resize(pad, 0u8);
        for i in 0..buf.len() {
            output.push(buf[i]);
        }
        const blocksize: usize = 8;
        for i in 0..output.len()/blocksize {
            let mut data: [u8;blocksize] = [0u8; blocksize];
            for j in 0..blocksize {
                data[j] = output[i*blocksize+j];
            }
            let mut block = Block::<BlowfishEcbEnc>::from(data);
            self.ctx_enc.encrypt_block_mut(&mut block);
            for j in 0..blocksize {
                output[i*blocksize+j] = block[j];
            }
        }
        return Some(Box::new(output));
    }

    fn can_decode_inplace(&mut self) -> bool {
        false
    }

    fn decode(&mut self, buf: &[u8]) -> Option<Box<Vec<u8>>> {
        let mut output: Vec<u8> = Vec::new();
        output.resize(buf.len(), 0u8);
        const blocksize: usize = 8;
        for i in 0..buf.len()/blocksize {
            let mut data: [u8;blocksize] = [0u8; blocksize];
            for j in 0..blocksize {
                data[j] = buf[i*blocksize+j];
            }
            let mut block = Block::<BlowfishEcbDec>::from(data);
            self.ctx_dec.decrypt_block_mut(&mut block);
            for j in 0..blocksize {
                output[i*blocksize+j] = block[j];
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
