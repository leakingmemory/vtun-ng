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
 * From lfd_encrypt.c:
   Encryption module uses software developed by the OpenSSL Project
   for use in the OpenSSL Toolkit. (http://www.openssl.org/)
   Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
 */

/*
 * From lfd_encrypt.c:
 * This lfd_encrypt module uses MD5 to create 128 bits encryption
 * keys and BlowFish for actual data encryption.
 * It is based on code written by Chris Todd<christ@insynq.com> with
 * several improvements and modifications by me.
 */

/*
 * From lfd_encrypt.c:
 * The current lfd_encrypt module is based on code attributed above and
 * uses new code written by Dale Fountain <dpf-vtun@fountainbay.com> to
 * allow multiple ciphers, modes, and key sizes. Feb 2004.
 */

use std::ptr::null_mut;
use std::time::SystemTime;
use openssl::cipher::{Cipher, CipherRef};
use openssl::cipher_ctx::CipherCtx;
use crate::{lfd_mod, linkfd, vtun_host};
use lfd_mod::{VTUN_ENC_AES128CBC, VTUN_ENC_AES128CFB, VTUN_ENC_AES128OFB, VTUN_ENC_AES256CBC, VTUN_ENC_AES256CFB, VTUN_ENC_AES256OFB, VTUN_ENC_BF128CBC, VTUN_ENC_BF128CFB, VTUN_ENC_BF128OFB, VTUN_ENC_BF256CBC, VTUN_ENC_BF256CFB, VTUN_ENC_BF256OFB};
use crate::linkfd::LfdMod;

const MAX_GIBBERISH: i32	= 10;
const MIN_GIBBERISH: i32   = 1;
const MAX_GIBBERISH_TIME: u64   = 2;

pub enum CipherState {
    None,  CipherInit, CipherCode, CipherSequence, CipherReqInit
}

pub struct LfdEncrypt {
    pub sequence_num: u32,
    pub gibberish: i32,
    pub gib_time_start: u64,
    pub p_host: *mut vtun_host::VtunHost,
    pub cipher: libc::c_int,
    pub blocksize: u32,
    pub keysize: u32,
    pub enc_init_first_time: bool,
    pub dec_init_first_time: bool,
    pub send_a_packet: bool,
    pub pkey: Vec<u8>,
    pub cipher_enc_state: CipherState,
    pub cipher_dec_state: CipherState,
    pub ctx_enc: CipherCtx,
    pub ctx_dec: CipherCtx,
    pub ctx_enc_ecb: CipherCtx,
    pub ctx_dec_ecb: CipherCtx
}

impl LfdEncrypt {
    pub fn prep_key(keysize: usize, host: *mut vtun_host::VtunHost) -> Option<Vec<u8>> {
        if keysize != 32 && keysize != 16 {
            return None;
        }
        let mut pkey: Vec<u8> = Vec::new();
        pkey.resize(keysize, 0u8);
        let passwd = unsafe { std::ffi::CStr::from_ptr((*host).passwd).to_str().unwrap() };
        if keysize == 32 {
            let first_half = passwd[0..passwd.len()/2].as_bytes();
            let second_half = passwd[passwd.len()/2..passwd.len()].as_bytes();
            {
                let hs = md5::compute(first_half);
                for i in 0..hs.len() {
                    pkey[i] = hs[i];
                }
            }
            {
                let hs = md5::compute(second_half);
                for i in 0..hs.len() {
                    pkey[i + 16] = hs[i];
                }
            }
        } else /*keysize == 16*/ {
            let hs = md5::compute(passwd.as_bytes());
            for i in 0..hs.len() {
                pkey[i] = hs[i];
            }
        }
        Some(pkey)
    }
    pub fn new(host: *mut vtun_host::VtunHost) -> Option<LfdEncrypt> {
        let mut lfd_encrypt: LfdEncrypt = LfdEncrypt {
            sequence_num: 0,
            gibberish: 0,
            gib_time_start: 0,
            p_host: null_mut(),
            cipher: 0,
            blocksize: 0,
            keysize: 0,
            enc_init_first_time: true,
            dec_init_first_time: true,
            send_a_packet: false,
            pkey: Vec::new(),
            cipher_enc_state: CipherState::None,
            cipher_dec_state: CipherState::None,
            ctx_enc: CipherCtx::new().unwrap(),
            ctx_dec: CipherCtx::new().unwrap(),
            ctx_enc_ecb: CipherCtx::new().unwrap(),
            ctx_dec_ecb: CipherCtx::new().unwrap()
        };
        let mut sb_init: bool = false;
        let mut random_bytes = [0u8; 4];

        let cipher_type: Option<&CipherRef>;

        openssl::rand::rand_bytes(&mut random_bytes).unwrap();
        lfd_encrypt.sequence_num = u32::from_ne_bytes(random_bytes);
        lfd_encrypt.gibberish = 0;
        lfd_encrypt.gib_time_start = 0;
        lfd_encrypt.p_host = host;
        unsafe {
            lfd_encrypt.cipher = (*host).cipher;
        }
        let cipher_name: &str;
        if lfd_encrypt.cipher == VTUN_ENC_AES256OFB ||
            lfd_encrypt.cipher == VTUN_ENC_AES256OFB ||
            lfd_encrypt.cipher == VTUN_ENC_AES256CFB ||
            lfd_encrypt.cipher == VTUN_ENC_AES256CBC {
            lfd_encrypt.blocksize = 16;
            lfd_encrypt.keysize = 32;
            sb_init = true;
            cipher_type = Some(Cipher::aes_256_ecb());
            cipher_name = "AES-256-ECB";
        }
        else if lfd_encrypt.cipher == lfd_mod::VTUN_ENC_AES256ECB
        {
            lfd_encrypt.blocksize = 16;
            lfd_encrypt.keysize = 32;
            cipher_type = Some(Cipher::aes_256_ecb());
            cipher_name = "AES-256-ECB";
        }
        else if lfd_encrypt.cipher == VTUN_ENC_AES128OFB ||
            lfd_encrypt.cipher == VTUN_ENC_AES128CFB ||
            lfd_encrypt.cipher == VTUN_ENC_AES128CBC
        {
            lfd_encrypt.blocksize = 16;
            lfd_encrypt.keysize = 16;
            sb_init = true;
            cipher_type = Some(Cipher::aes_128_ecb());
            cipher_name = "AES-128-ECB";
        }
        else if lfd_encrypt.cipher == lfd_mod::VTUN_ENC_AES128ECB
        {
            lfd_encrypt.blocksize = 16;
            lfd_encrypt.keysize = 16;
            cipher_type = Some(Cipher::aes_128_ecb());
            cipher_name = "AES-128-ECB";
        }
        else if lfd_encrypt.cipher == VTUN_ENC_BF256OFB ||
            lfd_encrypt.cipher == VTUN_ENC_BF256CFB ||
            lfd_encrypt.cipher == VTUN_ENC_BF256CBC
        {
            lfd_encrypt.blocksize = 8;
            lfd_encrypt.keysize = 32;
            sb_init = true;
            cipher_type = Some(Cipher::bf_ecb());
            cipher_name = "BF-ECB";
        }
        else if lfd_encrypt.cipher == lfd_mod::VTUN_ENC_BF256ECB
        {
            lfd_encrypt.blocksize = 8;
            lfd_encrypt.keysize = 32;
            cipher_type = Some(Cipher::bf_ecb());
            cipher_name = "BF-ECB";
        }
        else if lfd_encrypt.cipher == VTUN_ENC_BF128OFB ||
            lfd_encrypt.cipher == VTUN_ENC_BF128CFB ||
            lfd_encrypt.cipher == VTUN_ENC_BF128CBC
        {
            lfd_encrypt.blocksize = 8;
            lfd_encrypt.keysize = 16;
            sb_init = true;
            cipher_type = Some(Cipher::bf_ecb());
            cipher_name = "BF-ECB";
        }
        else /*if (lfd_encrypt.cipher == lfd_mod::VTUN_ENC_BF128ECB)*/
        {
            lfd_encrypt.blocksize = 8;
            lfd_encrypt.keysize = 16;
            cipher_type = Some(Cipher::bf_ecb());
            cipher_name = "BF-ECB";
        }
        if cipher_type.is_none() {
            return None;
        }
        if cipher_type.unwrap().key_length() != lfd_encrypt.keysize as usize {
            return None;
        }
        if lfd_encrypt.keysize == 32 {
            match Self::prep_key(32, host) {
                None => return None,
                Some(pkey) => {
                    lfd_encrypt.pkey = pkey;
                }
            }
        } else if lfd_encrypt.keysize == 16 {
            match Self::prep_key(16, host) {
                None => return None,
                Some(pkey) => {
                    lfd_encrypt.pkey = pkey;
                }
            }
        } else {
            return None;
        }
        if sb_init {
            lfd_encrypt.ctx_enc_ecb.encrypt_init(cipher_type, Some(&*lfd_encrypt.pkey), None).unwrap();
            lfd_encrypt.ctx_dec_ecb.decrypt_init(cipher_type, Some(&*lfd_encrypt.pkey), None).unwrap();
            lfd_encrypt.ctx_enc_ecb.set_padding(false);
            lfd_encrypt.ctx_dec_ecb.set_padding(false);
            lfd_encrypt.cipher_enc_state = CipherState::CipherInit;
            lfd_encrypt.cipher_dec_state = CipherState::CipherInit;
        } else {
            lfd_encrypt.ctx_enc.encrypt_init(cipher_type, Some(&*lfd_encrypt.pkey), None).unwrap();
            lfd_encrypt.ctx_dec.decrypt_init(cipher_type, Some(&*lfd_encrypt.pkey), None).unwrap();
            lfd_encrypt.ctx_enc.set_padding(false);
            lfd_encrypt.ctx_dec.set_padding(false);
            lfd_encrypt.cipher_enc_state = CipherState::CipherCode;
            lfd_encrypt.cipher_dec_state = CipherState::CipherCode;
            let tmpstr = format!("{}! encryption initialized", cipher_name);
            unsafe {
                lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, tmpstr.as_ptr() as *mut libc::c_char);
            }
        }
        Some(lfd_encrypt)
    }

    fn cipher_enc_init(&mut self, iv: &[u8]) -> bool
    {
        let mut var_key: bool = false;
        let cipher_type: Option<&CipherRef>;
        let cipher_name: &str;

        if self.cipher == VTUN_ENC_AES256OFB {
            cipher_type = Some(Cipher::aes_256_ofb());
            cipher_name = "AES-256-OFB";
        } else if self.cipher == VTUN_ENC_AES256CFB {
            cipher_type = Some(Cipher::aes_256_cfb128());
            cipher_name = "AES-256-CFB";
        } else if self.cipher == VTUN_ENC_AES256CBC {
            cipher_type = Some(Cipher::aes_256_cbc());
            cipher_name = "AES-256-CBC";
        } else if self.cipher == VTUN_ENC_AES128OFB {
            cipher_type = Some(Cipher::aes_128_ofb());
            cipher_name = "AES-128-OFB";
        } else if self.cipher == VTUN_ENC_AES128CFB {
            cipher_type = Some(Cipher::aes_128_cfb128());
            cipher_name = "AES-128-CFB";
        } else if self.cipher == VTUN_ENC_AES128CBC {
            cipher_type = Some(Cipher::aes_128_cbc());
            cipher_name = "AES-128-CBC";
        } else if self.cipher == VTUN_ENC_BF256OFB {
            var_key = true;
            cipher_type = Some(Cipher::bf_ofb());
            cipher_name = "Blowfish-256-OFB";
        } else if self.cipher == VTUN_ENC_BF256CFB {
            var_key = true;
            cipher_type = Some(Cipher::bf_cfb64());
            cipher_name = "Blowfish-256-CFB";
        } else if self.cipher == VTUN_ENC_BF256CBC {
            var_key = true;
            cipher_type = Some(Cipher::bf_cbc());
            cipher_name = "Blowfish-256-CBC";
        } else if self.cipher == VTUN_ENC_BF128OFB {
            var_key = true;
            cipher_type = Some(Cipher::bf_ofb());
            cipher_name = "Blowfish-128-OFB";
        } else if self.cipher == VTUN_ENC_BF128CFB {
            var_key = true;
            cipher_type = Some(Cipher::bf_cfb64());
            cipher_name = "Blowfish-128-CFB";
        } else if self.cipher == VTUN_ENC_BF128CBC {
            var_key = true;
            cipher_type = Some(Cipher::bf_cbc());
            cipher_name = "Blowfish-128-CBC";
        } else {
            /* if we're here, something weird's going on */
            return false;
        }

        if var_key {
            match self.ctx_enc.set_key_length(self.keysize as usize) {
                Ok(_) => {},
                Err(_) => return false
            }
        }
        self.ctx_enc.encrypt_init(cipher_type, Some(&*self.pkey), Some(iv)).unwrap();
        self.ctx_enc.set_padding(false);
        if self.enc_init_first_time
        {
            let tmpstr = format!("{} encryption initialized\n\0", cipher_name);
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, tmpstr.as_ptr() as *mut libc::c_char); }
            self.enc_init_first_time = false;
        }
        true
    }

    fn cipher_dec_init(&mut self, iv: &[u8]) -> bool
    {
        let mut var_key: bool = false;
        let cipher_type: Option<&CipherRef>;
        let cipher_name: &str;

        if self.cipher == VTUN_ENC_AES256OFB {
            cipher_type = Some(Cipher::aes_256_ofb());
            cipher_name = "AES-256-OFB";
        } else if self.cipher == VTUN_ENC_AES256CFB {
            cipher_type = Some(Cipher::aes_256_cfb128());
            cipher_name = "AES-256-CFB";
        } else if self.cipher == VTUN_ENC_AES256CBC {
            cipher_type = Some(Cipher::aes_256_cbc());
            cipher_name = "AES-256-CBC";
        } else if self.cipher == VTUN_ENC_AES128OFB {
            cipher_type = Some(Cipher::aes_128_ofb());
            cipher_name = "AES-128-OFB";
        } else if self.cipher == VTUN_ENC_AES128CFB {
            cipher_type = Some(Cipher::aes_128_cfb128());
            cipher_name = "AES-128-CFB";
        } else if self.cipher == VTUN_ENC_AES128CBC {
            cipher_type = Some(Cipher::aes_128_cbc());
            cipher_name = "AES-128-CBC";
        } else if self.cipher == VTUN_ENC_BF256OFB {
            var_key = true;
            cipher_type = Some(Cipher::bf_ofb());
            cipher_name = "Blowfish-256-OFB";
        } else if self.cipher == VTUN_ENC_BF256CFB {
            var_key = true;
            cipher_type = Some(Cipher::bf_cfb64());
            cipher_name = "Blowfish-256-CFB";
        } else if self.cipher == VTUN_ENC_BF256CBC {
            var_key = true;
            cipher_type = Some(Cipher::bf_cbc());
            cipher_name = "Blowfish-256-CBC";
        } else if self.cipher == VTUN_ENC_BF128OFB {
            var_key = true;
            cipher_type = Some(Cipher::bf_ofb());
            cipher_name = "Blowfish-128-OFB";
        } else if self.cipher == VTUN_ENC_BF128CFB {
            var_key = true;
            cipher_type = Some(Cipher::bf_cfb64());
            cipher_name = "Blowfish-128-CFB";
        } else if self.cipher == VTUN_ENC_BF128CBC {
            var_key = true;
            cipher_type = Some(Cipher::bf_cbc());
            cipher_name = "Blowfish-128-CBC";
        } else {
            /* if we're here, something weird's going on */
            return false;
        }

        if var_key {
            match self.ctx_dec.set_key_length(self.keysize as usize) {
                Ok(_) => {},
                Err(_) => return false
            }
        }
        self.ctx_dec.decrypt_init(cipher_type, Some(&*self.pkey), Some(iv)).unwrap();
        self.ctx_dec.set_padding(false);
        if self.dec_init_first_time
        {
            let tmpstr = format!("{} decryption initialized\n\0", cipher_name);
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, tmpstr.as_ptr() as *mut libc::c_char); }
            self.dec_init_first_time = false;
        }
        true
    }

    pub fn send_msg(&mut self) -> Option<Vec<u8>> {
        if matches!(self.cipher_enc_state, CipherState::CipherInit) {
            let mut outbuf: Vec<u8> = Vec::new();
            outbuf.reserve((self.blocksize as usize) * 3);
            outbuf.push(b'i');
            outbuf.push(b'v');
            outbuf.push(b'e');
            outbuf.push(b'c');
            {
                let mut iv: Vec<u8> = Vec::new();
                iv.resize(self.blocksize as usize, 0u8);
                openssl::rand::rand_bytes(&mut iv).unwrap();
                let ivstart = outbuf.len();
                outbuf.resize(ivstart + (self.blocksize as usize), 0u8);
                for i in 0..self.blocksize {
                    outbuf[ivstart + (i as usize)] = iv[i as usize];
                }
                if !self.cipher_enc_init(&*iv) {
                    return None;
                }
            }
            {
                let before = outbuf.len();
                outbuf.resize((self.blocksize as usize) * 2, 0u8);
                let appended = outbuf.len() - before;
                let mut tmpbuf: Vec<u8> = Vec::new();
                tmpbuf.resize(appended, 0u8);
                openssl::rand::rand_bytes(&mut tmpbuf).unwrap();
                for i in 0..appended {
                    outbuf[before + i] = tmpbuf[i];
                }
                let outlen = outbuf.len();
                outbuf.resize(outlen + (self.blocksize as usize), 0u8);
                match self.ctx_enc_ecb.cipher_update_inplace(&mut *outbuf, outlen) {
                    Ok(rlen) => { outbuf.resize(rlen, 0u8); },
                    Err(_) => return None
                };
                self.cipher_enc_state = CipherState::CipherSequence;
                Some(outbuf)
            }
        } else /*default or self.cipher_enc_state == CipherState::CipherCode)*/ {
            None
        }
    }

    /* Send In-Band Message */
    fn send_ib_mesg(&mut self) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::new();
        /* To simplify matters, I assume that blocksize
              will not be less than 8 bytes */
        if matches!(self.cipher_enc_state, CipherState::CipherSequence) {
            output.reserve(self.blocksize as usize);
            output.push(b's');
            output.push(b'e');
            output.push(b'q');
            output.push(b'#');
            output.push(((self.sequence_num >> 24) & 0xFF) as u8);
            output.push(((self.sequence_num >> 16) & 0xFF) as u8);
            output.push(((self.sequence_num >> 8) & 0xFF) as u8);
            output.push((self.sequence_num & 0xFF) as u8);
            if output.len() < self.blocksize as usize {
                output.resize(self.blocksize as usize, 0u8);
            }
        } else if matches!(self.cipher_enc_state, CipherState::CipherReqInit) {
            output.reserve(self.blocksize as usize);
            output.push(b'r');
            output.push(b's');
            output.push(b'y');
            output.push(b'n');
            output.push(((self.sequence_num >> 24) & 0xFF) as u8);
            output.push(((self.sequence_num >> 16) & 0xFF) as u8);
            output.push(((self.sequence_num >> 8) & 0xFF) as u8);
            output.push((self.sequence_num & 0xFF) as u8);
            if output.len() < self.blocksize as usize {
                output.resize(self.blocksize as usize, 0u8);
            }
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "Requesting remote encryptor re-init".as_ptr() as *mut libc::c_char); }
            self.cipher_enc_state = CipherState::CipherSequence;
            self.send_a_packet = true;
        }
        output
    }

    fn recv_msg(&mut self, buf: &mut Vec<u8>) -> bool
    {
        let mut iv: Vec<u8> = Vec::new();

        if matches!(self.cipher_dec_state, CipherState::CipherInit)
        {
            if buf.len() < ((self.blocksize as usize) * 2) {
                return false;
            }
            let mut outp: Vec<u8> = Vec::new();
            outp.resize((self.blocksize as usize) * 3, 0u8);
            match self.ctx_dec_ecb.cipher_update(&buf[..(self.blocksize as usize * 2)], Some(&mut *outp)) {
                Ok(rlen) => { outp.resize(rlen, 0u8); },
                Err(_) => return false
            };
            if outp[0] == b'i' && outp[1] == b'v' && outp[2] == b'e' && outp[3] == b'c' {
                iv.resize(self.blocksize as usize, 0u8);
                for i in 0..self.blocksize {
                    iv[i as usize] = outp[i as usize + 4];
                }
                if !self.cipher_dec_init(&*iv) {
                    return false;
                }
                self.cipher_dec_state = CipherState::CipherSequence;
                self.gibberish = 0;
                self.gib_time_start = 0;
                for i in 0..(buf.len() - ((self.blocksize as usize) * 2)) {
                    buf[i] = buf[i + ((self.blocksize as usize) * 2)];
                }
                buf.resize(buf.len() - ((self.blocksize as usize) * 2), 0u8);

                return true;
            } else {
                self.gibberish += 1;
                let mut gibberish_diff_time = 0;
                if self.gibberish == 1 {
                    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                        Ok(tm) => { self.gib_time_start = tm.as_secs() },
                        Err(_) => { self.gib_time_start = 0 },
                    }
                } else {
                    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                        Ok(tm) => { gibberish_diff_time = tm.as_secs() - self.gib_time_start },
                        Err(_) => { gibberish_diff_time = 0 }
                    }
                }
                if self.gibberish == MIN_GIBBERISH
                {
                    self.cipher_enc_state = CipherState::CipherReqInit;
                    self.send_a_packet = true;
                    unsafe {
                        lfd_mod::vtun_syslog(lfd_mod::LOG_INFO,
                                             "Min. gibberish threshold reached".as_ptr() as *mut libc::c_char);
                    }
                }
                if self.gibberish >= MAX_GIBBERISH || gibberish_diff_time >= MAX_GIBBERISH_TIME
                {
                    self.gibberish = 0;
                    self.gib_time_start = 0;
                    self.send_a_packet = true;

                    unsafe {
                        lfd_mod::vtun_syslog(lfd_mod::LOG_INFO,
                                             "Max. gibberish threshold reached".as_ptr() as *mut libc::c_char);
                    }
                    if matches!(self.cipher_enc_state, CipherState::CipherInit)
                    {
                        self.cipher_enc_state = CipherState::CipherInit;
                        self.ctx_enc = CipherCtx::new().unwrap();
                        unsafe {
                            lfd_mod::vtun_syslog(lfd_mod::LOG_INFO,
                                                 "Forcing local encryptor re-init".as_ptr() as *mut libc::c_char);
                        }
                    }
                }
            }
        }
        true
    }
    fn recv_ib_mesg(&mut self, buf: &mut Vec<u8>) -> bool
    {
        if matches!(self.cipher_dec_state, CipherState::CipherSequence)
        {
            if buf.len() < self.blocksize as usize {
                return false;
            }
            /* To simplify matters, I assume that blocksize
               will not be less than 8 bytes */
            if buf[0] == b's' && buf[1] == b'e' && buf[2] == b'q' && buf[3] == b'#'
            {
            }
            else if buf[0] == b'r' && buf[1] == b's' && buf[2] == b'y' && buf[3] == b'n'
            {
                if !matches!(self.cipher_enc_state, CipherState::CipherInit)
                {
                    self.cipher_enc_state = CipherState::CipherInit;
                    self.ctx_enc = CipherCtx::new().unwrap();
                }
                unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "Remote requests encryptor re-init".as_ptr() as *mut libc::c_char); }
            }
            else
            {
                if !matches!(self.cipher_dec_state, CipherState::CipherInit) &&
                   !matches!(self.cipher_enc_state, CipherState::CipherReqInit) &&
                   !matches!(self.cipher_enc_state, CipherState::CipherInit)
                {
                    self.ctx_dec = CipherCtx::new().unwrap();
                    self.cipher_dec_state = CipherState::CipherInit;
                    self.cipher_enc_state = CipherState::CipherReqInit;
                }
                unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "Local decryptor out of sync".as_ptr() as *mut libc::c_char); }

                buf.clear();
                return true;
            }
            for i in 0..(buf.len() - (self.blocksize as usize)) {
                buf[i] = buf[i + (self.blocksize as usize)];
            }
            buf.resize(buf.len() - (self.blocksize as usize), 0u8);
            return true;
        }
        true
    }
}

pub(crate) struct LfdEncryptFactory {
}

impl LfdEncryptFactory {
    pub fn new() -> LfdEncryptFactory {
        LfdEncryptFactory {
        }
    }
}

impl linkfd::LfdModFactory for LfdEncryptFactory {
    fn create(&self, host: &mut vtun_host::VtunHost) -> Option<Box<dyn LfdMod>> {
        match LfdEncrypt::new(host) {
            None => None,
            Some(e) => Some(Box::new(e))
        }
    }
}

impl LfdMod for LfdEncrypt {
    fn encode(&mut self, buf: &mut Vec<u8>) -> bool {
        let sendbuf = self.send_msg();

        let ib = self.send_ib_mesg();
        {
            let mut expectedlen = ib.len() + buf.len();
            let p = expectedlen & ((self.blocksize-1) as usize);
            expectedlen += (self.blocksize as usize) - p;
            expectedlen += self.blocksize as usize;
            if buf.capacity() < expectedlen {
                buf.reserve(expectedlen);
            }
        }
        {
            let inputlen = buf.len();
            buf.resize(inputlen + ib.len(), 0u8);
            for i in 0..inputlen {
                buf[ib.len() + inputlen - i - 1] = buf[inputlen - i - 1];
            }
            for i in 0..ib.len() {
                buf[i] = ib[i];
            }
        }
        /* ( len % blocksize ) */
        let p = buf.len() & ((self.blocksize-1) as usize);
        let pad = (self.blocksize as usize) - p;

        buf.resize(buf.len() + pad, (pad & 0xFF) as u8);
        if pad == (self.blocksize as usize) {
            let mut rand_bytes: Vec<u8> = Vec::new();
            rand_bytes.resize((self.blocksize - 1) as usize, 0u8);
            openssl::rand::rand_bytes(&mut rand_bytes).unwrap();
            for i in 0..(self.blocksize - 1) {
                let outbuflen = buf.len();
                buf[outbuflen - (self.blocksize as usize) + (i as usize)] = rand_bytes[i as usize];
            }
        }
        {
            let outbuflen = buf.len();
            buf.resize(outbuflen + (self.blocksize as usize), 0u8);
            match self.ctx_enc.cipher_update_inplace(&mut *buf, outbuflen) {
                Ok(rlen) => { buf.resize(rlen, 0u8); },
                Err(_) => return false
            }
        }

        self.sequence_num += 1;

        match sendbuf {
            Some(sendbuf) => {
                let buflen = buf.len();
                buf.resize(buflen + sendbuf.len(), 0u8);
                for i in 0..buflen {
                    buf[buflen + sendbuf.len() - i - 1] = buf[buflen - i - 1];
                }
                for i in 0..sendbuf.len() {
                    buf[i] = sendbuf[i];
                }
                true
            },
            None => true
        }
    }
    fn decode(&mut self, buf: &mut Vec<u8>) -> bool {
        if !self.recv_msg(buf) {
            return false;
        }

        let msglen = buf.len();
        buf.resize(msglen + (self.blocksize as usize), 0u8);
        match self.ctx_dec.cipher_update_inplace(buf.as_mut_slice(), msglen) {
            Ok(outlen) => {buf.resize(outlen, 0u8)},
            Err(_) => return false
        };

        if !self.recv_ib_mesg(buf) {
            return false;
        }

        let iblen = buf.len();
        let pad = buf[iblen - 1];
        if pad < 1 || (pad as u32) > self.blocksize {
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "decrypt_buf: bad pad length".as_ptr() as *mut libc::c_char); }
            return false;
        }
        buf.resize(iblen - pad as usize, 0u8);
        true
    }
}
