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
use openssl::hash::{hash, MessageDigest};
use lfd_mod;
use lfd_mod::{VtunHost, VTUN_ENC_AES128CBC, VTUN_ENC_AES128CFB, VTUN_ENC_AES128OFB, VTUN_ENC_AES256CBC, VTUN_ENC_AES256CFB, VTUN_ENC_AES256OFB, VTUN_ENC_BF128CBC, VTUN_ENC_BF128CFB, VTUN_ENC_BF128OFB, VTUN_ENC_BF256CBC, VTUN_ENC_BF256CFB, VTUN_ENC_BF256OFB};

const MAX_GIBBERISH: i32	= 10;
const MIN_GIBBERISH: i32   = 1;
const MAX_GIBBERISH_TIME: u64   = 2;
const LINKFD_FRAME_RESERV: usize = 128;
const LINKFD_FRAME_APPEND: usize = 64;

pub enum CipherState {
    None,  CipherInit, CipherCode, CipherSequence, CipherReqInit
}

pub struct LfdEncrypt {
    pub sequence_num: u32,
    pub gibberish: i32,
    pub gib_time_start: u64,
    pub p_host: *mut VtunHost,
    pub cipher: libc::c_int,
    pub blocksize: u32,
    pub keysize: u32,
    pub enc_init_first_time: bool,
    pub dec_init_first_time: bool,
    pub send_a_packet: bool,
    pub pkey: Vec<u8>,
    pub returned_enc_buffer: Vec<u8>,
    pub returned_dec_buffer: Vec<u8>,
    pub cipher_enc_state: CipherState,
    pub cipher_dec_state: CipherState,
    pub ctx_enc: openssl::cipher_ctx::CipherCtx,
    pub ctx_dec: openssl::cipher_ctx::CipherCtx,
    pub ctx_enc_ecb: openssl::cipher_ctx::CipherCtx,
    pub ctx_dec_ecb: openssl::cipher_ctx::CipherCtx
}

static mut LFD_ENCRYPT: Option<LfdEncrypt> = None;

impl LfdEncrypt {
    pub fn prep_key(keysize: usize, host: *mut VtunHost) -> Option<Vec<u8>> {
        if (keysize != 32 && keysize != 16) {
            return None;
        }
        let mut pkey: Vec<u8> = Vec::new();
        pkey.resize(keysize, 0u8);
        let passwd = unsafe { std::ffi::CStr::from_ptr((*host).passwd).to_str().unwrap() };
        if keysize == 32 {
            let first_half = passwd[0..passwd.len()/2].as_bytes();
            let second_half = passwd[passwd.len()/2..passwd.len()].as_bytes();
            {
                let hs = hash(MessageDigest::md5(), first_half);
                match hs {
                    Ok(hs) => {
                        for i in 0..hs.len() {
                            pkey[i] = hs[i];
                        }
                    },
                    Err(_) => {
                        return None;
                    }
                }
            }
            {
                let hs = hash(MessageDigest::md5(), second_half);
                match hs {
                    Ok(hs) => {
                        for i in 0..hs.len() {
                            pkey[i + 16] = hs[i];
                        }
                    },
                    Err(_) => {
                        return None;
                    }
                }
            }
        } else /*keysize == 16*/ {
            let hs = hash(MessageDigest::md5(), passwd.as_bytes());
            match hs {
                Ok(hs) => {
                    for i in 0..hs.len() {
                        pkey[i] = hs[i];
                    }
                },
                Err(_) => {
                    return None;
                }
            }
        }
        return Some(pkey);
    }
    pub fn alloc(host: *mut VtunHost) -> Option<LfdEncrypt> {
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
            returned_enc_buffer: Vec::new(),
            returned_dec_buffer: Vec::new(),
            cipher_enc_state: CipherState::None,
            cipher_dec_state: CipherState::None,
            ctx_enc: CipherCtx::new().unwrap(),
            ctx_dec: CipherCtx::new().unwrap(),
            ctx_enc_ecb: CipherCtx::new().unwrap(),
            ctx_dec_ecb: CipherCtx::new().unwrap()
        };
        let mut sb_init: bool = false;
        let mut var_key: bool = false;
        let mut random_bytes = [0u8; 4];
        let mut cipher_type: Option<&CipherRef> = None;
        openssl::rand::rand_bytes(&mut random_bytes).unwrap();
        lfd_encrypt.sequence_num = u32::from_ne_bytes(random_bytes);
        lfd_encrypt.gibberish = 0;
        lfd_encrypt.gib_time_start = 0;
        lfd_encrypt.p_host = host;
        unsafe {
            lfd_encrypt.cipher = (*host).cipher;
        }
        let mut cipher_name = "";
        if (lfd_encrypt.cipher == lfd_mod::VTUN_ENC_AES256OFB ||
            lfd_encrypt.cipher == lfd_mod::VTUN_ENC_AES256OFB ||
            lfd_encrypt.cipher == lfd_mod::VTUN_ENC_AES256CFB ||
            lfd_encrypt.cipher == lfd_mod::VTUN_ENC_AES256CBC) {
            lfd_encrypt.blocksize = 16;
            lfd_encrypt.keysize = 32;
            sb_init = true;
            cipher_type = Some(Cipher::aes_256_ecb());
            cipher_name = "AES-256-ECB";
        }
        else if (lfd_encrypt.cipher == lfd_mod::VTUN_ENC_AES256ECB)
        {
            lfd_encrypt.blocksize = 16;
            lfd_encrypt.keysize = 32;
            cipher_type = Some(Cipher::aes_256_ecb());
            cipher_name = "AES-256-ECB";
        }
        else if (lfd_encrypt.cipher == lfd_mod::VTUN_ENC_AES128OFB ||
            lfd_encrypt.cipher == lfd_mod::VTUN_ENC_AES128CFB ||
            lfd_encrypt.cipher == lfd_mod::VTUN_ENC_AES128CBC)
        {
            lfd_encrypt.blocksize = 16;
            lfd_encrypt.keysize = 16;
            sb_init = true;
            cipher_type = Some(Cipher::aes_128_ecb());
            cipher_name = "AES-128-ECB";
        }
        else if (lfd_encrypt.cipher == lfd_mod::VTUN_ENC_AES128ECB)
        {
            lfd_encrypt.blocksize = 16;
            lfd_encrypt.keysize = 16;
            cipher_type = Some(Cipher::aes_128_ecb());
            cipher_name = "AES-128-ECB";
        }
        else if (lfd_encrypt.cipher == lfd_mod::VTUN_ENC_BF256OFB ||
            lfd_encrypt.cipher == lfd_mod::VTUN_ENC_BF256CFB ||
            lfd_encrypt.cipher == lfd_mod::VTUN_ENC_BF256CBC)
        {
            lfd_encrypt.blocksize = 8;
            lfd_encrypt.keysize = 32;
            var_key = true;
            sb_init = true;
            cipher_type = Some(Cipher::bf_ecb());
            cipher_name = "BF-ECB";
        }
        else if (lfd_encrypt.cipher == lfd_mod::VTUN_ENC_BF256ECB)
        {
            lfd_encrypt.blocksize = 8;
            lfd_encrypt.keysize = 32;
            var_key = true;
            cipher_type = Some(Cipher::bf_ecb());
            cipher_name = "BF-ECB";
        }
        else if (lfd_encrypt.cipher == lfd_mod::VTUN_ENC_BF128OFB ||
            lfd_encrypt.cipher == lfd_mod::VTUN_ENC_BF128CFB ||
            lfd_encrypt.cipher == lfd_mod::VTUN_ENC_BF128CBC)
        {
            lfd_encrypt.blocksize = 8;
            lfd_encrypt.keysize = 16;
            var_key = true;
            sb_init = true;
            cipher_type = Some(Cipher::bf_ecb());
            cipher_name = "BF-ECB";
        }
        else /*if (lfd_encrypt.cipher == lfd_mod::VTUN_ENC_BF128ECB)*/
        {
            lfd_encrypt.blocksize = 8;
            lfd_encrypt.keysize = 16;
            var_key = true;
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
            if (sb_init) {
                lfd_encrypt.ctx_enc_ecb.encrypt_init(cipher_type, Some(&*lfd_encrypt.pkey), None).unwrap();
                lfd_encrypt.ctx_dec_ecb.decrypt_init(cipher_type, Some(&*lfd_encrypt.pkey), None).unwrap();
            } else {
                lfd_encrypt.ctx_enc.encrypt_init(cipher_type, Some(&*lfd_encrypt.pkey), None).unwrap();
                lfd_encrypt.ctx_dec.decrypt_init(cipher_type, Some(&*lfd_encrypt.pkey), None).unwrap();
            }
        } else if (lfd_encrypt.keysize == 16) {
            match Self::prep_key(16, host) {
                None => return None,
                Some(pkey) => {
                    lfd_encrypt.pkey = pkey;
                }
            }
            if (sb_init) {
                lfd_encrypt.ctx_enc_ecb.encrypt_init(cipher_type, Some(&*lfd_encrypt.pkey), None).unwrap();
                lfd_encrypt.ctx_dec_ecb.decrypt_init(cipher_type, Some(&*lfd_encrypt.pkey), None).unwrap();
            } else {
                lfd_encrypt.ctx_enc.encrypt_init(cipher_type, Some(&*lfd_encrypt.pkey), None).unwrap();
                lfd_encrypt.ctx_dec.decrypt_init(cipher_type, Some(&*lfd_encrypt.pkey), None).unwrap();
            }
        } else {
            return None;
        }
        if (sb_init)
        {
            lfd_encrypt.ctx_enc_ecb.set_padding(false);
            lfd_encrypt.ctx_dec_ecb.set_padding(false);
            lfd_encrypt.cipher_enc_state = CipherState::CipherInit;
            lfd_encrypt.cipher_dec_state = CipherState::CipherInit;
        }
        else
        {
            lfd_encrypt.ctx_enc.set_padding(false);
            lfd_encrypt.ctx_dec.set_padding(false);
            lfd_encrypt.cipher_enc_state = CipherState::CipherCode;
            lfd_encrypt.cipher_dec_state = CipherState::CipherCode;
            let tmpstr = format!("{}! encryption initialized", cipher_name);
            unsafe {
                lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, tmpstr.as_ptr() as *mut libc::c_char);
            }
        }
        return Some(lfd_encrypt);
    }

    fn cipher_enc_init(&mut self, iv: &[u8]) -> bool
    {
        let mut var_key: bool = false;
        let mut cipher_type: Option<&CipherRef> = None;
        //char tmpstr[64];
        let mut cipher_name = "";

        if (self.cipher == VTUN_ENC_AES256OFB) {
            cipher_type = Some(Cipher::aes_256_ofb());
            cipher_name = "AES-256-OFB";
        } else if (self.cipher == VTUN_ENC_AES256CFB) {
            cipher_type = Some(Cipher::aes_256_cfb128());
            cipher_name = "AES-256-CFB";
        } else if (self.cipher == VTUN_ENC_AES256CBC) {
            cipher_type = Some(Cipher::aes_256_cbc());
            cipher_name = "AES-256-CBC";
        } else if (self.cipher == VTUN_ENC_AES128OFB) {
            cipher_type = Some(Cipher::aes_128_ofb());
            cipher_name = "AES-128-OFB";
        } else if (self.cipher == VTUN_ENC_AES128CFB) {
            cipher_type = Some(Cipher::aes_128_cfb128());
            cipher_name = "AES-128-CFB";
        } else if (self.cipher == VTUN_ENC_AES128CBC) {
            cipher_type = Some(Cipher::aes_128_cbc());
            cipher_name = "AES-128-CBC";
        } else if (self.cipher == VTUN_ENC_BF256OFB) {
            var_key = true;
            cipher_type = Some(Cipher::bf_ofb());
            cipher_name = "Blowfish-256-OFB";
        } else if (self.cipher == VTUN_ENC_BF256CFB) {
            var_key = true;
            cipher_type = Some(Cipher::bf_cfb64());
            cipher_name = "Blowfish-256-CFB";
        } else if (self.cipher == VTUN_ENC_BF256CBC) {
            var_key = true;
            cipher_type = Some(Cipher::bf_cbc());
            cipher_name = "Blowfish-256-CBC";
        } else if (self.cipher == VTUN_ENC_BF128OFB) {
            var_key = true;
            cipher_type = Some(Cipher::bf_ofb());
            cipher_name = "Blowfish-128-OFB";
        } else if (self.cipher == VTUN_ENC_BF128CFB) {
            var_key = true;
            cipher_type = Some(Cipher::bf_cfb64());
            cipher_name = "Blowfish-128-CFB";
        } else if (self.cipher == VTUN_ENC_BF128CBC) {
            var_key = true;
            cipher_type = Some(Cipher::bf_cbc());
            cipher_name = "Blowfish-128-CBC";
        } else {
            /* if we're here, something weird's going on */
            return false;
        }

        if (var_key) {
            self.ctx_enc.set_key_length(self.keysize as usize);
        }
        self.ctx_enc.encrypt_init(cipher_type, Some(&*self.pkey), Some(iv)).unwrap();
        self.ctx_enc.set_padding(false);
        if (self.enc_init_first_time)
        {
            let tmpstr = format!("{} encryption initialized", cipher_name);
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, tmpstr.as_ptr() as *mut libc::c_char); }
            self.enc_init_first_time = false;
        }
        return true;
    }

    fn cipher_dec_init(&mut self, iv: &[u8]) -> bool
    {
        let mut var_key: bool = false;
        let mut cipher_type: Option<&CipherRef> = None;
        let mut cipher_name = "";

        if (self.cipher == VTUN_ENC_AES256OFB) {
            cipher_type = Some(Cipher::aes_256_ofb());
            cipher_name = "AES-256-OFB";
        } else if (self.cipher == VTUN_ENC_AES256CFB) {
            cipher_type = Some(Cipher::aes_256_cfb128());
            cipher_name = "AES-256-CFB";
        } else if (self.cipher == VTUN_ENC_AES256CBC) {
            cipher_type = Some(Cipher::aes_256_cbc());
            cipher_name = "AES-256-CBC";
        } else if (self.cipher == VTUN_ENC_AES128OFB) {
            cipher_type = Some(Cipher::aes_128_ofb());
            cipher_name = "AES-128-OFB";
        } else if (self.cipher == VTUN_ENC_AES128CFB) {
            cipher_type = Some(Cipher::aes_128_cfb128());
            cipher_name = "AES-128-CFB";
        } else if (self.cipher == VTUN_ENC_AES128CBC) {
            cipher_type = Some(Cipher::aes_128_cbc());
            cipher_name = "AES-128-CBC";
        } else if (self.cipher == VTUN_ENC_BF256OFB) {
            var_key = true;
            cipher_type = Some(Cipher::bf_ofb());
            cipher_name = "Blowfish-256-OFB";
        } else if (self.cipher == VTUN_ENC_BF256CFB) {
            var_key = true;
            cipher_type = Some(Cipher::bf_cfb64());
            cipher_name = "Blowfish-256-CFB";
        } else if (self.cipher == VTUN_ENC_BF256CBC) {
            var_key = true;
            cipher_type = Some(Cipher::bf_cbc());
            cipher_name = "Blowfish-256-CBC";
        } else if (self.cipher == VTUN_ENC_BF128OFB) {
            var_key = true;
            cipher_type = Some(Cipher::bf_ofb());
            cipher_name = "Blowfish-128-OFB";
        } else if (self.cipher == VTUN_ENC_BF128CFB) {
            var_key = true;
            cipher_type = Some(Cipher::bf_cfb64());
            cipher_name = "Blowfish-128-CFB";
        } else if (self.cipher == VTUN_ENC_BF128CBC) {
            var_key = true;
            cipher_type = Some(Cipher::bf_cbc());
            cipher_name = "Blowfish-128-CBC";
        } else {
            /* if we're here, something weird's going on */
            return false;
        }

        if (var_key) {
            self.ctx_dec.set_key_length(self.keysize as usize);
        }
        self.ctx_dec.decrypt_init(cipher_type, Some(&*self.pkey), Some(iv)).unwrap();
        self.ctx_dec.set_padding(false);
        if (self.dec_init_first_time)
        {
            let tmpstr = format!("{} decryption initialized", cipher_name);
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, tmpstr.as_ptr() as *mut libc::c_char); }
            self.dec_init_first_time = false;
        }
        return true;
    }

    pub fn send_msg(&mut self) -> Option<Vec<u8>> {
        if (matches!(self.cipher_enc_state, CipherState::CipherInit)) {
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
                if (!self.cipher_enc_init(&*iv)) {
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
                return Some(outbuf);
            }
        } else /*default or self.cipher_enc_state == CipherState::CipherCode)*/ {
            return None;
        }
    }

    /* Send In-Band Message */
    fn send_ib_mesg(&mut self) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::new();
        /* To simplify matters, I assume that blocksize
              will not be less than 8 bytes */
        if (matches!(self.cipher_enc_state, CipherState::CipherSequence)) {
            output.reserve(self.blocksize as usize);
            output.push(b's');
            output.push(b'e');
            output.push(b'q');
            output.push(b'#');
            output.push(((self.sequence_num >> 24) & 0xFF) as u8);
            output.push(((self.sequence_num >> 16) & 0xFF) as u8);
            output.push(((self.sequence_num >> 8) & 0xFF) as u8);
            output.push((self.sequence_num & 0xFF) as u8);
            if (output.len() < self.blocksize as usize) {
                output.resize(self.blocksize as usize, 0u8);
            }
        } else if (matches!(self.cipher_enc_state, CipherState::CipherReqInit)) {
            output.reserve(self.blocksize as usize);
            output.push(b'r');
            output.push(b's');
            output.push(b'y');
            output.push(b'n');
            output.push(((self.sequence_num >> 24) & 0xFF) as u8);
            output.push(((self.sequence_num >> 16) & 0xFF) as u8);
            output.push(((self.sequence_num >> 8) & 0xFF) as u8);
            output.push((self.sequence_num & 0xFF) as u8);
            if (output.len() < self.blocksize as usize) {
                output.resize(self.blocksize as usize, 0u8);
            }
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "Requesting remote encryptor re-init".as_ptr() as *mut libc::c_char); }
            self.cipher_enc_state = CipherState::CipherSequence;
            self.send_a_packet = true;
        }
        return output;
    }

    pub fn encrypt(&mut self, buf: &mut[u8]) -> Option<Vec<u8>> {
        let mut outbuf: Vec<u8> = Vec::new();

        let mut sendbuf = self.send_msg();

        let mut ib = self.send_ib_mesg();
        {
            let mut expectedlen = ib.len() + buf.len();
            let p = (expectedlen & ((self.blocksize-1) as usize));
            expectedlen += (self.blocksize as usize) - p;
            expectedlen += self.blocksize as usize;
            outbuf.reserve(expectedlen);
        }
        outbuf.append(& mut ib);
        {
            let prelen = outbuf.len();
            outbuf.resize(prelen + buf.len(), 0u8);
            for i in 0..buf.len() {
                outbuf[prelen + i] = buf[i];
            }
        }
        /* ( len % blocksize ) */
        let p = (outbuf.len() & ((self.blocksize-1) as usize));
        let pad = (self.blocksize as usize) - p;

        outbuf.resize(outbuf.len() + pad, (pad & 0xFF) as u8);
        if (pad == (self.blocksize as usize)) {
            let mut rand_bytes: Vec<u8> = Vec::new();
            rand_bytes.resize((self.blocksize - 1) as usize, 0u8);
            openssl::rand::rand_bytes(&mut rand_bytes).unwrap();
            for i in 0..(self.blocksize - 1) {
                let outbuflen = outbuf.len();
                outbuf[outbuflen - (self.blocksize as usize) + (i as usize)] = rand_bytes[i as usize];
            }
        }
        {
            let outbuflen = outbuf.len();
            outbuf.resize(outbuflen + (self.blocksize as usize), 0u8);
            match self.ctx_enc.cipher_update_inplace(&mut *outbuf, outbuflen) {
                Ok(rlen) => { outbuf.resize(rlen, 0u8); },
                Err(_) => return None
            }
        }

        self.sequence_num += 1;

        match sendbuf {
            Some(mut sendbuf) => {
                let mut finalbuf = Vec::new();
                finalbuf.reserve(LINKFD_FRAME_RESERV + sendbuf.len() + outbuf.len() + LINKFD_FRAME_APPEND);
                finalbuf.resize(LINKFD_FRAME_RESERV, 0u8);
                finalbuf.append(&mut sendbuf);
                finalbuf.append(&mut outbuf);
                finalbuf.resize(finalbuf.len() + LINKFD_FRAME_APPEND, 0u8);
                return Some(finalbuf);
            }
            None => {
                let mut prefixer: Vec<u8> = Vec::new();
                prefixer.reserve(LINKFD_FRAME_RESERV + outbuf.len() + LINKFD_FRAME_APPEND);
                prefixer.resize(LINKFD_FRAME_RESERV, 0u8);
                prefixer.append(&mut outbuf);
                prefixer.resize(prefixer.len() + LINKFD_FRAME_APPEND, 0u8);
                return Some(prefixer);
            }
        }
    }

    fn recv_msg(&mut self, buf: &[u8]) -> Option<Vec<u8>>
    {
        let mut iv: Vec<u8> = Vec::new();

        if (matches!(self.cipher_dec_state, CipherState::CipherInit))
        {
            if (buf.len() < ((self.blocksize as usize) * 2)) {
                return None;
            }
            let mut outp: Vec<u8> = Vec::new();
            outp.resize((self.blocksize as usize) * 3, 0u8);
            match self.ctx_dec_ecb.cipher_update(&buf[..(self.blocksize as usize * 2)], Some(&mut *outp)) {
                Ok(rlen) => { outp.resize(rlen, 0u8); },
                Err(_) => return None
            };
            if (outp[0] == b'i' && outp[1] == b'v' && outp[2] == b'e' && outp[3] == b'c') {
                iv.resize(self.blocksize as usize, 0u8);
                for i in 0..self.blocksize {
                    iv[i as usize] = outp[i as usize + 4];
                }
                if (!self.cipher_dec_init(&*iv)) {
                    return None;
                }
                self.cipher_dec_state = CipherState::CipherSequence;
                self.gibberish = 0;
                self.gib_time_start = 0;
                let mut remainingbuf: Vec<u8> = Vec::new();
                remainingbuf.resize(buf.len() - ((self.blocksize as usize) * 2), 0u8);
                for i in 0..(buf.len() - ((self.blocksize as usize) * 2)) {
                    remainingbuf[i as usize] = buf[i as usize + ((self.blocksize as usize) * 2)];
                }
                return Some(remainingbuf);
            } else {
                self.gibberish += 1;
                let mut gibberish_diff_time = 0;
                if (self.gibberish == 1) {
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
                if (self.gibberish == MIN_GIBBERISH)
                {
                    self.cipher_enc_state = CipherState::CipherReqInit;
                    self.send_a_packet = true;
                    unsafe {
                        lfd_mod::vtun_syslog(lfd_mod::LOG_INFO,
                                             "Min. gibberish threshold reached".as_ptr() as *mut libc::c_char);
                    }
                }
                if (self.gibberish >= MAX_GIBBERISH || gibberish_diff_time >= MAX_GIBBERISH_TIME)
                {
                    self.gibberish = 0;
                    self.gib_time_start = 0;
                    self.send_a_packet = true;

                    unsafe {
                        lfd_mod::vtun_syslog(lfd_mod::LOG_INFO,
                                             "Max. gibberish threshold reached".as_ptr() as *mut libc::c_char);
                    }
                    if (matches!(self.cipher_enc_state, CipherState::CipherInit))
                    {
                        self.cipher_enc_state = CipherState::CipherInit;
                        self.ctx_enc = openssl::cipher_ctx::CipherCtx::new().unwrap();
                        unsafe {
                            lfd_mod::vtun_syslog(lfd_mod::LOG_INFO,
                                                 "Forcing local encryptor re-init".as_ptr() as *mut libc::c_char);
                        }
                    }
                }
            }
        }
        let mut outbuf = Vec::new();
        outbuf.reserve(buf.len() + (self.blocksize as usize));
        outbuf.resize(buf.len(), 0u8);
        for i in 0..buf.len() {
            outbuf[i as usize] = buf[i as usize];
        }
        return Some(outbuf);
    }
    fn recv_ib_mesg(&mut self, buf: Vec<u8>) -> Option<Vec<u8>>
    {
        if (matches!(self.cipher_dec_state, CipherState::CipherSequence))
        {
            if (buf.len() < self.blocksize as usize) {
                return None;
            }
            /* To simplify matters, I assume that blocksize
               will not be less than 8 bytes */
            if (buf[0] == b's' && buf[1] == b'e' && buf[2] == b'q' && buf[3] == b'#')
            {
            }
            else if (buf[0] == b'r' && buf[1] == b's' && buf[2] == b'y' && buf[3] == b'n')
            {
                if (!matches!(self.cipher_enc_state, CipherState::CipherInit))
                {
                    self.cipher_enc_state = CipherState::CipherInit;
                    self.ctx_enc = openssl::cipher_ctx::CipherCtx::new().unwrap();
                }
                unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "Remote requests encryptor re-init".as_ptr() as *mut libc::c_char); }
            }
            else
            {
                if (!matches!(self.cipher_dec_state, CipherState::CipherInit) &&
                    !matches!(self.cipher_enc_state, CipherState::CipherReqInit) &&
                    !matches!(self.cipher_enc_state, CipherState::CipherInit))
                {
                    self.ctx_dec = CipherCtx::new().unwrap();
                    self.cipher_dec_state = CipherState::CipherInit;
                    self.cipher_enc_state = CipherState::CipherReqInit;
                }
                unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "Local decryptor out of sync".as_ptr() as *mut libc::c_char); }

                let vec: Vec<u8> = Vec::new();
                return Some(vec);
            }
            let mut outbuf: Vec<u8> = Vec::new();
            outbuf.resize(buf.len() - (self.blocksize as usize), 0u8);
            for i in 0..(buf.len() - (self.blocksize as usize)) {
                outbuf[i as usize] = buf[i as usize + (self.blocksize as usize)];
            }
            return Some(outbuf);
        }
        return Some(buf);
    }

    pub fn decrypt(&mut self, buf: &mut[u8]) -> Option<Vec<u8>> {
        let mut msg = match self.recv_msg(buf) {
            Some(msgbuf) => msgbuf,
            None => return None
        };

        let msglen = msg.len();
        msg.resize(msglen + (self.blocksize as usize), 0u8);
        match self.ctx_dec.cipher_update_inplace(&mut msg, msglen) {
            Ok(outlen) => {msg.resize(outlen, 0u8)},
            Err(_) => return None
        };

        let mut ib = match self.recv_ib_mesg(msg) {
            Some(ibmsg ) => ibmsg,
            None => return None
        };

        let iblen = ib.len();
        let pad = ib[iblen - 1];
        if (pad < 1 || (pad as u32) > self.blocksize) {
            unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "decrypt_buf: bad pad length".as_ptr() as *mut libc::c_char); }
            return None;
        }
        ib.resize(iblen - pad as usize, 0u8);
        let mut prefixer: Vec<u8> = Vec::new();
        prefixer.reserve(LINKFD_FRAME_RESERV + ib.len() + LINKFD_FRAME_APPEND);
        prefixer.resize(LINKFD_FRAME_RESERV, 0u8);
        prefixer.append(&mut ib);
        prefixer.resize(prefixer.len() + LINKFD_FRAME_APPEND, 0u8);
        return Some(prefixer);
    }
}

extern "C" {
    static mut send_a_packet: libc::c_int;
}
#[no_mangle]
pub extern "C" fn alloc_encrypt(host: *mut VtunHost) -> libc::c_int
{
    unsafe {
        LFD_ENCRYPT = LfdEncrypt::alloc(host);
        if (LFD_ENCRYPT.is_some()) {
            return 0;
        }
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn free_encrypt() -> libc::c_int {
    unsafe { LFD_ENCRYPT = None; }
    return 0;
}

#[no_mangle]
pub extern "C" fn encrypt_buf(len: libc::c_int, in_ptr: *mut libc::c_char, out_ptr: *mut *mut libc::c_char) -> libc::c_int {
    if in_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }

    let slice = unsafe {
        std::slice::from_raw_parts_mut(in_ptr as *mut u8, len as usize)
    };

    let output = unsafe { match &mut LFD_ENCRYPT {
        Some(ref mut lfdEncrypt) => lfdEncrypt.encrypt(slice),
        None => return -1
    } };

    unsafe {
        match &mut LFD_ENCRYPT {
            Some(ref mut lfdEncrypt) => {
                if (lfdEncrypt.send_a_packet) {
                    send_a_packet = 1;
                    lfdEncrypt.send_a_packet = false;
                }
                match output {
                    Some(outp) => {
                        lfdEncrypt.returned_enc_buffer = outp;
                        let len = lfdEncrypt.returned_enc_buffer.len() - LINKFD_FRAME_RESERV - LINKFD_FRAME_APPEND;
                        *out_ptr = *&lfdEncrypt.returned_enc_buffer.as_ptr() as *mut libc::c_char;
                        *out_ptr = (*out_ptr).add(LINKFD_FRAME_RESERV);
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
pub extern "C" fn decrypt_buf(len: libc::c_int, in_ptr: *mut libc::c_char, out_ptr: *mut *mut libc::c_char) -> libc::c_int {
    if in_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }

    let slice = unsafe {
        std::slice::from_raw_parts_mut(in_ptr as *mut u8, len as usize)
    };

    let output = unsafe { match &mut LFD_ENCRYPT {
        Some(ref mut lfdEncrypt) => lfdEncrypt.decrypt(slice),
        None => return -1
    } };

    unsafe {
        match &mut LFD_ENCRYPT {
            Some(ref mut lfdEncrypt) => {
                if (lfdEncrypt.send_a_packet) {
                    send_a_packet = 1;
                    lfdEncrypt.send_a_packet = false;
                }
                match output {
                    Some(outp) => {
                        lfdEncrypt.returned_dec_buffer = outp;
                        let len = lfdEncrypt.returned_dec_buffer.len() - LINKFD_FRAME_RESERV - LINKFD_FRAME_APPEND;
                        *out_ptr = *&lfdEncrypt.returned_dec_buffer.as_ptr() as *mut libc::c_char;
                        *out_ptr = (*out_ptr).add(LINKFD_FRAME_RESERV);
                        return len as libc::c_int;
                    },
                    None => return -1
                }
            },
            None => return -1
        }
    }
}

