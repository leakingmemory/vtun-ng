/*
    Copyright (C) 2025 Jan-Espen Oversand <sigsegv@radiotube.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 */

use std::any::type_name;
use std::time::{SystemTime, UNIX_EPOCH};
use cipher::{Block, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use rand::RngCore;
use rand::rngs::ThreadRng;
use crate::syslog::vtun_syslog;
use crate::{lfd_mod};
use crate::linkfd::{LfdMod, LfdModFactory};
use crate::vtun_host::VtunHost;

const MAX_GIBBERISH: u32	= 10;
const MIN_GIBBERISH: u32   = 1;
const MAX_GIBBERISH_TIME: u64   = 2;

struct LfdIvEncrypt<InitEncryptor,InitDecryptor,Encryptor,Decryptor,const KEY_SIZE: usize,const BLOCK_SIZE: usize> {
    random: ThreadRng,
    key: [u8; KEY_SIZE],
    encryptor: Option<Encryptor>,
    decryptor: Option<Decryptor>,
    seq: u32,
    gibberish_counter: u32,
    gibberish_time: u64,
    request_reinit: bool,
    request_send: bool,
    _phantom_init_encryptor: std::marker::PhantomData<InitEncryptor>,
    _phantom_init_decryptor: std::marker::PhantomData<InitDecryptor>,
}

/* when rust gets support for costant expressions in where clauses
fn log2_for_powers_of_two(n: usize) -> usize {
    let mut n = n;
    let mut r = 0;
    while n > 0 {
        n >>= 1;
        r += 1;
    }
    r
}
 */


enum ControlFlowDecision {
    Continue,
    Ignore
}

impl<InitEncryptor: KeyInit + BlockEncryptMut,InitDecryptor: KeyInit + cipher::BlockSizeUser + BlockDecryptMut,Encryptor: KeyIvInit,Decryptor: KeyIvInit,const KEY_SIZE: usize,const BLOCK_SIZE: usize> LfdIvEncrypt<InitEncryptor,InitDecryptor,Encryptor,Decryptor,KEY_SIZE,BLOCK_SIZE>
/*where -- when rust gets support
    Assert<{KEY_SIZE == 16 || KEY_SIZE == 32}>: IsTrue,
    Assert<{BLOCK_SIZE >= 8 && (1 << log2_for_powers_of_two(BLOCK_SIZE)) == BLOCK_SIZE}>: IsTrue*/
{
    fn prep_key(passwd: &str) -> [u8; KEY_SIZE] {
        if KEY_SIZE == 32 {
            let md5_1 = md5::compute(passwd[0..passwd.len()/2].as_bytes());
            let md5_2 = md5::compute(passwd[passwd.len()/2..].as_bytes());
            let mut key = [0u8; KEY_SIZE];
            for i in 0..md5_1.len() {
                key[i] = md5_1[i];
                key[i+16] = md5_2[i];
            }
            key
        } else {
            let md5 = md5::compute(passwd.as_bytes());
            let mut key = [0u8; KEY_SIZE];
            for i in 0..KEY_SIZE {
                key[i] = md5[i];
            }
            key
        }
    }
    pub fn new(host: &VtunHost) -> Result<Self,i32> {
        let key = match host.passwd {
            Some(ref passwd) => Self::prep_key(passwd.as_str()),
            None => return Err(0)
        };
        let msg = format!("Encryptor for {} starting", type_name::<Encryptor>());
        vtun_syslog(lfd_mod::LOG_INFO, &msg);
        let mut obj = Self {
            random: rand::rng(),
            key,
            encryptor: None,
            decryptor: None,
            gibberish_counter: 0,
            gibberish_time: 0,
            request_reinit: false,
            request_send: false,
            _phantom_init_encryptor: std::marker::PhantomData,
            _phantom_init_decryptor: std::marker::PhantomData,
            seq: 0
        };
        {
            let mut seq_bytes = [0u8; 4];
            obj.random.fill_bytes(&mut seq_bytes);
            obj.seq = u32::from_be_bytes(seq_bytes);
        }
        Ok(obj)
    }

    fn recv_gibberish_msg(&mut self, _msg: &mut [u8]) -> Result<ControlFlowDecision,()> {
        let first_gibberish = self.gibberish_counter == 0;
        self.gibberish_counter += 1;
        let gibberish_elapsed = if first_gibberish {
            self.gibberish_time = match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(duration) => duration.as_secs(),
                Err(_) => {
                    vtun_syslog(lfd_mod::LOG_ERR, "SystemTime::now() failed");
                    0
                }
            };
            0
        } else {
            match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(duration) => duration.as_secs() - self.gibberish_time,
                Err(_) => {
                    vtun_syslog(lfd_mod::LOG_ERR, "SystemTime::now() failed");
                    0
                }
            }
        };
        if self.gibberish_counter == MIN_GIBBERISH {
            self.request_reinit = true;
            self.request_send = true;
        }
        if self.gibberish_counter >= MAX_GIBBERISH || gibberish_elapsed >= MAX_GIBBERISH_TIME {
            self.request_reinit = false;
            self.request_send = true;
            vtun_syslog(lfd_mod::LOG_ERR, "Other end is taking too long to respond to reinit request, resetting encoder");
            self.encryptor = None;
        }
        Ok(ControlFlowDecision::Ignore)
    }
    fn recv_ivec_msg(&mut self, msg: &mut [u8]) -> Result<ControlFlowDecision,()> {
        let mut init_decryptor = match InitDecryptor::new_from_slice(&self.key) {
            Ok(decryptor) => decryptor,
            Err(_) => return Err(())
        };
        for i in 0..msg.len()/BLOCK_SIZE {
            let block = Block::<InitDecryptor>::from_mut_slice(&mut msg[i*BLOCK_SIZE..i*BLOCK_SIZE+BLOCK_SIZE]);
            init_decryptor.decrypt_block_mut(block);
        }
        if msg[0] != b'i' || msg[1] != b'v' || msg[2] != b'e' || msg[3] != b'c' {
            return self.recv_gibberish_msg(msg);
        }
        let iv = & msg[4..BLOCK_SIZE+4];
        self.decryptor = Some(match Decryptor::new_from_slices(&self.key, &iv) {
            Ok(decryptor) => decryptor,
            Err(_) => return Err(())
        });
        self.gibberish_counter = 0;
        Ok(ControlFlowDecision::Continue)
    }
    fn ivec_msg(&mut self, msg: &mut [u8]) -> Result<(),()> {
        msg[0] = b'i';
        msg[1] = b'v';
        msg[2] = b'e';
        msg[3] = b'c';
        self.random.fill_bytes(&mut msg[4..BLOCK_SIZE*2]);
        let mut iv = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            iv[i] = msg[i+4];
        }
        self.encryptor = Some(match Encryptor::new_from_slices(&self.key, &iv) {
            Ok(encryptor) => encryptor,
            Err(_) => return Err(())
        });
        let mut init_encryptor = match InitEncryptor::new_from_slice(&self.key) {
            Ok(encryptor) => encryptor,
            Err(_) => return Err(())
        };
        for i in 0..msg.len()/BLOCK_SIZE {
            let mut data: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                data[j] = msg[i*BLOCK_SIZE+j];
            }
            let block = Block::<InitEncryptor>::from_mut_slice(&mut data);
            init_encryptor.encrypt_block_mut(block);
            for j in 0..BLOCK_SIZE {
                msg[i*BLOCK_SIZE+j] = block[j];
            }
        }
        Ok(())
    }
    fn recv_seq_msg(&mut self, blk: &mut [u8]) -> Result<(),()> {
        if blk[0] != b's' || blk[1] != b'e' || blk[2] != b'q' || blk[3] != b'#' {
            if blk[0] != b'r' || blk[1] != b's' || blk[2] != b'y' || blk[3] != b'n' {
                return Err(());
            }
            vtun_syslog(lfd_mod::LOG_INFO, "Reinit request received");
            self.encryptor = None;
            self.request_send = true;
            self.request_reinit = false;
        }
        Ok(())
    }
    fn seq_msg(&mut self, blk: &mut [u8]) {
        if self.request_reinit {
            blk[0] = b'r';
            blk[1] = b's';
            blk[2] = b'y';
            blk[3] = b'n';
            self.request_reinit = false;
        } else {
            blk[0] = b's';
            blk[1] = b'e';
            blk[2] = b'q';
            blk[3] = b'#';
        }
        blk[4] = (self.seq >> 24) as u8;
        blk[5] = ((self.seq >> 16) & 0xff) as u8;
        blk[6] = ((self.seq >> 8) & 0xff) as u8;
        blk[7] = (self.seq & 0xff) as u8;
        if BLOCK_SIZE > 8 {
            self.random.fill_bytes(&mut blk[8..BLOCK_SIZE]);
        }
    }
}

fn extend_below(buf: &mut Vec<u8>, ext_size: usize) {
    let len = buf.len();
    buf.resize(len + ext_size, 0u8);
    for i in 1..len+1 {
        buf[len + ext_size - i] = buf[len - i];
    }
    for i in 0..ext_size {
        buf[i] = 0;
    }
}

fn remove_prefix(buf: &mut Vec<u8>, prefix_size: usize) {
    let len = buf.len();
    if prefix_size > len {
        buf.truncate(0);
        return;
    }
    for i in prefix_size .. len {
        buf[i-prefix_size] = buf[i];
    }
    buf.truncate(len - prefix_size);
}

impl<InitEncryptor: BlockEncryptMut+KeyInit,InitDecryptor: BlockDecryptMut+KeyInit,Encryptor: BlockEncryptMut+KeyIvInit,Decryptor: BlockDecryptMut+KeyIvInit,const KEY_SIZE: usize,const BLOCK_SIZE: usize> LfdMod for LfdIvEncrypt<InitEncryptor,InitDecryptor,Encryptor,Decryptor,KEY_SIZE,BLOCK_SIZE>
/*where -- when rust gets support
    Assert<{KEY_SIZE == 16 || KEY_SIZE == 32}>: IsTrue,
    Assert<{BLOCK_SIZE >= 8 && BLOCK_SIZE < 256 && (1 << log2_for_powers_of_two(BLOCK_SIZE)) == BLOCK_SIZE}>: IsTrue*/
{
    fn encode(&mut self, buf: &mut Vec<u8>) -> Result<(),()> {
        self.request_send = false;
        let pad = BLOCK_SIZE - (buf.len() & (BLOCK_SIZE - 1));
        let mut len = buf.len() + pad;
        let mut base = 0;
        buf.resize(len, 0);
        self.random.fill_bytes(&mut buf[len - pad..len - 1]);
        buf[len - 1] = pad as u8;
        if self.encryptor.is_none() {
            extend_below(buf, BLOCK_SIZE * 3);
            base = BLOCK_SIZE * 2;
            match self.ivec_msg(&mut buf[0..base]) {
                Ok(_) => {},
                Err(_) => return Err(())
            };
            self.seq_msg(&mut buf[base..base+BLOCK_SIZE]);
            len = len + BLOCK_SIZE;
        } else {
            extend_below(buf, BLOCK_SIZE);
            self.seq_msg(&mut buf[base..base+BLOCK_SIZE]);
            len = len + BLOCK_SIZE;
        }
        self.seq += 1;
        for i in base/BLOCK_SIZE..(base+len)/BLOCK_SIZE {
            let mut data: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                data[j] = buf[i*BLOCK_SIZE + j];
            }
            let block = Block::<Encryptor>::from_mut_slice(&mut data);
            match self.encryptor {
                Some(ref mut encryptor) => encryptor.encrypt_block_mut(block),
                None => {
                    buf.clear();
                    return Err(());
                }
            };
            for j in 0..BLOCK_SIZE {
                buf[i*BLOCK_SIZE + j] = block[j];
            }
        }
        Ok(())
    }
    fn decode(&mut self, buf: &mut Vec<u8>) -> Result<(),()> {
        let init = self.decryptor.is_none();
        if init {
            match self.recv_ivec_msg(&mut buf[0..BLOCK_SIZE*2]) {
                Ok(decision) => {
                    match decision {
                        ControlFlowDecision::Continue => {},
                        ControlFlowDecision::Ignore => {
                            return Ok(());
                        }
                    }
                },
                Err(_) => {
                    vtun_syslog(lfd_mod::LOG_ERR, "Decrypting init blocks failed");
                    return Err(());
                }
            };
            remove_prefix(buf, BLOCK_SIZE * 2);
        }
        let len = buf.len();
        for i in 0..len/BLOCK_SIZE {
            let block = Block::<Decryptor>::from_mut_slice(&mut buf[i*BLOCK_SIZE..(i+1)*BLOCK_SIZE]);
            match self.decryptor {
                Some(ref mut decryptor) => decryptor.decrypt_block_mut(block),
                None => {
                    vtun_syslog(lfd_mod::LOG_ERR, "Decryptor failed");
                    return Err(());
                }
            };
        }
        {
            match self.recv_seq_msg(&mut buf[0 .. BLOCK_SIZE]) {
                Ok(()) => {},
                Err(()) => {
                    vtun_syslog(lfd_mod::LOG_ERR, "Decryptor sequence or reinit prefix decoding failed");
                    return Err(());
                }
            };
            remove_prefix(buf, BLOCK_SIZE);
        }
        let mut pad = buf[buf.len() - 1] as usize;
        if pad > buf.len() {
            pad = buf.len();
        }
        buf.truncate(buf.len() - pad);
        Ok(())
    }

    fn request_send(&mut self) -> bool {
        let req = self.request_send;
        self.request_send = false;
        req
    }
}

pub struct LfdIvEncryptFactory<InitEncryptor: KeyInit,InitDecryptor: KeyInit,Encryptor: KeyIvInit, Decryptor: KeyIvInit, const KEY_SIZE: usize, const BLOCK_SIZE: usize> {
    _phantom_encryptor: std::marker::PhantomData<Encryptor>,
    _phantom_decryptor: std::marker::PhantomData<Decryptor>,
    _phantom_init_encryptor: std::marker::PhantomData<InitEncryptor>,
    _phantom_init_decryptor: std::marker::PhantomData<InitDecryptor>
}

impl<InitEncryptor: KeyInit,InitDecryptor: KeyInit,Encryptor: KeyIvInit, Decryptor: KeyIvInit, const KEY_SIZE: usize, const BLOCK_SIZE: usize> LfdIvEncryptFactory<InitEncryptor,InitDecryptor,Encryptor,Decryptor,KEY_SIZE,BLOCK_SIZE> {
    pub(crate) fn new() -> Self {
        Self {
            _phantom_encryptor: std::marker::PhantomData,
            _phantom_decryptor: std::marker::PhantomData,
            _phantom_init_encryptor: std::marker::PhantomData,
            _phantom_init_decryptor: std::marker::PhantomData
        }
    }
}

impl<InitEncryptor: KeyInit + BlockEncryptMut + 'static, InitDecryptor: KeyInit + BlockDecryptMut + 'static, Encryptor: KeyIvInit + BlockEncryptMut + 'static, Decryptor: KeyIvInit + BlockDecryptMut + 'static, const KEY_SIZE: usize, const BLOCK_SIZE: usize> LfdModFactory for LfdIvEncryptFactory<InitEncryptor,InitDecryptor,Encryptor,Decryptor,KEY_SIZE,BLOCK_SIZE> {
    fn create(&self, host: &mut VtunHost) -> Result<Box<dyn LfdMod>,i32> {
        let lfd = match LfdIvEncrypt::<InitEncryptor, InitDecryptor, Encryptor, Decryptor, KEY_SIZE, BLOCK_SIZE>::new(host) {
            Ok(lfd) => lfd,
            Err(code) => {
                let msg = format!("Failed to create encryptor for {} (code: {})", type_name::<Encryptor>(), code);
                vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                return Err(0);
            }
        };
        Ok(Box::new(lfd))
    }
}
