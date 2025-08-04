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
use cipher::{Block, BlockDecryptMut, BlockEncryptMut, KeyInit};
use rand::RngCore;
use rand::rngs::ThreadRng;
use crate::syslog::vtun_syslog;
use crate::{lfd_mod};
use crate::linkfd::{LfdMod, LfdModFactory};
use crate::vtun_host::VtunHost;

struct LfdGenericEncrypt<Encryptor,Decryptor,const KEY_SIZE: usize,const BLOCK_SIZE: usize> {
    random: ThreadRng,
    encryptor: Encryptor,
    decryptor: Decryptor
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


impl<Encryptor: KeyInit,Decryptor: KeyInit,const KEY_SIZE: usize,const BLOCK_SIZE: usize> LfdGenericEncrypt<Encryptor,Decryptor,KEY_SIZE,BLOCK_SIZE>
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
        let lfd_generic_encryptor = Self {
            random: rand::rng(),
            encryptor: Encryptor::new_from_slice(&key).unwrap(),
            decryptor: Decryptor::new_from_slice(&key).unwrap()
        };
        let msg = format!("Generic encryptor for {} initialized", type_name::<Encryptor>());
        vtun_syslog(lfd_mod::LOG_INFO, &msg);
        Ok(lfd_generic_encryptor)
    }
}

impl<Encryptor: BlockEncryptMut,Decryptor: BlockDecryptMut,const KEY_SIZE: usize,const BLOCK_SIZE: usize> LfdMod for LfdGenericEncrypt<Encryptor,Decryptor,KEY_SIZE,BLOCK_SIZE>
/*where -- when rust gets support
    Assert<{KEY_SIZE == 16 || KEY_SIZE == 32}>: IsTrue,
    Assert<{BLOCK_SIZE >= 8 && BLOCK_SIZE < 256 && (1 << log2_for_powers_of_two(BLOCK_SIZE)) == BLOCK_SIZE}>: IsTrue*/
{
    fn encode(&mut self, buf: &mut Vec<u8>) -> bool {
        let pad = BLOCK_SIZE - (buf.len() & (BLOCK_SIZE - 1));
        let len = buf.len() + pad;
        buf.resize(len, 0);
        self.random.fill_bytes(&mut buf[len - pad..len - 1]);
        buf[len - 1] = pad as u8;
        for i in 0..len/BLOCK_SIZE {
            let mut data: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                data[j] = buf[i*BLOCK_SIZE + j];
            }
            let block = Block::<Encryptor>::from_mut_slice(&mut data);
            self.encryptor.encrypt_block_mut(block);
            for j in 0..BLOCK_SIZE {
                buf[i*BLOCK_SIZE + j] = block[j];
            }
        }
        true
    }
    fn decode(&mut self, buf: &mut Vec<u8>) -> bool {
        for i in 0..buf.len()/BLOCK_SIZE {
            let block = Block::<Decryptor>::from_mut_slice(&mut buf[i*BLOCK_SIZE..(i+1)*BLOCK_SIZE]);
            self.decryptor.decrypt_block_mut(block);
        }
        let mut pad = buf[buf.len() - 1] as usize;
        if pad > buf.len() {
            pad = buf.len();
        }
        buf.truncate(buf.len() - pad);
        true
    }
}

pub struct LfdGenericEncryptFactory<Encryptor: KeyInit, Decryptor: KeyInit, const KEY_SIZE: usize, const BLOCK_SIZE: usize> {
    phantom_encryptor: std::marker::PhantomData<Encryptor>,
    phantom_decryptor: std::marker::PhantomData<Decryptor>
}

impl<Encryptor: KeyInit, Decryptor: KeyInit, const KEY_SIZE: usize, const BLOCK_SIZE: usize> LfdGenericEncryptFactory<Encryptor,Decryptor,KEY_SIZE,BLOCK_SIZE> {
    pub(crate) fn new() -> Self {
        Self {
            phantom_encryptor: std::marker::PhantomData,
            phantom_decryptor: std::marker::PhantomData
        }
    }
}

impl<Encryptor: KeyInit + BlockEncryptMut + 'static, Decryptor: KeyInit + BlockDecryptMut + 'static, const KEY_SIZE: usize, const BLOCK_SIZE: usize> LfdModFactory for LfdGenericEncryptFactory<Encryptor,Decryptor,KEY_SIZE,BLOCK_SIZE> {
    fn create(&self, host: &mut VtunHost) -> Result<Box<dyn LfdMod>,i32> {
        match LfdGenericEncrypt::<Encryptor, Decryptor, KEY_SIZE, BLOCK_SIZE>::new(host) {
            Ok(lfd) => Ok(Box::new(lfd)),
            Err(code) => {
                let msg = format!("Failed to create generic encryptor for {} (code: {})", type_name::<Encryptor>(), code);
                vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                Err(0)
            }
        }
    }
}
