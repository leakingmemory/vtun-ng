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
use aes::Aes256;
use cipher::{Block, BlockDecryptMut, BlockEncryptMut, KeyInit};
use ecb::{Decryptor, Encryptor};
use sha2::Digest;

pub fn encrypt_challenge(buf: &mut [u8], passwd: &str) -> Result<(),()>{
    let key = sha2::Sha256::digest(passwd.as_bytes());
    match Encryptor::<Aes256>::new_from_slice(key.as_slice()) {
        Ok(mut encryptor) => {
            encryptor.encrypt_block_mut(Block::<Encryptor<Aes256>>::from_mut_slice(buf));
            Ok(())
        },
        Err(_) => Err(())
    }
}

pub fn decrypt_challenge(buf: &mut [u8], passwd: &str) -> Result<(),()>{
    let key = sha2::Sha256::digest(passwd.as_bytes());
    match Decryptor::<Aes256>::new_from_slice(key.as_slice()) {
        Ok(mut encryptor) => {
            encryptor.decrypt_block_mut(Block::<Encryptor<Aes256>>::from_mut_slice(buf));
            Ok(())
        },
        Err(_) => Err(())
    }
}

pub fn mix_in_bytes(buf: &mut [u8], data: &[u8]) {
    let mut digester = sha2::Sha256::new();
    digester.update(buf as &[u8]);
    digester.update(data);
    let hash = digester.finalize();
    let mut len = hash.len();
    if len > buf.len() {
        len = buf.len();
    }
    for i in 0..len {
        buf[i] = hash[i];
    }
}
