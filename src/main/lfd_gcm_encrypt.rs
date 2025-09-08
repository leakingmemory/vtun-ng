use aes_gcm::{AeadCore, AeadInPlace, Key, KeySizeUser, Nonce};
use cipher::{Iv, IvSizeUser, KeyInit, KeyIvInit};
use cipher::consts::U16;
use sha2::Digest;
use crate::lfd_iv_encrypt;

pub struct LfdGcmInit<Cipher: KeyInit> {
    cipher: Cipher,
    iv: [u8; 16]
}

impl<Cipher: KeyInit> KeySizeUser for LfdGcmInit<Cipher> { type KeySize = Cipher::KeySize; }

impl<Cipher: KeyInit> IvSizeUser for LfdGcmInit<Cipher> { type IvSize = U16; }

impl<Cipher: KeyInit> KeyIvInit for LfdGcmInit<Cipher> {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        Self {
            cipher: Cipher::new(key),
            iv: iv.as_slice().try_into().unwrap()
        }
    }
}

pub(crate) struct LfdGcmEncrypt<Cipher: KeyInit, const BLOCK_SIZE: usize> {
    init: LfdGcmInit<Cipher>,
    seq: u64,
    buf: Option<Vec<u8>>
}

pub(crate) struct LfdGcmDecrypt<Cipher: KeyInit, const BLOCK_SIZE: usize> {
    init: LfdGcmInit<Cipher>,
    seq: u64
}

impl<Cipher: KeyInit, const BLOCK_SIZE: usize> KeySizeUser for LfdGcmEncrypt<Cipher, BLOCK_SIZE> { type KeySize = <LfdGcmInit<Cipher> as KeySizeUser>::KeySize; }

impl<Cipher: KeyInit, const BLOCK_SIZE: usize> IvSizeUser for LfdGcmEncrypt<Cipher, BLOCK_SIZE> { type IvSize = <LfdGcmInit<Cipher> as IvSizeUser>::IvSize; }

impl<Cipher: KeyInit, const BLOCK_SIZE: usize> KeyIvInit for LfdGcmEncrypt<Cipher, BLOCK_SIZE> {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        Self {
            init: LfdGcmInit::<Cipher>::new(key, iv),
            seq: 0,
            buf: Some(Vec::new())
        }
    }
}

impl<Cipher: KeyInit, const BLOCK_SIZE: usize> KeySizeUser for LfdGcmDecrypt<Cipher, BLOCK_SIZE> { type KeySize = <LfdGcmInit<Cipher> as KeySizeUser>::KeySize; }

impl<Cipher: KeyInit, const BLOCK_SIZE: usize> IvSizeUser for LfdGcmDecrypt<Cipher, BLOCK_SIZE> { type IvSize = <LfdGcmInit<Cipher> as IvSizeUser>::IvSize; }

impl<Cipher: KeyInit, const BLOCK_SIZE: usize> KeyIvInit for LfdGcmDecrypt<Cipher, BLOCK_SIZE> {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        Self {
            init: LfdGcmInit::<Cipher>::new(key, iv),
            seq: 0
        }
    }
}

impl<Cipher: KeyInit + AeadInPlace + AeadCore, const BLOCK_SIZE: usize> lfd_iv_encrypt::EncryptVec<BLOCK_SIZE> for LfdGcmEncrypt<Cipher,BLOCK_SIZE> {
    fn encrypt_mut(&mut self, data: &mut Vec<u8>, base: usize, len: usize) -> Result<(),()> {
        if base != 0 || len < data.len() {
            let mut buf = self.buf.take().unwrap_or_else(Vec::new);
            buf.resize(len, 0u8);
            for i in 0..len {
                buf[i] = data[base + i];
            }
            match self.encrypt_mut(&mut buf, 0, len) {
                Ok(_) => {},
                Err(_) => return Err(())
            }
            if buf.len() < len {
                /* This is unexpected, it's probably going to be larger (+tag) */
                return Err(());
            }
            if buf.len() > len {
                let diff = buf.len() - len;
                data.resize(data.len() + diff, 0u8);
                if (base + len) < data.len() {
                    let trail = data.len() - base - len;
                    let datalen = data.len();
                    for i in 0..trail {
                        data[datalen - i - 1] = data[base + len + trail - i - 1];
                    }
                }
            }
            for i in 0..buf.len() {
                data[base + i] = buf[i];
            }
            self.buf = Some(buf);
            return Ok(())
        }
        let mut ivdata = [0u8; 32];
        {
            for i in 0..self.init.iv.len() {
                ivdata[i] = self.init.iv[i];
            }
            let seq = self.seq.to_be_bytes();
            for i in 0..seq.len() {
                ivdata[self.init.iv.len() + i] = seq[i];
            }
        }
        if self.seq == u64::MAX {
            /*
             * The cipher becomes significantly less secure if this wraps
             * AES-GCM -> wrap == disaster
             * AES-GCM-SIV -> wrap == not-ideal
             */
            return Err(())
        }
        if data.capacity() < data.len() + 16 {
            data.reserve(data.len() + 16 - data.capacity());
        }
        let digest = sha2::Sha256::digest(ivdata);
        let nonce = Nonce::from_slice(&digest[0..12]);
        match self.init.cipher.encrypt_in_place(&nonce, &[0u8; 0], data) {
            Ok(_) => {},
            Err(_) => return Err(())
        }
        self.seq += 1;
        Ok(())
    }
}

impl<Cipher: KeyInit + AeadInPlace + AeadCore, const BLOCK_SIZE: usize> lfd_iv_encrypt::DecryptVec<BLOCK_SIZE> for LfdGcmDecrypt<Cipher,BLOCK_SIZE> {
    fn decrypt_mut(&mut self, data: &mut Vec<u8>) -> Result<(),()> {
        let mut ivdata = [0u8; 32];
        {
            for i in 0..self.init.iv.len() {
                ivdata[i] = self.init.iv[i];
            }
            let seq = self.seq.to_be_bytes();
            for i in 0..seq.len() {
                ivdata[self.init.iv.len() + i] = seq[i];
            }
        }
        let digest = sha2::Sha256::digest(ivdata);
        let nonce = Nonce::from_slice(&digest[0..12]);
        match self.init.cipher.decrypt_in_place(&nonce, &[0u8; 0], data) {
            Ok(_) => {},
            Err(_) => return Err(())
        }
        self.seq = self.seq.wrapping_add(1);
        Ok(())
    }
}