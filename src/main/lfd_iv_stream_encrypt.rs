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

use cipher::{ArrayLength, Block, BlockCipher, BlockClosure, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, BlockSizeUser, InvalidLength, Iv, IvSizeUser, Key, KeyInit, KeyIvInit, KeySizeUser, StreamCipher};
use cipher::block_padding::{Padding, UnpadError};
use cipher::inout::{InOut, InOutBuf, InOutBufReserved, NotEqualError, PadError};
use crate::lfd_iv_encrypt::LfdIvEncryptFactory;
use crate::linkfd::{LfdMod, LfdModFactory};
use crate::mainvtun::VtunContext;
use crate::vtun_host::VtunHost;

pub(crate) struct FixedSizeForVariableKeySizeWrapper<Cipher, KeySize> {
    cipher: Cipher,
    _phantom_key_size: std::marker::PhantomData<KeySize>
}

impl<Cipher: KeyInit,KeySize: ArrayLength<u8> + 'static> KeySizeUser for FixedSizeForVariableKeySizeWrapper<Cipher,KeySize> {
    type KeySize = KeySize;
}

impl<Cipher: KeyInit,KeySize: ArrayLength<u8> + 'static> KeyInit for FixedSizeForVariableKeySizeWrapper<Cipher,KeySize> {
    fn new(key: &Key<Self>) -> Self {
        Self {
            cipher: match Cipher::new_from_slice(key.as_slice()) {
                Ok(cipher) => cipher,
                Err(err) => panic!("new_from_slice: {:?}", err)
            },
            _phantom_key_size: std::marker::PhantomData
        }
    }
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        Ok(Self {
            cipher: match Cipher::new_from_slice(key) {
                Ok(cipher) => cipher,
                Err(err) => return Err(err)
            },
            _phantom_key_size: std::marker::PhantomData
        })
    }
}

impl<Cipher: BlockSizeUser,KeySize: ArrayLength<u8> + 'static> BlockSizeUser for FixedSizeForVariableKeySizeWrapper<Cipher,KeySize> {
    type BlockSize = Cipher::BlockSize;
}

impl<Cipher: BlockCipher,KeySize: ArrayLength<u8> + 'static> BlockCipher for FixedSizeForVariableKeySizeWrapper<Cipher,KeySize> {
}

impl<Cipher: BlockEncrypt,KeySize: ArrayLength<u8> + 'static> BlockEncrypt for FixedSizeForVariableKeySizeWrapper<Cipher,KeySize> {
    fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize=Self::BlockSize>) {
        self.cipher.encrypt_with_backend(f);
    }

    fn encrypt_block_inout(&self, block: InOut<'_, '_, Block<Self>>) {
        self.cipher.encrypt_block_inout(block);
    }

    fn encrypt_blocks_inout(&self, blocks: InOutBuf<'_, '_, Block<Self>>) {
        self.cipher.encrypt_blocks_inout(blocks);
    }

    fn encrypt_block(&self, block: &mut Block<Self>) {
        self.cipher.encrypt_block(block);
    }

    fn encrypt_block_b2b(&self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        self.cipher.encrypt_block_b2b(in_block, out_block);
    }

    fn encrypt_blocks(&self, blocks: &mut [Block<Self>]) {
        self.cipher.encrypt_blocks(blocks);
    }

    fn encrypt_blocks_b2b(&self, in_blocks: &[Block<Self>], out_blocks: &mut [Block<Self>]) -> Result<(), NotEqualError> {
        self.cipher.encrypt_blocks_b2b(in_blocks, out_blocks)
    }

    fn encrypt_padded_inout<'inp, 'out, P: Padding<Self::BlockSize>>(&self, _data: InOutBufReserved<'inp, 'out, u8>) -> Result<&'out [u8], PadError> {
        todo!()
    }

    fn encrypt_padded<'a, P: Padding<Self::BlockSize>>(&self, _buf: &'a mut [u8], _msg_len: usize) -> Result<&'a [u8], PadError> {
        todo!()
    }

    fn encrypt_padded_b2b<'a, P: Padding<Self::BlockSize>>(&self, _msg: &[u8], _out_buf: &'a mut [u8]) -> Result<&'a [u8], PadError> {
        todo!()
    }
}

struct StreamEncryptorToEncryptorAndDecryptor<StreamEncryptor: KeyIvInit> {
    encryptor: StreamEncryptor
}

impl<StreamEncryptor: KeyIvInit> KeySizeUser for StreamEncryptorToEncryptorAndDecryptor<StreamEncryptor> {
    type KeySize = StreamEncryptor::KeySize;
}

impl<StreamEncryptor: KeyIvInit> IvSizeUser for StreamEncryptorToEncryptorAndDecryptor<StreamEncryptor> {
    type IvSize = StreamEncryptor::IvSize;
}

impl<StreamEncryptor: KeyIvInit> KeyIvInit for StreamEncryptorToEncryptorAndDecryptor<StreamEncryptor> {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        Self {
            encryptor: StreamEncryptor::new(key, iv)
        }
    }

    fn new_from_slices(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        Ok(Self {
            encryptor: match StreamEncryptor::new_from_slices(key, iv) {
                Ok(encryptor) => encryptor,
                Err(err) => return Err(err)
            }
        })
    }
}

impl<StreamEncryptor: KeyIvInit + StreamCipher> BlockSizeUser for StreamEncryptorToEncryptorAndDecryptor<StreamEncryptor> {
    type BlockSize = StreamEncryptor::IvSize;
}

impl<StreamEncryptor: KeyIvInit + StreamCipher> BlockDecryptMut for StreamEncryptorToEncryptorAndDecryptor<StreamEncryptor> {
    fn decrypt_with_backend_mut(&mut self, _f: impl BlockClosure<BlockSize=Self::BlockSize>) {
        todo!()
    }

    fn decrypt_block_inout_mut(&mut self, block: InOut<'_, '_, Block<Self>>) {
        self.encryptor.apply_keystream_inout(block.into_buf());
    }

    fn decrypt_blocks_inout_mut(&mut self, blocks: InOutBuf<'_, '_, Block<Self>>) {
        for block in blocks {
            self.encryptor.apply_keystream_inout(block.into_buf());
        }
    }

    fn decrypt_block_mut(&mut self, block: &mut Block<Self>) {
        self.encryptor.apply_keystream(block)
    }

    fn decrypt_block_b2b_mut(&mut self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        match self.encryptor.apply_keystream_b2b(in_block, out_block) {
            Ok(()) => (),
            Err(err) => panic!("decrypt_block_b2b_mut: {:?}", err)
        }
    }

    fn decrypt_blocks_mut(&mut self, blocks: &mut [Block<Self>]) {
        for block in blocks {
            self.encryptor.apply_keystream(block)
        }
    }

    fn decrypt_blocks_b2b_mut(&mut self, in_blocks: &[Block<Self>], out_blocks: &mut [Block<Self>]) -> Result<(), NotEqualError> {
        let len = in_blocks.len();
        if len != out_blocks.len() {
            return Err(NotEqualError)
        }
        for i in 0..len {
            self.decrypt_block_b2b_mut(&in_blocks[i], &mut out_blocks[i])
        }
        Ok(())
    }

    fn decrypt_padded_inout_mut<'inp, 'out, P: Padding<Self::BlockSize>>(self, _data: InOutBuf<'inp, 'out, u8>) -> Result<&'out [u8], UnpadError> {
        todo!()
    }

    fn decrypt_padded_mut<P: Padding<Self::BlockSize>>(self, _buf: &mut [u8]) -> Result<&[u8], UnpadError> {
        todo!()
    }

    fn decrypt_padded_b2b_mut<'a, P: Padding<Self::BlockSize>>(self, _in_buf: &[u8], _out_buf: &'a mut [u8]) -> Result<&'a [u8], UnpadError> {
        todo!()
    }
}

impl<StreamEncryptor: KeyIvInit + StreamCipher> BlockEncryptMut for StreamEncryptorToEncryptorAndDecryptor<StreamEncryptor> {
    fn encrypt_with_backend_mut(&mut self, _f: impl BlockClosure<BlockSize=Self::BlockSize>) {
        todo!()
    }

    fn encrypt_block_inout_mut(&mut self, block: InOut<'_, '_, Block<Self>>) {
        self.encryptor.apply_keystream_inout(block.into_buf());
    }

    fn encrypt_blocks_inout_mut(&mut self, blocks: InOutBuf<'_, '_, Block<Self>>) {
        for block in blocks {
            self.encryptor.apply_keystream_inout(block.into_buf());
        }
    }

    fn encrypt_block_mut(&mut self, block: &mut Block<Self>) {
        self.encryptor.apply_keystream(block)
    }

    fn encrypt_block_b2b_mut(&mut self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        match self.encryptor.apply_keystream_b2b(in_block, out_block) {
            Ok(()) => (),
            Err(err) => panic!("decrypt_block_b2b_mut: {:?}", err)
        }
    }

    fn encrypt_blocks_mut(&mut self, blocks: &mut [Block<Self>]) {
        for block in blocks {
            self.encryptor.apply_keystream(block)
        }
    }

    fn encrypt_blocks_b2b_mut(&mut self, in_blocks: &[Block<Self>], out_blocks: &mut [Block<Self>]) -> Result<(), NotEqualError> {
        let len = in_blocks.len();
        if len != out_blocks.len() {
            return Err(NotEqualError)
        }
        for i in 0..len {
            self.decrypt_block_b2b_mut(&in_blocks[i], &mut out_blocks[i])
        }
        Ok(())
    }

    fn encrypt_padded_inout_mut<'inp, 'out, P: Padding<Self::BlockSize>>(self, _data: InOutBufReserved<'inp, 'out, u8>) -> Result<&'out [u8], PadError> {
        todo!()
    }

    fn encrypt_padded_mut<P: Padding<Self::BlockSize>>(self, _buf: &mut [u8], _msg_len: usize) -> Result<&[u8], PadError> {
        todo!()
    }

    fn encrypt_padded_b2b_mut<'a, P: Padding<Self::BlockSize>>(self, _msg: &[u8], _out_buf: &'a mut [u8]) -> Result<&'a [u8], PadError> {
        todo!()
    }
}

pub(crate) struct LfdIvStreamEncryptFactory<InitEncryptor: KeyInit,InitDecryptor: KeyInit, StreamEncryptor: KeyIvInit, const KEY_SIZE: usize, const BLOCK_SIZE: usize> {
    _phantom_init_encryptor: std::marker::PhantomData<InitEncryptor>,
    _phantom_init_decryptor: std::marker::PhantomData<InitDecryptor>,
    _phantom_stream_encryptor: std::marker::PhantomData<StreamEncryptor>
}

impl<InitEncryptor: KeyInit,InitDecryptor: KeyInit, StreamEncryptor: KeyIvInit, const KEY_SIZE: usize, const BLOCK_SIZE: usize> LfdIvStreamEncryptFactory<InitEncryptor,InitDecryptor, StreamEncryptor, KEY_SIZE, BLOCK_SIZE> {
    pub(crate) fn new() -> Self {
        Self {
            _phantom_init_encryptor: std::marker::PhantomData,
            _phantom_init_decryptor: std::marker::PhantomData,
            _phantom_stream_encryptor: std::marker::PhantomData
        }
    }
}

impl<InitEncryptor: KeyInit + BlockEncryptMut + 'static, InitDecryptor: KeyInit + BlockDecryptMut + 'static, StreamEncryptor: KeyIvInit + StreamCipher + 'static, const KEY_SIZE: usize, const BLOCK_SIZE: usize> LfdModFactory for LfdIvStreamEncryptFactory<InitEncryptor,InitDecryptor,StreamEncryptor, KEY_SIZE, BLOCK_SIZE> {
    fn create(&self, ctx: &VtunContext, host: &mut VtunHost) -> Result<Box<dyn LfdMod>, i32> {
        let factory = LfdIvEncryptFactory::<InitEncryptor,InitDecryptor,StreamEncryptorToEncryptorAndDecryptor<StreamEncryptor>,StreamEncryptorToEncryptorAndDecryptor<StreamEncryptor>,KEY_SIZE,BLOCK_SIZE>::new();
        factory.create(ctx, host)
    }
}