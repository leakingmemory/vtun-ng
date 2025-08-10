use blowfish::Blowfish;
use cipher::{Block, BlockDecryptMut, BlockEncryptMut, KeyInit};

pub const VTUN_CHAL_SIZE: usize = 16;

pub fn gen_chal(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    match getrandom::fill(buf) {
        Ok(_) => Ok(()),
        Err(e) => Err(e)
    }
}

type BlowfishEcbEnc = ecb::Encryptor<Blowfish>;
type BlowfishEcbDec = ecb::Decryptor<Blowfish>;

pub fn encrypt_chal(slice: &mut [u8], pwd: &str)
{
    let key = md5::compute(pwd.as_bytes());

    let mut bfecb = BlowfishEcbEnc::new_from_slice(&(key[0..16])).unwrap();

    for i in 0..(VTUN_CHAL_SIZE/8) {
        bfecb.encrypt_block_mut(<&mut Block<BlowfishEcbEnc>>::from(&mut slice[i * 8..(i + 1) * 8]));
    }
}

pub fn decrypt_chal(slice: &mut [u8], pwd: &str)
{
    let key = md5::compute(pwd.as_bytes());

    let mut bfecb = BlowfishEcbDec::new_from_slice(&(key[0..16])).unwrap();

    for i in 0..(VTUN_CHAL_SIZE/8) {
        bfecb.decrypt_block_mut(<&mut Block<BlowfishEcbDec>>::from(&mut slice[i * 8..(i + 1) * 8]));
    }
}
