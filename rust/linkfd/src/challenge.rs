use std::ffi::CStr;
use blowfish::Blowfish;
use cipher::{Block, BlockDecryptMut, BlockEncryptMut, KeyInit};

pub const VTUN_CHAL_SIZE: usize = 16;

#[no_mangle]
pub extern "C" fn gen_chal(buf: *mut u8) {
    let slice = unsafe {
        std::slice::from_raw_parts_mut(buf, VTUN_CHAL_SIZE)
    };

    openssl::rand::rand_bytes(slice).expect("");
}

type BlowfishEcbEnc = ecb::Encryptor<Blowfish>;
type BlowfishEcbDec = ecb::Decryptor<Blowfish>;
#[no_mangle]
pub extern "C" fn encrypt_chal(in_chal: *mut u8, in_pwd: *mut libc::c_char)
{
    let slice = unsafe {
        std::slice::from_raw_parts_mut(in_chal, VTUN_CHAL_SIZE)
    };
    let pwd = unsafe {CStr::from_ptr(in_pwd).to_bytes()};
    let key = md5::compute(pwd);

    let mut bfecb = BlowfishEcbEnc::new_from_slice(&(key[0..16])).unwrap();

    for i in 0..(VTUN_CHAL_SIZE/8) {
        bfecb.encrypt_block_mut(<&mut Block<BlowfishEcbEnc>>::from(&mut slice[i * 8..(i + 1) * 8]));
    }
}

#[no_mangle]
pub extern "C" fn decrypt_chal(in_chal: *mut u8, in_pwd: *mut libc::c_char)
{
    let slice = unsafe {
        std::slice::from_raw_parts_mut(in_chal, VTUN_CHAL_SIZE)
    };
    let pwd = unsafe {CStr::from_ptr(in_pwd).to_bytes()};
    let key = md5::compute(pwd);

    let mut bfecb = BlowfishEcbDec::new_from_slice(&(key[0..16])).unwrap();

    for i in 0..(VTUN_CHAL_SIZE/8) {
        bfecb.decrypt_block_mut(<&mut Block<BlowfishEcbDec>>::from(&mut slice[i * 8..(i + 1) * 8]));
    }
}
