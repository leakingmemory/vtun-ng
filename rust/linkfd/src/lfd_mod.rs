#[repr(C)]
pub struct VtunSopt {
    pub dev: *mut libc::c_char,
    pub laddr: *mut libc::c_char,
    pub lport: libc::c_int,
    pub raddr: *mut libc::c_char,
    pub rport: libc::c_int,
    pub host: *mut libc::c_char,
}

#[repr(C)]
pub struct VtunStat {
    pub byte_in: u64,
    pub byte_out: u64,
    pub comp_in: u64,
    pub comp_out: u64,
    pub file: *mut libc::c_void,
}

#[repr(C)]
pub struct VtunAddr {
    pub name: *mut libc::c_char,
    pub ip: *mut libc::c_char,
    pub port: libc::c_int,
    pub type_: libc::c_int,
}

#[repr(C)]
struct LListElement {
    pub next: *mut LListElement,
    pub data: *mut libc::c_void
}

#[repr(C)]
pub struct LList {
    pub head: *mut LListElement,
    pub tail: *mut LListElement
}

#[repr(C)]
pub struct VtunHost {
    pub host: *mut libc::c_char,
    pub passwd: *mut libc::c_char,
    pub dev: *mut libc::c_char,
    pub up: LList,
    pub down: LList,
    pub flags: libc::c_int,
    pub timeout: libc::c_int,
    pub spd_in: libc::c_int,
    pub spd_out: libc::c_int,
    pub zlevel: libc::c_int,
    pub cipher: libc::c_int,
    pub rmt_fd: libc::c_int,
    pub loc_fd: libc::c_int,
    pub persist: libc::c_int,
    pub multi: libc::c_int,
    pub ka_interval: libc::c_int,
    pub ka_maxfail: libc::c_int,
    pub src_addr: VtunAddr,
    pub stat: VtunStat,
    pub sopt: VtunSopt,
}

#[repr(C)]
pub struct LfdMod {
    pub name: *mut libc::c_char,
    pub alloc: Option<unsafe extern "C" fn(*mut VtunHost) -> libc::c_int>,
    pub encode: Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_char, *mut *mut libc::c_char) -> libc::c_int>,
    pub avail_encode: Option<unsafe extern "C" fn() -> libc::c_int>,
    pub decode: Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_char, *mut *mut libc::c_char) -> libc::c_int>,
    pub avail_decode: Option<unsafe extern "C" fn() -> libc::c_int>,
    pub free: Option<unsafe extern "C" fn() -> libc::c_int>,
    pub next: *mut LfdMod,
    pub prev: *mut LfdMod,
}

pub static VTUN_ENC_BF128ECB: libc::c_int = 1;
pub static VTUN_ENC_BF128CBC: libc::c_int = 2;
pub static VTUN_ENC_BF128CFB: libc::c_int = 3;
pub static VTUN_ENC_BF128OFB: libc::c_int = 4;
pub static VTUN_ENC_BF256ECB: libc::c_int = 5;
pub static VTUN_ENC_BF256CBC: libc::c_int = 6;
pub static VTUN_ENC_BF256CFB: libc::c_int = 7;
pub static VTUN_ENC_BF256OFB: libc::c_int = 8;

pub static VTUN_ENC_AES128ECB: libc::c_int = 9;
pub static VTUN_ENC_AES128CBC: libc::c_int = 10;
pub static VTUN_ENC_AES128CFB: libc::c_int = 11;
pub static VTUN_ENC_AES128OFB: libc::c_int = 12;
pub static VTUN_ENC_AES256ECB: libc::c_int = 13;
pub static VTUN_ENC_AES256CBC: libc::c_int = 14;
pub static VTUN_ENC_AES256CFB: libc::c_int = 15;
pub static VTUN_ENC_AES256OFB: libc::c_int = 16;

pub static VTUN_LEGACY_ENCRYPT: libc::c_int = 999;

pub const LOG_EMERG: libc::c_int = 0;
pub const LOG_ALERT: libc::c_int = 1;
pub const LOG_CRIT: libc::c_int = 2;
pub const LOG_ERR: libc::c_int = 3;
pub const LOG_WARNING: libc::c_int = 4;
pub const LOG_NOTICE: libc::c_int = 5;
pub const LOG_INFO: libc::c_int = 6;
pub const LOG_DEBUG: libc::c_int = 7;
pub unsafe extern "C" fn vtun_syslog(_priority: libc::c_int, _format: *mut libc::c_char) {}
