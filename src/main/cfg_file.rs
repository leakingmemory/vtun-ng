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

use std::{fs, ptr};
use std::ffi::CStr;
use std::ptr::null_mut;
use std::rc::{Rc, Weak};
use std::sync::Mutex;
use logos::Logos;
use crate::{lexer, lfd_mod, linkfd, llist, mainvtun, syslog, tunnel, vtun_host};
use crate::lexer::Token;
use crate::vtun_host::VtunHost;

pub fn find_host_rs(host: &str) -> Option<&mut vtun_host::VtunHost> {
    unsafe {
        let mut host = host.to_string();
        host.push_str("\0");
        let host = find_host(host.as_ptr() as *const libc::c_char);
        if host.is_null() {
            return None;
        }
        Some( &mut *host)
    }
}

struct VtunConfigRoot {
    pub host_list: Vec<vtun_host::VtunHost>
}

trait ParsingContext {
    fn SetFailed(&mut self);
    fn Token(&mut self, ctx: &Rc<Mutex<dyn ParsingContext>>, token: lexer::Token) -> Option<Rc<Mutex<dyn ParsingContext>>>;
    fn EndOfFileOk(&self) -> bool {
        false
    }
}

struct RootParsingContext {
    pub failed: bool,
    pub default_ctx: Vec<Rc<Mutex<KwDefaultParsingContext>>>,
    pub ident_ctx: Vec<Rc<Mutex<RootIdentParsingContext>>>,
    pub options_ctx: Vec<Rc<Mutex<KwOptionsParsingContext>>>
}

impl RootParsingContext {
    pub fn new() -> Self {
        Self {
            failed: false,
            default_ctx: Vec::new(),
            ident_ctx: Vec::new(),
            options_ctx: Vec::new()
        }
    }
    fn apply(&self, opts: &mut lfd_mod::VtunOpts) {
        for options_ctx in &self.options_ctx {
            let options_ctx = options_ctx.lock().unwrap();
            options_ctx.apply(opts);
        }
    }
    fn strdup(s: &str) -> *mut libc::c_char {
        let nullterm = format!("{}\0", s);
        unsafe { libc::strdup(nullterm.as_ptr() as *const libc::c_char) }
    }
    fn get_hosts(&self, ctx: &mainvtun::VtunContext) -> Vec<vtun_host::VtunHost> {
        let mut vec: Vec<vtun_host::VtunHost> = Vec::new();
        vec.reserve(self.ident_ctx.len());
        for ident_ctx in &self.ident_ctx {
            let ident_ctx = ident_ctx.lock().unwrap();
            let name = Self::strdup(ident_ctx.identifier.as_str());
            let host_ctx = match ident_ctx.host_ctx {
                Some(ref host_ctx) => host_ctx.lock().unwrap(),
                None => continue
            };
            let mut host = vtun_host::VtunHost::new();
            host.host = name;
            for default_ctx in &self.default_ctx {
                let default_ctx = default_ctx.lock().unwrap();
                let host_ctx = match default_ctx.host_ctx {
                    Some(ref host_ctx) => host_ctx.lock().unwrap(),
                    None => continue
                };
                host_ctx.apply(ctx, &mut host);
            }
            host_ctx.apply(ctx, &mut host);
            vec.push(host);
        }
        vec
    }
}
impl ParsingContext for RootParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in config file");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.failed = true;
    }
    fn Token(&mut self, ctx: &Rc<Mutex<dyn ParsingContext>>, token: lexer::Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwDefault => {
                let default_ctx = Rc::new(Mutex::new(KwDefaultParsingContext::new(Rc::clone(ctx))));
                self.default_ctx.push(default_ctx.clone());
                Some(default_ctx)
            },
            Token::Ident(identifier) => {
                let ident_ctx = Rc::new(Mutex::new(RootIdentParsingContext::new(Rc::clone(ctx), identifier.as_str())));
                self.ident_ctx.push(ident_ctx.clone());
                Some(ident_ctx)
            },
            Token::KwOptions => {
                let options_ctx = Rc::new(Mutex::new(KwOptionsParsingContext::new(Rc::clone(ctx))));
                self.options_ctx.push(options_ctx.clone());
                Some(options_ctx)
            },
            Token::Semicolon => None,
            _ => {
                let msg = format!("Unexpected token in config");
                syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                self.SetFailed();
                None
            }
        }
    }
    fn EndOfFileOk(&self) -> bool {
        true
    }
}

struct KwDefaultParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    pub host_ctx: Option<Rc<Mutex<HostConfigParsingContext>>>
}

impl KwDefaultParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            host_ctx: None
        }
    }
}

impl ParsingContext for KwDefaultParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in default");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }
    fn Token(&mut self, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::LBrace => {
                let parent = match self.parent.upgrade() {
                    Some(parent) => parent,
                    None => Rc::clone(ctx)
                };
                let host_ctx = Rc::new(Mutex::new(HostConfigParsingContext::new(parent)));
                self.host_ctx = Some(host_ctx.clone());
                Some(host_ctx)
            },
            _ => {
                let msg = format!("Expected {{ afer default");
                syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                self.SetFailed();
                None
            }
        }
    }
}

struct RootIdentParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    identifier: String,
    pub host_ctx: Option<Rc<Mutex<HostConfigParsingContext>>>
}

impl RootIdentParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>, identifier: &str) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            identifier: identifier.to_string(),
            host_ctx: None
        }
    }
}

impl ParsingContext for RootIdentParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error after {}", self.identifier);
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }
    fn Token(&mut self, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::LBrace => {
                let parent = match self.parent.upgrade() {
                    Some(parent) => parent,
                    None => Rc::clone(ctx)
                };
                let host_ctx = Rc::new(Mutex::new(HostConfigParsingContext::new(parent)));
                self.host_ctx = Some(host_ctx.clone());
                Some(host_ctx)
            },
            _ => {
                let msg = format!("Expected {{ afer {}", self.identifier);
                syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                self.SetFailed();
                None
            }
        }
    }
}

struct HostConfigParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    pub compress_ctx: Option<Rc<Mutex<CompressConfigParsingContext>>>,
    pub speed_ctx: Option<Rc<Mutex<IntegerOptionParsingContext>>>,
    pub passwd_ctx: Option<Rc<Mutex<StringOptionParsingContext>>>,
    pub type_ctx: Option<Rc<Mutex<TypeConfigParsingContext>>>,
    pub proto_ctx: Option<Rc<Mutex<ProtoConfigParsingContext>>>,
    pub encrypt_ctx: Option<Rc<Mutex<EncryptConfigParsingContext>>>,
    pub keepalive_ctx: Option<Rc<Mutex<KeepaliveConfigParsingContext>>>,
    pub up_ctx: Option<Rc<Mutex<KwUpDownParsingContext>>>,
    pub down_ctx: Option<Rc<Mutex<KwUpDownParsingContext>>>,
    pub srcaddr_ctx: Option<Rc<Mutex<KwBindaddrConfigParsingContext>>>,
    pub device_ctx: Option<Rc<Mutex<StringOptionParsingContext>>>,
    pub nathack_ctx: Option<Rc<Mutex<NatHackConfigParsingContext>>>,
    pub persist_ctx: Option<Rc<Mutex<BoolOptionParsingContext>>>,
    pub keep_ctx: Option<Rc<Mutex<BoolOptionParsingContext>>>,
    pub stat_ctx: Option<Rc<Mutex<BoolOptionParsingContext>>>
}

impl HostConfigParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            compress_ctx: None,
            speed_ctx: None,
            passwd_ctx: None,
            type_ctx: None,
            proto_ctx: None,
            encrypt_ctx: None,
            keepalive_ctx: None,
            up_ctx: None,
            down_ctx: None,
            srcaddr_ctx: None,
            device_ctx: None,
            nathack_ctx: None,
            persist_ctx: None,
            keep_ctx: None,
            stat_ctx: None
        }
    }
    pub fn free_nonnull(s: *mut libc::c_char) {
        if !s.is_null() {
            unsafe { libc::free(s as *mut libc::c_void) };
        }
    }
    pub fn strdup(s: &str) -> *mut libc::c_char {
        let nullterm = format!("{}\0", s);
        unsafe { libc::strdup(nullterm.as_ptr() as *const libc::c_char) }
    }
    pub fn apply(&self, ctx: &mainvtun::VtunContext, host: &mut vtun_host::VtunHost) {
        match self.compress_ctx {
            None => {},
            Some(ref compress_ctx) => compress_ctx.lock().unwrap().apply(host)
        }
        match self.speed_ctx {
            None => {},
            Some(ref speed_ctx) => {
                let speed_ctx = speed_ctx.lock().unwrap();
                host.spd_out = speed_ctx.value;
            }
        }
        match self.passwd_ctx {
            None => {},
            Some(ref passwd_ctx) => {
                let passwd_ctx = passwd_ctx.lock().unwrap();
                Self::free_nonnull(host.passwd);
                host.passwd = Self::strdup(passwd_ctx.value.as_str());
            }
        }
        match self.type_ctx {
            None => {},
            Some(ref type_ctx) => {
                let type_ctx = type_ctx.lock().unwrap();
                type_ctx.apply(host);
            }
        }
        match self.encrypt_ctx {
            None => {},
            Some(ref encrypt_ctx) => {
                let encrypt_ctx = encrypt_ctx.lock().unwrap();
                encrypt_ctx.apply(host);
            }
        }
        match self.keepalive_ctx {
            None => {},
            Some(ref keepalive_ctx) => {
                let keepalive_ctx = keepalive_ctx.lock().unwrap();
                keepalive_ctx.apply(host);
            }
        }
        match self.proto_ctx {
            None => {},
            Some(ref proto_ctx) => {
                let proto_ctx = proto_ctx.lock().unwrap();
                proto_ctx.apply(host);
            }
        }
        match self.up_ctx {
            None => {},
            Some(ref up_ctx) => up_ctx.lock().unwrap().apply(ctx, &mut host.up)
        }
        match self.down_ctx {
            None => {},
            Some(ref down_ctx) => down_ctx.lock().unwrap().apply(ctx, &mut host.down)
        }
        match self.srcaddr_ctx {
            None => {},
            Some(ref srcaddr_ctx) => srcaddr_ctx.lock().unwrap().apply(&mut host.src_addr)
        }
        match self.device_ctx {
            None => {},
            Some(ref device_ctx) => {
                let device_ctx = device_ctx.lock().unwrap();
                Self::free_nonnull(host.dev);
                host.dev = Self::strdup(device_ctx.value.as_str());
            }
        }
        match self.nathack_ctx {
            None => {},
            Some(ref nathack_ctx) => {
                let nathack_ctx = nathack_ctx.lock().unwrap();
                nathack_ctx.apply(host);
            }
        }
        match self.persist_ctx {
            None => {},
            Some(ref persist_ctx) => {
                let persist_ctx = persist_ctx.lock().unwrap();
                host.persist = if persist_ctx.value { 1 } else { 0 };
            }
        }
        match self.keep_ctx {
            None => {},
            Some(ref keep_ctx) => {
                let keep_ctx = keep_ctx.lock().unwrap();
                if keep_ctx.value {
                    host.flags = host.flags | lfd_mod::VTUN_PERSIST_KEEPIF;
                } else {
                    host.flags = host.flags & !(lfd_mod::VTUN_PERSIST_KEEPIF);
                }
            }
        }
        match self.stat_ctx {
            None => {},
            Some(ref stat_ctx) => {
                let stat_ctx = stat_ctx.lock().unwrap();
                if stat_ctx.value {
                    host.flags = host.flags | linkfd::VTUN_STAT;
                } else {
                    host.flags = host.flags & !(linkfd::VTUN_STAT);
                }
            }
        }
    }
}

impl ParsingContext for HostConfigParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in config section");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }
    fn Token(&mut self, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwCompress => {
                let compress_ctx = Rc::new(Mutex::new(CompressConfigParsingContext::new(Rc::clone(&ctx))));
                self.compress_ctx = Some(compress_ctx.clone());
                Some(compress_ctx)
            },
            Token::KwSpeed => {
                let speed_ctx = Rc::new(Mutex::new(IntegerOptionParsingContext::new(Rc::clone(&ctx), "speed", token)));
                self.speed_ctx = Some(speed_ctx.clone());
                Some(speed_ctx)
            },
            Token::KwPasswd => {
                let passwd_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "passwd", token)));
                self.passwd_ctx = Some(passwd_ctx.clone());
                Some(passwd_ctx)
            },
            Token::KwType => {
                let type_ctx = Rc::new(Mutex::new(TypeConfigParsingContext::new(Rc::clone(&ctx))));
                self.type_ctx = Some(type_ctx.clone());
                Some(type_ctx)
            },
            Token::KwProto => {
                let proto_ctx = Rc::new(Mutex::new(ProtoConfigParsingContext::new(Rc::clone(&ctx))));
                self.proto_ctx = Some(proto_ctx.clone());
                Some(proto_ctx)
            },
            Token::KwEncrypt => {
                let encrypt_ctx = Rc::new(Mutex::new(EncryptConfigParsingContext::new(Rc::clone(&ctx))));
                self.encrypt_ctx = Some(encrypt_ctx.clone());
                Some(encrypt_ctx)
            },
            Token::KwKeepalive => {
                let keepalive_ctx = Rc::new(Mutex::new(KeepaliveConfigParsingContext::new(Rc::clone(&ctx))));
                self.keepalive_ctx = Some(keepalive_ctx.clone());
                Some(keepalive_ctx)
            },
            Token::KwSrcaddr => {
                let srcaddr_ctx = Rc::new(Mutex::new(KwBindaddrConfigParsingContext::new(Rc::clone(&ctx), Token::KwSrcaddr, "srcaddr")));
                self.srcaddr_ctx = Some(srcaddr_ctx.clone());
                Some(srcaddr_ctx)
            },
            Token::KwDevice => {
                let device_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "device", token)));
                self.device_ctx = Some(device_ctx.clone());
                Some(device_ctx)
            },
            Token::KwNatHack => {
                let nathack_ctx = Rc::new(Mutex::new(NatHackConfigParsingContext::new(Rc::clone(&ctx))));
                self.nathack_ctx = Some(nathack_ctx.clone());
                Some(nathack_ctx)
            },
            Token::KwPersist => {
                let persist_ctx = Rc::new(Mutex::new(BoolOptionParsingContext::new(Rc::clone(&ctx), "persist", token)));
                self.persist_ctx = Some(persist_ctx.clone());
                Some(persist_ctx)
            },
            Token::KwKeep => {
                let keep_ctx = Rc::new(Mutex::new(BoolOptionParsingContext::new(Rc::clone(&ctx), "keep", token)));
                self.keep_ctx = Some(keep_ctx.clone());
                Some(keep_ctx)
            },
            Token::KwStat => {
                let stat_ctx = Rc::new(Mutex::new(BoolOptionParsingContext::new(Rc::clone(&ctx), "stat", token)));
                self.stat_ctx = Some(stat_ctx.clone());
                Some(stat_ctx)
            },
            Token::Ident(ident) => {
                match ident.as_str() {
                    "up" => {
                        let up_ctx = Rc::new(Mutex::new(KwUpDownParsingContext::new(Rc::clone(&ctx), "up")));
                        self.up_ctx = Some(up_ctx.clone());
                        Some(up_ctx)
                    },
                    "down" => {
                        let down_ctx = Rc::new(Mutex::new(KwUpDownParsingContext::new(Rc::clone(&ctx), "down")));
                        self.down_ctx = Some(down_ctx.clone());
                        Some(down_ctx)
                    },
                    _ => {
                        let msg = format!("Unexpected token '{}' in host configuration section", ident);
                        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                        self.SetFailed();
                        None
                    }
                }
            }
            Token::Semicolon => None,
            Token::RBrace => {
                self.parent.upgrade()
            },
            _ => {
                let msg = format!("Unexpected token in host configuration section");
                syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                self.SetFailed();
                None
            }
        }
    }
}

struct CompressConfigParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    compress_type: i32,
    separator: bool,
    compress_level: i32
}

impl CompressConfigParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            compress_type: -1,
            separator: false,
            compress_level: -1
        }
    }
    pub fn apply(&self, host: &mut vtun_host::VtunHost) {
        host.flags = host.flags & !(linkfd::VTUN_ZLIB | linkfd::VTUN_LZO);
        host.flags = host.flags | self.compress_type;
        host.zlevel = self.compress_level;
    }
    fn UnexpectedToken(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after compress");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.SetFailed();
        None
    }
}

impl ParsingContext for CompressConfigParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in compress");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }

    fn Token(&mut self, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwNo => {
                if (self.compress_type != -1) {
                    return self.UnexpectedToken();
                }
                self.compress_type = 0;
                None
            },
            Token::Ident(ident) => {
                if (self.compress_type != -1) {
                    return self.UnexpectedToken();
                }
                self.compress_type = match ident.as_str() {
                    "zlib" => linkfd::VTUN_ZLIB,
                    "lzo" => linkfd::VTUN_LZO,
                    _ => return self.UnexpectedToken()
                };
                None
            }
            Token::Colon => {
                if self.compress_type == -1 || self.separator {
                    return self.UnexpectedToken();
                }
                self.separator = true;
                None
            }
            Token::Number(num) => {
                if (self.compress_type == -1 || !self.separator || self.compress_level != -1) {
                    return self.UnexpectedToken();
                }
                self.compress_level = num as i32;
                None
            }
            Token::Semicolon => {
                if self.compress_type == -1 || (self.separator && self.compress_level == -1) {
                    return self.UnexpectedToken();
                }
                if self.compress_level == -1 {
                    self.compress_level = 1;
                }
                self.parent.upgrade()
            }
            _ => {
                self.UnexpectedToken()
            }
        }
    }
}

struct EncryptConfigParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    encrypt_type: i32
}

impl EncryptConfigParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            encrypt_type: -1
        }
    }
    pub fn apply(&self, host: &mut vtun_host::VtunHost) {
        if self.encrypt_type != 0 {
            host.flags = host.flags | linkfd::VTUN_ENCRYPT;
            host.cipher = self.encrypt_type;
        } else {
            host.flags = host.flags & !linkfd::VTUN_ENCRYPT;
            host.cipher = 0;
        }
    }
    fn UnexpectedToken(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after encrypt");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.SetFailed();
        None
    }
}

impl ParsingContext for EncryptConfigParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in encrypt");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }

    fn Token(&mut self, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwNo => {
                if (self.encrypt_type != -1) {
                    return self.UnexpectedToken();
                }
                self.encrypt_type = 0;
                None
            },
            Token::KwYes => {
                if self.encrypt_type != -1 {
                    return self.UnexpectedToken();
                }
                self.encrypt_type = lfd_mod::VTUN_ENC_BF128ECB;
                None
            },
            Token::Ident(ident) => {
                if self.encrypt_type != -1 {
                    return self.UnexpectedToken();
                }
                self.encrypt_type = match ident.as_str() {
                    "blowfish128ecb" => lfd_mod::VTUN_ENC_BF128ECB,
                    "blowfish128cbc" => lfd_mod::VTUN_ENC_BF128CBC,
                    "blowfish128cfb" => lfd_mod::VTUN_ENC_BF128CFB,
                    "blowfish128ofb" => lfd_mod::VTUN_ENC_BF128OFB,
                    "blowfish256ecb" => lfd_mod::VTUN_ENC_BF256ECB,
                    "blowfish256cbc" => lfd_mod::VTUN_ENC_BF256CBC,
                    "blowfish256cfb" => lfd_mod::VTUN_ENC_BF256CFB,
                    "blowfish256ofb" => lfd_mod::VTUN_ENC_BF256OFB,
                    "aes128ecb" => lfd_mod::VTUN_ENC_AES128ECB,
                    "aes128cbc" => lfd_mod::VTUN_ENC_AES128CBC,
                    "aes128cfb" => lfd_mod::VTUN_ENC_AES128CFB,
                    "aes128ofb" => lfd_mod::VTUN_ENC_AES128OFB,
                    "aes256ecb" => lfd_mod::VTUN_ENC_AES256ECB,
                    "aes256cbc" => lfd_mod::VTUN_ENC_AES256CBC,
                    "aes256cfb" => lfd_mod::VTUN_ENC_AES256CFB,
                    "aes256ofb" => lfd_mod::VTUN_ENC_AES256OFB,

                    "oldblowfish128ecb" => lfd_mod::VTUN_LEGACY_ENCRYPT,

                    _ => return self.UnexpectedToken()
                };
                None
            }
            Token::Semicolon => {
                if self.encrypt_type == -1 {
                    return self.UnexpectedToken();
                }
                self.parent.upgrade()
            }
            _ => {
                self.UnexpectedToken()
            }
        }
    }
}

struct TypeConfigParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    pub type_value: i32
}

impl TypeConfigParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            type_value: -1
        }
    }
    pub fn apply(&self, host: &mut vtun_host::VtunHost) {
        host.flags = host.flags & !(linkfd::VTUN_TUN | linkfd::VTUN_ETHER | linkfd::VTUN_TTY | linkfd::VTUN_PIPE);
        host.flags = host.flags | self.type_value;
    }
    fn UnexpectedToken(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after type");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.SetFailed();
        None
    }
}

impl ParsingContext for TypeConfigParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in type");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }

    fn Token(&mut self, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwTun => {
                if self.type_value != -1 {
                    return self.UnexpectedToken();
                }
                self.type_value = linkfd::VTUN_TUN;
                None
            },
            Token::KwEther => {
                if self.type_value != -1 {
                    return self.UnexpectedToken();
                }
                self.type_value = linkfd::VTUN_ETHER;
                None
            },
            Token::KwTty => {
                if self.type_value != -1 {
                    return self.UnexpectedToken();
                }
                self.type_value = linkfd::VTUN_TTY;
                None
            },
            Token::KwPipe => {
                if self.type_value != -1 {
                    return self.UnexpectedToken();
                }
                self.type_value = linkfd::VTUN_PIPE;
                None
            },
            Token::Semicolon => {
                if self.type_value == -1 {
                    return self.UnexpectedToken();
                }
                self.parent.upgrade()
            }
            _ => {
                self.UnexpectedToken()
            }
        }
    }
}

struct ProtoConfigParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    pub proto_value: i32
}

impl ProtoConfigParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            proto_value: -1
        }
    }
    pub fn apply(&self, host: &mut vtun_host::VtunHost) {
        host.flags = host.flags & !(linkfd::VTUN_TCP | linkfd::VTUN_UDP);
        host.flags = host.flags | self.proto_value;
    }
    fn UnexpectedToken(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after proto");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.SetFailed();
        None
    }
}

impl ParsingContext for ProtoConfigParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in proto");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }

    fn Token(&mut self, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwTcp => {
                if self.proto_value != -1 {
                    return self.UnexpectedToken();
                }
                self.proto_value = linkfd::VTUN_TCP;
                None
            },
            Token::KwUdp => {
                if self.proto_value != -1 {
                    return self.UnexpectedToken();
                }
                self.proto_value = linkfd::VTUN_UDP;
                None
            },
            Token::Semicolon => {
                if self.proto_value == -1 {
                    return self.UnexpectedToken();
                }
                self.parent.upgrade()
            }
            _ => {
                self.UnexpectedToken()
            }
        }
    }
}

struct KeepaliveConfigParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    pub keepalive_interval: i32,
    pub keepalive_count: i32,
    interval_set: bool,
    count_set: bool,
    sep_once: bool
}

impl KeepaliveConfigParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            keepalive_interval: -1,
            keepalive_count: -1,
            interval_set: false,
            count_set: false,
            sep_once: false
        }
    }
    pub fn apply(&self, host: &mut vtun_host::VtunHost) {
        host.ka_interval = self.keepalive_interval;
        host.ka_maxfail = self.keepalive_count;
    }
    fn UnexpectedToken(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after keepalive");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.SetFailed();
        None
    }
}

impl ParsingContext for KeepaliveConfigParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in keepalive");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }

    fn Token(&mut self, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwNo => {
                if self.interval_set || self.count_set {
                    return self.UnexpectedToken();
                }
                self.interval_set = true;
                self.keepalive_interval = -1;
                self.count_set = true;
                self.keepalive_count = -1;
                None
            },
            Token::KwYes => {
                if self.interval_set || self.count_set {
                    return self.UnexpectedToken();
                }
                self.keepalive_interval = 30;
                self.keepalive_count = 4;
                self.interval_set = true;
                self.count_set = true;
                None
            }
            Token::Number(num) => {
                if (self.count_set) {
                    return self.UnexpectedToken();
                }
                if (self.interval_set) {
                    self.keepalive_count = num as i32;
                    self.count_set = true;
                } else {
                    self.keepalive_interval = num as i32;
                    self.interval_set = true;
                }
                None
            },
            Token::Colon => {
                if (self.sep_once) {
                    return self.UnexpectedToken();
                }
                self.sep_once = true;
                None
            },
            Token::Semicolon => {
                if !self.interval_set || !self.count_set {
                    return self.UnexpectedToken();
                }
                self.parent.upgrade()
            }
            _ => {
                self.UnexpectedToken()
            }
        }
    }
}

struct NatHackConfigParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    pub nat_hack_disabled: bool,
    pub nat_hack_server: bool,
    pub nat_hack_client: bool
}

impl NatHackConfigParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            nat_hack_disabled: false,
            nat_hack_server: false,
            nat_hack_client: false
        }
    }
    fn apply(&self, host: &mut vtun_host::VtunHost) {
        host.flags = host.flags & !(lfd_mod::VTUN_NAT_HACK_CLIENT | lfd_mod::VTUN_NAT_HACK_SERVER);
        if self.nat_hack_client {
            host.flags = host.flags | lfd_mod::VTUN_NAT_HACK_CLIENT;
        }
        if self.nat_hack_server {
            host.flags = host.flags | lfd_mod::VTUN_NAT_HACK_SERVER;
        }
    }
    fn server(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        if self.nat_hack_disabled || self.nat_hack_server || self.nat_hack_client {
            return self.UnexpectedToken();
        }
        self.nat_hack_server = true;
        None
    }
    fn client(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        if self.nat_hack_disabled || self.nat_hack_server || self.nat_hack_client {
            return self.UnexpectedToken();
        }
        self.nat_hack_client = true;
        None
    }
    fn Str(&mut self, s: &str) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match s {
            "server" => self.server(),
            "client" => self.client(),
            "no" => {
                if self.nat_hack_disabled || self.nat_hack_server || self.nat_hack_client {
                    return self.UnexpectedToken();
                }
                self.nat_hack_disabled = true;
                None
            },
            _ => self.UnexpectedToken()
        }
    }
    fn UnexpectedToken(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after nat_hack");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.SetFailed();
        None
    }
}

impl ParsingContext for NatHackConfigParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in nat_hack");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }

    fn Token(&mut self, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwNo => {
                if self.nat_hack_disabled || self.nat_hack_server || self.nat_hack_client {
                    return self.UnexpectedToken();
                }
                self.nat_hack_disabled = true;
                None
            },
            Token::KwServer => self.server(),
            Token::Ident(ident) => self.Str(ident.as_str()),
            Token::Quoted(ident) => self.Str(ident.as_str()),
            Token::Semicolon => {
                if !self.nat_hack_disabled && !self.nat_hack_server && !self.nat_hack_client {
                    return self.UnexpectedToken();
                }
                self.parent.upgrade()
            }
            _ => {
                self.UnexpectedToken()
            }
        }
    }
}

struct KwOptionsParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    options_ctx: Option<Rc<Mutex<OptionsConfigParsingContext>>>
}

impl KwOptionsParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            options_ctx: None
        }
    }
    fn apply(&self, opts: &mut lfd_mod::VtunOpts) {
        match self.options_ctx {
            None => {},
            Some(ref options_ctx) => options_ctx.lock().unwrap().apply(opts)
        }
    }
}

impl ParsingContext for KwOptionsParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in default");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }
    fn Token(&mut self, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::LBrace => {
                let parent = match self.parent.upgrade() {
                    Some(parent) => parent,
                    None => Rc::clone(ctx)
                };
                let options_ctx = Rc::new(Mutex::new(OptionsConfigParsingContext::new(parent)));
                self.options_ctx = Some(options_ctx.clone());
                Some(options_ctx)
            },
            _ => {
                let msg = format!("Expected {{ afer default");
                syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                self.SetFailed();
                None
            }
        }
    }
}

struct OptionsConfigParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    port_ctx: Option<Rc<Mutex<IntegerOptionParsingContext>>>,
    timeout_ctx: Option<Rc<Mutex<IntegerOptionParsingContext>>>,
    ppp_ctx: Option<Rc<Mutex<StringOptionParsingContext>>>,
    ifconfig_ctx: Option<Rc<Mutex<StringOptionParsingContext>>>,
    route_ctx: Option<Rc<Mutex<StringOptionParsingContext>>>,
    firewall_ctx: Option<Rc<Mutex<StringOptionParsingContext>>>,
    ip_ctx: Option<Rc<Mutex<StringOptionParsingContext>>>,
    bindaddr_ctx: Option<Rc<Mutex<KwBindaddrConfigParsingContext>>>,
    persist_ctx: Option<Rc<Mutex<BoolOptionParsingContext>>>,
    syslog_ctx: Option<Rc<Mutex<SyslogOptionParsingContext>>>
}

impl OptionsConfigParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            port_ctx: None,
            timeout_ctx: None,
            ppp_ctx: None,
            ifconfig_ctx: None,
            route_ctx: None,
            firewall_ctx: None,
            ip_ctx: None,
            bindaddr_ctx: None,
            persist_ctx: None,
            syslog_ctx: None
        }
    }
    fn free_non_null(str: *mut libc::c_char) {
        if (str != ptr::null_mut()) {
            unsafe { libc::free(str as *mut libc::c_void); }
        }
    }
    fn strdup(str: &str) -> *mut libc::c_char {
        let str = format!("{}\0", str);
        unsafe { libc::strdup(str.as_ptr() as *mut libc::c_char) }
    }
    fn apply(&self, opts: &mut lfd_mod::VtunOpts) {
        match self.port_ctx {
            None => {},
            Some(ref port_ctx) => opts.bind_addr.port = port_ctx.lock().unwrap().value as libc::c_int
        }
        match self.timeout_ctx {
            None => {},
            Some(ref timeout_ctx) => opts.timeout = timeout_ctx.lock().unwrap().value as libc::c_int
        }
        match self.ppp_ctx {
            None => {},
            Some(ref ppp_ctx) => {
                let ppp_ctx = ppp_ctx.lock().unwrap();
                Self::free_non_null(opts.ppp);
                opts.ppp = Self::strdup(&ppp_ctx.value);
            }
        }
        match self.ifconfig_ctx {
            None => {},
            Some(ref ifconfig_ctx) => {
                let ifconfig_ctx = ifconfig_ctx.lock().unwrap();
                Self::free_non_null(opts.ifcfg);
                opts.ifcfg = Self::strdup(&ifconfig_ctx.value);
            }
        }
        match self.route_ctx {
            None => {},
            Some(ref route_ctx) => {
                let route_ctx = route_ctx.lock().unwrap();
                Self::free_non_null(opts.route);
                opts.route = Self::strdup(&route_ctx.value);
            }
        }
        match self.firewall_ctx {
            None => {},
            Some(ref firewall_ctx) => {
                let firewall_ctx = firewall_ctx.lock().unwrap();
                Self::free_non_null(opts.fwall);
                opts.fwall = Self::strdup(&firewall_ctx.value);
            }
        }
        match self.ip_ctx {
            None => {},
            Some(ref ip_ctx) => {
                let ip_ctx = ip_ctx.lock().unwrap();
                Self::free_non_null(opts.iproute);
                opts.iproute = Self::strdup(&ip_ctx.value);
            }
        }
        match self.bindaddr_ctx {
            None => {},
            Some(ref bindaddr_ctx) => {
                let bindaddr_ctx = bindaddr_ctx.lock().unwrap();
                bindaddr_ctx.apply(&mut opts.bind_addr);
            }
        }
        match self.persist_ctx {
            None => {},
            Some(ref persist_ctx) => opts.persist = if persist_ctx.lock().unwrap().value { 1 } else { 0 }
        }
        match self.syslog_ctx {
            None => {},
            Some(ref syslog_ctx) => {
                opts.syslog = syslog_ctx.lock().unwrap().value;
            }
        }
    }
}

impl ParsingContext for OptionsConfigParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in options section");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }
    fn Token(&mut self, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwPort => {
                let port_ctx = Rc::new(Mutex::new(IntegerOptionParsingContext::new(Rc::clone(&ctx), "port", token)));
                self.port_ctx = Some(port_ctx.clone());
                Some(port_ctx)
            },
            Token::KwTimeout => {
                let timeout_ctx = Rc::new(Mutex::new(IntegerOptionParsingContext::new(Rc::clone(&ctx), "timeout", token)));
                self.timeout_ctx = Some(timeout_ctx.clone());
                Some(timeout_ctx)
            },
            Token::KwPpp => {
                let ppp_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "ppp", token)));
                self.ppp_ctx = Some(ppp_ctx.clone());
                Some(ppp_ctx)
            },
            Token::KwIfconfig => {
                let ifconfig_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "ifconfig", token)));
                self.ifconfig_ctx = Some(ifconfig_ctx.clone());
                Some(ifconfig_ctx)
            },
            Token::KwRoute => {
                let route_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "route", token)));
                self.route_ctx = Some(route_ctx.clone());
                Some(route_ctx)
            },
            Token::KwFirewall => {
                let firewall_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "firewall", token)));
                self.firewall_ctx = Some(firewall_ctx.clone());
                Some(firewall_ctx)
            },
            Token::KwIp => {
                let ip_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "ip", token)));
                self.ip_ctx = Some(ip_ctx.clone());
                Some(ip_ctx)
            },
            Token::KwBindaddr => {
                let bindaddr_ctx = Rc::new(Mutex::new(KwBindaddrConfigParsingContext::new(Rc::clone(&ctx), Token::KwBindaddr, "bindaddr")));
                self.bindaddr_ctx = Some(bindaddr_ctx.clone());
                Some(bindaddr_ctx)
            },
            Token::KwPersist => {
                let persist_ctx = Rc::new(Mutex::new(BoolOptionParsingContext::new(Rc::clone(&ctx), "persist", token)));
                self.persist_ctx = Some(persist_ctx.clone());
                Some(persist_ctx)
            },
            Token::KwSyslog => {
                let syslog_ctx = Rc::new(Mutex::new(SyslogOptionParsingContext::new(Rc::clone(&ctx))));
                self.syslog_ctx = Some(syslog_ctx.clone());
                Some(syslog_ctx)
            },
            Token::Semicolon => None,
            Token::RBrace => {
                self.parent.upgrade()
            },
            _ => {
                let msg = format!("Unexpected token in options section");
                syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                self.SetFailed();
                None
            }
        }
    }
}

struct KwBindaddrConfigParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    token: Token,
    token_name: &'static str,
    bindaddr_ctx: Option<Rc<Mutex<BindaddrConfigParsingContext>>>
}

impl KwBindaddrConfigParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>, token: Token, token_name: &'static str) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            token,
            token_name,
            bindaddr_ctx: None
        }
    }
    pub fn apply(&self, bindaddr: &mut vtun_host::VtunAddr) {
        match self.bindaddr_ctx {
            None => {},
            Some(ref bindaddr_ctx) => bindaddr_ctx.lock().unwrap().apply(bindaddr)
        }
    }
}

impl ParsingContext for KwBindaddrConfigParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in {}", self.token_name);
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }
    fn Token(&mut self, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::LBrace => {
                let parent = match self.parent.upgrade() {
                    Some(parent) => parent,
                    None => Rc::clone(ctx)
                };
                let bindaddr_ctx = Rc::new(Mutex::new(BindaddrConfigParsingContext::new(parent, self.token_name)));
                self.bindaddr_ctx = Some(bindaddr_ctx.clone());
                Some(bindaddr_ctx)
            },
            _ => {
                let msg = format!("Expected {{ afer bindaddr");
                syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                self.SetFailed();
                None
            }
        }
    }
}

struct BindaddrConfigParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    token_name: &'static str,
    addr_ctx: Option<Rc<Mutex<AddrConfigParsingContext>>>,
    iface_ctx: Option<Rc<Mutex<StringOptionParsingContext>>>
}

impl BindaddrConfigParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>, token_name: &'static str) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            token_name,
            addr_ctx: None,
            iface_ctx: None
        }
    }
    pub fn apply(&self, bindaddr: &mut vtun_host::VtunAddr) {
        match self.iface_ctx {
            None => {},
            Some(ref iface_ctx) => {
                if self.addr_ctx.is_some() {
                    let msg = format!("In '{}' iface overrides addr", self.token_name);
                    syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                }
                let ifname = format!("{}\0", iface_ctx.lock().unwrap().value);
                if bindaddr.name != null_mut() {
                    unsafe { libc::free(bindaddr.name as *mut libc::c_void); }
                }
                bindaddr.name = unsafe { libc::strdup(ifname.as_ptr() as *mut libc::c_char) };
                bindaddr.type_ = lfd_mod::VTUN_ADDR_IFACE;
                return;
            }
        }
        match self.addr_ctx {
            None => {},
            Some(ref addr_ctx) => {
                let addr_ctx = addr_ctx.lock().unwrap();
                addr_ctx.apply(bindaddr)
            }
        }
    }
    fn UnexpectedToken(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token afer {}", self.token_name);
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.SetFailed();
        None
    }
}

impl ParsingContext for BindaddrConfigParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in {}", self.token_name);
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }
    fn Token(&mut self, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwAddr => {
                let addr_ctx = Rc::new(Mutex::new(AddrConfigParsingContext::new(Rc::clone(&ctx))));
                self.addr_ctx = Some(addr_ctx.clone());
                Some(addr_ctx)
            },
            Token::KwIface => {
                let iface_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "iface", token)));
                self.iface_ctx = Some(iface_ctx.clone());
                Some(iface_ctx)
            },
            Token::RBrace => self.parent.upgrade(),
            _ => self.UnexpectedToken()
        }
    }
}

struct AddrConfigParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    pub ipv4: Option<u32>,
    pub hostname: Option<String>
}

impl AddrConfigParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            ipv4: None,
            hostname: None
        }
    }
    pub fn apply(&self, bindaddr: &mut vtun_host::VtunAddr) {
        match self.hostname {
            Some(ref hostname) => {
                let hostname = format!("{}\0", hostname);
                if bindaddr.name != null_mut() {
                    unsafe { libc::free(bindaddr.name as *mut libc::c_void); }
                }
                bindaddr.name = unsafe { libc::strdup(hostname.as_ptr() as *mut libc::c_char) };
                bindaddr.type_ = lfd_mod::VTUN_ADDR_NAME;
                return;
            }
            None => {}
        }
        match self.ipv4 {
            Some(ipv4) => {
                let ipv4 = format!("{}\0", std::net::Ipv4Addr::from(ipv4).to_string());
                if bindaddr.ip != null_mut() {
                    unsafe { libc::free(bindaddr.ip as *mut libc::c_void); }
                }
                bindaddr.ip = unsafe { libc::strdup(ipv4.as_ptr() as *mut libc::c_char) };
            },
            None => {}
        }
    }
    fn hostname(&mut self, hostname: String) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        if self.hostname.is_some() || self.ipv4.is_some() {
            return self.UnexpectedToken();
        }
        self.hostname = Some(hostname);
        None
    }
    fn UnexpectedToken(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after addr");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.SetFailed();
        None
    }
}

impl ParsingContext for AddrConfigParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error after addr");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }
    fn Token(&mut self, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::IPv4(ipv4) => {
                if self.hostname.is_some() || self.ipv4.is_some() {
                    return self.UnexpectedToken();
                }
                self.ipv4 = Some(ipv4);
                None
            },
            Token::Ident(hostname) => self.hostname(hostname),
            Token::Quoted(hostname) => self.hostname(hostname),
            Token::Semicolon => {
                if self.hostname.is_none() && self.ipv4.is_none() {
                    return self.UnexpectedToken();
                }
                self.parent.upgrade()
            },
            _ => self.UnexpectedToken()
        }
    }
}

struct SyslogOptionParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    pub value: libc::c_int,
    is_set: bool
}

impl SyslogOptionParsingContext {
    fn new(parent: Rc<Mutex<dyn ParsingContext>>) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            value: 0,
            is_set: false
        }
    }
    fn from_token(&mut self, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        if (self.is_set) {
            return self.UnexpectedToken();
        }
        self.value = match token {
            Token::KwSyslog => libc::LOG_SYSLOG,
            _ => return self.UnexpectedToken()
        };
        self.is_set = true;
        None
    }
    fn str(&mut self, s: &str) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        if (self.is_set) {
            return self.UnexpectedToken();
        }
        self.value = match s {
            "auth" => libc::LOG_AUTH,
            "cron" => libc::LOG_CRON,
            "daemon" => libc::LOG_DAEMON,
            "kern" => libc::LOG_KERN,
            "lpr" => libc::LOG_LPR,
            "mail" => libc::LOG_MAIL,
            "news" => libc::LOG_NEWS,
            "syslog" => libc::LOG_SYSLOG,
            "user" => libc::LOG_USER,
            "uucp" => libc::LOG_UUCP,
            "local0" => libc::LOG_LOCAL0,
            "local1" => libc::LOG_LOCAL1,
            "local2" => libc::LOG_LOCAL2,
            "local3" => libc::LOG_LOCAL3,
            "local4" => libc::LOG_LOCAL4,
            "local5" => libc::LOG_LOCAL5,
            "local6" => libc::LOG_LOCAL6,
            "local7" => libc::LOG_LOCAL7,
            _ => return self.UnexpectedToken()
        };
        self.is_set = true;
        None
    }
    fn UnexpectedToken(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after syslog");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.SetFailed();
        None
    }
}

impl ParsingContext for SyslogOptionParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error after syslog");
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }
    fn Token(&mut self, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::Ident(ident) => self.str(ident.as_str()),
            Token::Quoted(quoted) => self.str(quoted.as_str()),
            Token::Semicolon => {
                if !self.is_set {
                    return self.UnexpectedToken();
                }
                self.parent.upgrade()
            },
            _ => self.from_token(token)
        }
    }
}

struct KwUpDownParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    ident: &'static str,
    updown_ctx: Option<Rc<Mutex<UpDownParsingContext>>>
}

impl KwUpDownParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>, ident: &'static str) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            ident,
            updown_ctx: None
        }
    }
    pub fn apply(&self, vtun_ctx: &mainvtun::VtunContext, list: &mut llist::LList) {
        match self.updown_ctx {
            None => {},
            Some(ref ctx) => ctx.lock().unwrap().apply(vtun_ctx, list)
        }
    }
}

impl ParsingContext for KwUpDownParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in {}", self.ident);
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }
    fn Token(&mut self, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::LBrace => {
                let parent = match self.parent.upgrade() {
                    Some(parent) => parent,
                    None => Rc::clone(ctx)
                };
                let updown_ctx = Rc::new(Mutex::new(UpDownParsingContext::new(parent, self.ident)));
                self.updown_ctx = Some(updown_ctx.clone());
                Some(updown_ctx)
            },
            _ => {
                let msg = format!("Expected {{ afer {}", self.ident);
                syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                self.SetFailed();
                None
            }
        }
    }
}

struct UpDownParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    ident: &'static str,
    pub cmds: Vec<Rc<Mutex<CommandConfigParsingContext>>>
}

impl UpDownParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>, ident: &'static str) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            ident,
            cmds: Vec::new()
        }
    }
    pub fn apply(&self, ctx: &mainvtun::VtunContext, list: &mut llist::LList) {
        for cmdmtx in self.cmds.iter() {
            let mut nullterm_cmd;
            let nullterm_args;
            let mut flags: libc::c_int = 0;
            {
                let cmd = cmdmtx.lock().unwrap();
                nullterm_cmd = match cmd.token {
                    Token::KwFirewall => unsafe { CStr::from_ptr(ctx.vtun.fwall) }.to_str().unwrap().to_string(),
                    Token::KwIp => unsafe { CStr::from_ptr(ctx.vtun.iproute) }.to_str().unwrap().to_string(),
                    Token::KwIfconfig => unsafe { CStr::from_ptr(ctx.vtun.ifcfg) }.to_str().unwrap().to_string(),
                    Token::KwPpp => unsafe { CStr::from_ptr(ctx.vtun.ppp) }.to_str().unwrap().to_string(),
                    Token::KwRoute => unsafe { CStr::from_ptr(ctx.vtun.route) }.to_str().unwrap().to_string(),
                    Token::KwProgram => match &cmd.path {
                        None => "".to_string(),
                        Some(path) => path.to_string()
                    },
                    _ => continue
                };
                nullterm_cmd.push_str("\0");
                nullterm_args = match cmd.args {
                    Some(ref args) => format!("{}\0", args),
                    None => "\0".to_string()
                };
                if (cmd.wait) {
                    flags = flags | linkfd::VTUN_CMD_WAIT;
                }
                if (cmd.delay) {
                    flags = flags | linkfd::VTUN_CMD_DELAY;
                }
                // Not in use in the old code
                /*if (cmd.use_shell) {
                    flags = flags | linkfd::VTUN_CMD_SHELL;
                }*/
            }
            let cmdobj = {
                let cmdobj;
                unsafe {
                    cmdobj = libc::malloc(size_of::<tunnel::VtunCmd>()) as *mut tunnel::VtunCmd;
                    libc::memset(cmdobj as *mut libc::c_void, 0, size_of::<tunnel::VtunCmd>());
                    (*cmdobj).prog = libc::strdup(nullterm_cmd.as_ptr() as *mut libc::c_char);
                    (*cmdobj).args = libc::strdup(nullterm_args.as_ptr() as *mut libc::c_char);
                    (*cmdobj).flags = flags;
                }
                cmdobj
            };
            if (list.head != ptr::null_mut()) {
                unsafe {&mut *(list.tail)}.next = unsafe {
                    let next: *mut llist::LListElement = libc::malloc(size_of::<llist::LListElement>()) as *mut llist::LListElement;
                    libc::memset(next as *mut libc::c_void, 0, size_of::<llist::LListElement>());
                    (*next).data = cmdobj as *mut libc::c_void;
                    next
                };
                list.tail = unsafe {&mut *(list.tail)}.next;
            } else {
                list.head = unsafe {
                    let next: *mut llist::LListElement = libc::malloc(size_of::<llist::LListElement>()) as *mut llist::LListElement;
                    libc::memset(next as *mut libc::c_void, 0, size_of::<llist::LListElement>());
                    (*next).data = cmdobj as *mut libc::c_void;
                    next
                };
                list.tail = list.head;
            }
        }
    }
}

impl ParsingContext for UpDownParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in {}", self.ident);
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }
    fn Token(&mut self, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwProgram => {
                let program_ctx = Rc::new(Mutex::new(CommandConfigParsingContext::new(Rc::clone(&ctx), "program", token)));
                self.cmds.push(program_ctx.clone());
                Some(program_ctx)
            },
            Token::KwIfconfig => {
                let ifconfig_ctx = Rc::new(Mutex::new(CommandConfigParsingContext::new(Rc::clone(&ctx), "ifconfig", token)));
                self.cmds.push(ifconfig_ctx.clone());
                Some(ifconfig_ctx)
            },
            Token::KwRoute => {
                let route_ctx = Rc::new(Mutex::new(CommandConfigParsingContext::new(Rc::clone(&ctx), "route", token)));
                self.cmds.push(route_ctx.clone());
                Some(route_ctx)
            },
            Token::KwFirewall => {
                let firewall_ctx = Rc::new(Mutex::new(CommandConfigParsingContext::new(Rc::clone(&ctx), "firewall", token)));
                self.cmds.push(firewall_ctx.clone());
                Some(firewall_ctx)
            },
            Token::KwIp => {
                let ip_ctx = Rc::new(Mutex::new(CommandConfigParsingContext::new(Rc::clone(&ctx), "ip", token)));
                self.cmds.push(ip_ctx.clone());
                Some(ip_ctx)
            },
            Token::KwPpp => {
                let ppp_ctx = Rc::new(Mutex::new(CommandConfigParsingContext::new(Rc::clone(&ctx), "ppp", token)));
                self.cmds.push(ppp_ctx.clone());
                Some(ppp_ctx)
            },
            Token::Semicolon => None,
            Token::RBrace => {
                self.parent.upgrade()
            },
            _ => {
                let msg = format!("Unexpected token in {} section", self.ident);
                syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                self.SetFailed();
                None
            }
        }
    }
}

struct CommandConfigParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    pub token: Token,
    pub token_name: &'static str,
    pub path: Option<String>,
    pub args: Option<String>,
    pub wait: bool,
    pub delay: bool,
    // Not in use in the old code
    //pub use_shell: bool
}

impl CommandConfigParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>, token_name: &'static str, token: Token) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            token,
            token_name,
            path: None,
            args: None,
            wait: false,
            delay: false,
            // Not in use in the old code
            //use_shell: false
        }
    }
    fn HandleString(&mut self, str: &str) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        if matches!(self.token, Token::KwProgram) && self.path.is_none() {
            self.path = Some(str.to_string());
            return None;
        }
        match &self.args {
            Some(_) => match str {
                "wait" => {
                    if (self.wait) {
                        return self.UnexpectedToken();
                    }
                    self.wait = true;
                    None
                },
                "delay" => {
                    if (self.delay) {
                        return self.UnexpectedToken();
                    }
                    self.delay = true;
                    None
                },
                // Not in use in the old code
                /*"shell" => {
                    if self.use_shell {
                        return self.UnexpectedToken();
                    }
                    self.use_shell = true;
                    None
                },*/
                _ => self.UnexpectedToken()
            },
            None => {
                self.args = Some(str.to_string());
                None
            }
        }
    }
    fn UnexpectedToken(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after {}", self.token_name);
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.SetFailed();
        None
    }
}

impl ParsingContext for CommandConfigParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in {}", self.token_name);
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }

    fn Token(&mut self, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::Ident(ident) => self.HandleString(ident.as_str()),
            Token::Quoted(quoted) => self.HandleString(quoted.as_str()),
            Token::Semicolon => {
                if matches!(self.token, Token::KwProgram) && self.path.is_none() {
                    return self.UnexpectedToken();
                }
                match &self.args {
                    None => self.UnexpectedToken(),
                    Some(_) => self.parent.upgrade()
                }
            }
            _ => {
                self.UnexpectedToken()
            }
        }
    }
}

struct IntegerOptionParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    token_name: &'static str,
    token: Token,
    value: i32,
    is_set: bool
}

impl IntegerOptionParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>, token_name: &'static str, token: Token) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            token_name,
            token,
            value: -1,
            is_set: false
        }
    }
    fn UnexpectedToken(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after {}", self.token_name);
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.SetFailed();
        None
    }
}

impl ParsingContext for IntegerOptionParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in {}", self.token_name);
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }

    fn Token(&mut self, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::Number(value) => {
                if self.is_set {
                    return self.UnexpectedToken();
                }
                self.value = value as i32;
                self.is_set = true;
                None
            },
            Token::Semicolon => {
                if !self.is_set {
                    return self.UnexpectedToken();
                }
                self.parent.upgrade()
            }
            _ => {
                self.UnexpectedToken()
            }
        }
    }
}

struct StringOptionParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    token_name: &'static str,
    token: Token,
    value: String,
    is_set: bool
}

impl StringOptionParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>, token_name: &'static str, token: Token) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            token_name,
            token,
            value: "".to_string(),
            is_set: false
        }
    }
    fn UnexpectedToken(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after {}", self.token_name);
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.SetFailed();
        None
    }
}

impl ParsingContext for StringOptionParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in {}", self.token_name);
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }

    fn Token(&mut self, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::Ident(value) => {
                if (self.is_set) {
                    return self.UnexpectedToken();
                }
                self.value = value.to_string();
                self.is_set = true;
                None
            },
            Token::Quoted(value) => {
                if (self.is_set) {
                    return self.UnexpectedToken();
                }
                self.value = value;
                self.is_set = true;
                None
            },
            Token::Semicolon => {
                if !self.is_set {
                    return self.UnexpectedToken();
                }
                self.parent.upgrade()
            }
            _ => {
                self.UnexpectedToken()
            }
        }
    }
}

struct BoolOptionParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    token_name: &'static str,
    token: Token,
    value: bool,
    is_set: bool
}

impl BoolOptionParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>, token_name: &'static str, token: Token) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            token_name,
            token,
            value: false,
            is_set: false
        }
    }
    fn yes(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        self.value = true;
        self.is_set = true;
        None
    }
    fn no(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        self.value = false;
        self.is_set = true;
        None
    }
    fn UnexpectedToken(&mut self) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after {}", self.token_name);
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.SetFailed();
        None
    }
}

impl ParsingContext for BoolOptionParsingContext {
    fn SetFailed(&mut self) {
        let msg = format!("Parse error in {}", self.token_name);
        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().SetFailed(),
            None => {}
        }
    }

    fn Token(&mut self, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwYes => self.yes(),
            Token::KwNo => self.no(),
            Token::Quoted(value) => {
                match value.as_str() {
                    "yes" => self.yes(),
                    "no" => self.no(),
                    _ => self.UnexpectedToken()
                }
            },
            Token::Semicolon => {
                if !self.is_set {
                    return self.UnexpectedToken();
                }
                self.parent.upgrade()
            }
            _ => {
                self.UnexpectedToken()
            }
        }
    }
}

impl VtunConfigRoot {
    pub fn new(vtun_ctx: &mut mainvtun::VtunContext, file: &str) -> Option<Self> {
        let rootctx = Rc::new(Mutex::new(RootParsingContext::new()));
        {
            let mut ctx: Rc<Mutex<dyn ParsingContext>> = rootctx.clone();
            let content = match fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => {
                    let msg = format!("Failed to read config file '{}'", file);
                    syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                    return None;
                }
            };
            let mut lexer = lexer::Token::lexer(content.as_str());
            while let Some(result) = lexer.next() {
                match result {
                    Ok(token) => {
                        let mut nctx = None;
                        {
                            let mut mctx = ctx.lock().unwrap();
                            match token {
                                Token::_Comment => {},
                                _ => {
                                    nctx = mctx.Token(&ctx, token);
                                }
                            }
                        }
                        {
                            let rctx = rootctx.lock().unwrap();
                            if (rctx.failed) {
                                let msg = format!("Parse error at: {}", lexer.slice());
                                syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                                return None;
                            }
                        }
                        match nctx {
                            Some(nctx) => { ctx = nctx; },
                            None => {}
                        }
                    },
                    Err(_) => {
                        let msg = format!("Parse error at: {}", lexer.slice());
                        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                        return None;
                    }
                }
            }
            let mut mctx = ctx.lock().unwrap();
            if !mctx.EndOfFileOk() {
                let msg = format!("Parse error at: End of file");
                syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                return None;
            }
        }
        let parsed = rootctx.lock().unwrap();
        parsed.apply(&mut vtun_ctx.vtun);

        let root = VtunConfigRoot {
            host_list: parsed.get_hosts(vtun_ctx)
        };

        Some(root)
    }
    pub fn clear_nat_hack_flags(&mut self, server: bool) {
        for host in &mut self.host_list {
            if (server) {
                host.clear_nat_hack_server();
            } else {
                host.clear_nat_hack_client();
            }
        }
    }
    pub fn find_host(&mut self, name: &str) -> Option<&mut vtun_host::VtunHost> {
        for host in &mut self.host_list {
            if host.host_name() == name {
                return Some(host);
            }
        }
        None
    }
}

static mut CONFIG_ROOT: Option<VtunConfigRoot> = None;

pub fn read_config(ctx: &mut mainvtun::VtunContext, file: *const libc::c_char) -> libc::c_int {
    let root = VtunConfigRoot::new(ctx, unsafe { std::ffi::CStr::from_ptr(file) }.to_str().unwrap());
    match root {
        Some(root) => unsafe { CONFIG_ROOT = Some(root); },
        None => return 0
    }
    1
}

#[no_mangle]
pub extern "C" fn clear_nat_hack_flags(server: libc::c_int) -> libc::c_int {
    unsafe {
        if let Some(root) = &mut CONFIG_ROOT {
            root.clear_nat_hack_flags(if server != 0 { true } else { false });
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn find_host(name: *const libc::c_char) -> *mut vtun_host::VtunHost {
    let found_host = unsafe {
        if let Some(root) = &mut CONFIG_ROOT {
            root.find_host(std::ffi::CStr::from_ptr(name).to_str().unwrap())
        } else {
            None
        }
    };
    match found_host {
        Some(host) => host as *mut VtunHost,
        None => std::ptr::null_mut()
    }
}
