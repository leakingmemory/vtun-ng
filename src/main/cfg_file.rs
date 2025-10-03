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

use std::{fs};
use std::rc::{Rc, Weak};
use std::sync::Mutex;
use logos::Logos;
use crate::{lfd_mod, linkfd, vtun_host};
use crate::lexer::Token;
#[cfg(test)]
use crate::lfd_mod::VtunOpts;
use crate::linkfd::VTUN_ENCRYPT;
use crate::mainvtun::VtunContext;
use crate::syslog::SyslogObject;
use crate::tunnel::VtunCmd;
use crate::vtun_host::{VtunAddr, VtunHost};

pub struct VtunConfigRoot {
    pub host_list: Vec<VtunHost>
}

trait ParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext);
    fn token(&mut self, vtunctx: &VtunContext, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>>;
    fn end_of_file_ok(&self) -> bool {
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
    fn apply(&self, ctx: &mut VtunContext) {
        for options_ctx in &self.options_ctx {
            let options_ctx = options_ctx.lock().unwrap();
            options_ctx.apply(ctx);
        }
    }
    fn get_hosts(&self, ctx: &VtunContext) -> Vec<VtunHost> {
        let mut vec: Vec<VtunHost> = Vec::new();
        vec.reserve(self.ident_ctx.len());
        for ident_ctx in &self.ident_ctx {
            let ident_ctx = ident_ctx.lock().unwrap();
            let host_ctx = match ident_ctx.host_ctx {
                Some(ref host_ctx) => host_ctx.lock().unwrap(),
                None => continue
            };
            let mut host = VtunHost::new();
            host.host = Some(ident_ctx.identifier.clone());
            for default_ctx in &self.default_ctx {
                let default_ctx = default_ctx.lock().unwrap();
                let host_ctx = match default_ctx.host_ctx {
                    Some(ref host_ctx) => host_ctx.lock().unwrap(),
                    None => continue
                };
                host_ctx.apply(ctx, &mut host);
            }
            host_ctx.apply(ctx, &mut host);
            if (host.flags & VTUN_ENCRYPT) != 0 {
                if (host.requires & vtun_host::RequiresFlags::INTEGRITY_PROTECTION) != 0 &&
                    (host.requires & vtun_host::RequiresFlags::CLIENT_ONLY) == 0 &&
                    match host.cipher {
                        lfd_mod::VTUN_ENC_AES128GCM => false,
                        lfd_mod::VTUN_ENC_AES256GCM => false,
                        _ => true
                    } {
                    let msg = format!("Host config {} requires integrity protection but configured with a cipher that does not check integrity. Not suitable for server. Setting client only.", match host.host {
                        Some(ref str) => str.as_str(),
                        None => ""
                    });
                    ctx.syslog(lfd_mod::LOG_WARNING, msg.as_str());
                    let msg = format!("Host config {} is automatically client only.", match host.host {
                        Some(ref str) => str.as_str(),
                        None => ""
                    });
                    ctx.syslog(lfd_mod::LOG_WARNING, msg.as_str());
                    host.requires = host.requires | vtun_host::RequiresFlags::CLIENT_ONLY;
                }
            } else if (host.requires & (vtun_host::RequiresFlags::ENCRYPTION | vtun_host::RequiresFlags::INTEGRITY_PROTECTION)) != 0 &&
                (host.requires & vtun_host::RequiresFlags::CLIENT_ONLY) == 0 {
                let msg = format!("Host config {} requires encryption and/or integrity protection but configured without appropriate type of encryption. Not suitable for server. Setting client only.", match host.host {
                    Some(ref str) => str.as_str(),
                    None => ""
                });
                ctx.syslog(lfd_mod::LOG_WARNING, msg.as_str());
                let msg = format!("Host config {} is automatically client only.", match host.host {
                    Some(ref str) => str.as_str(),
                    None => ""
                });
                ctx.syslog(lfd_mod::LOG_WARNING, msg.as_str());
                host.requires = host.requires | vtun_host::RequiresFlags::CLIENT_ONLY;
            }
            vec.push(host);
        }
        vec
    }
}
impl ParsingContext for RootParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        ctx.syslog(lfd_mod::LOG_ERR, "Parse error in config file");
        self.failed = true;
    }
    fn token(&mut self, vtunctx: &VtunContext, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
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
                vtunctx.syslog(lfd_mod::LOG_ERR, "Unexpected token in config");
                self.set_failed(vtunctx);
                None
            }
        }
    }
    fn end_of_file_ok(&self) -> bool {
        true
    }
}

fn cipher_from_string(str: &str) -> Result<i32,()> {
    let cipher = match str {
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
        "aes128gcm" => lfd_mod::VTUN_ENC_AES128GCM,
        "aes256gcm" => lfd_mod::VTUN_ENC_AES256GCM,

        "oldblowfish128ecb" => lfd_mod::VTUN_LEGACY_ENCRYPT,

        _ => return Err(())
    };
    Ok(cipher)
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
    fn set_failed(&mut self, ctx: &VtunContext) {
        ctx.syslog(lfd_mod::LOG_ERR, "Parse error in default");
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }
    fn token(&mut self, vtunctx: &VtunContext, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
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
                vtunctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                self.set_failed(vtunctx);
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
    fn set_failed(&mut self, ctx: &VtunContext) {
        let msg = format!("Parse error after {}", self.identifier);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }
    fn token(&mut self, vtunctx: &VtunContext, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
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
                vtunctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                self.set_failed(vtunctx);
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
    pub stat_ctx: Option<Rc<Mutex<BoolOptionParsingContext>>>,
    pub experimental_ctx: Option<Rc<Mutex<BoolOptionParsingContext>>>,
    pub requires_ctx: Option<Rc<Mutex<KwRequiresParsingContext>>>,
    pub accept_encrypt_ctx: Vec<Rc<Mutex<KwAcceptEncryptParsingContext>>>
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
            stat_ctx: None,
            experimental_ctx: None,
            requires_ctx: None,
            accept_encrypt_ctx: Vec::new()
        }
    }
    pub fn apply(&self, ctx: &VtunContext, host: &mut VtunHost) {
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
                host.passwd = Some(passwd_ctx.value.clone());
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
            Some(ref srcaddr_ctx) => srcaddr_ctx.lock().unwrap().apply(ctx, &mut host.src_addr)
        }
        match self.device_ctx {
            None => {},
            Some(ref device_ctx) => {
                let device_ctx = device_ctx.lock().unwrap();
                host.dev = Some(device_ctx.value.clone());
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
                    host.flags = host.flags & !lfd_mod::VTUN_PERSIST_KEEPIF;
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
                    host.flags = host.flags & !linkfd::VTUN_STAT;
                }
            }
        }
        match self.experimental_ctx {
            None => {},
            Some(ref experimental_ctx) => {
                let experimental_ctx = experimental_ctx.lock().unwrap();
                host.experimental = experimental_ctx.value;
            }
        }
        match self.requires_ctx {
            None => {},
            Some(ref requires_ctx) => {
                let requires_ctx = requires_ctx.lock().unwrap();
                host.requires = requires_ctx.flags.clone();
            }
        }
        for accept_encrypt in self.accept_encrypt_ctx.iter() {
            let accept_encrypt = accept_encrypt.lock().unwrap();
            for cipher in accept_encrypt.ciphers.iter() {
                match host.accepted_cipher {
                    Some(ref mut accepted_cipher) => {
                        if !accepted_cipher.contains(cipher) {
                            accepted_cipher.push(cipher.clone());
                        }
                    },
                    None => {
                        host.accepted_cipher = Some(vec![cipher.clone()]);
                    }
                }
            }
        }
    }
}

impl ParsingContext for HostConfigParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        ctx.syslog(lfd_mod::LOG_ERR, "Parse error in config section");
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }
    fn token(&mut self, vtunctx: &VtunContext, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwCompress => {
                let compress_ctx = Rc::new(Mutex::new(CompressConfigParsingContext::new(Rc::clone(&ctx))));
                self.compress_ctx = Some(compress_ctx.clone());
                Some(compress_ctx)
            },
            Token::KwSpeed => {
                let speed_ctx = Rc::new(Mutex::new(IntegerOptionParsingContext::new(Rc::clone(&ctx), "speed")));
                self.speed_ctx = Some(speed_ctx.clone());
                Some(speed_ctx)
            },
            Token::KwPasswd => {
                let passwd_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "passwd")));
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
                let srcaddr_ctx = Rc::new(Mutex::new(KwBindaddrConfigParsingContext::new(Rc::clone(&ctx), "srcaddr")));
                self.srcaddr_ctx = Some(srcaddr_ctx.clone());
                Some(srcaddr_ctx)
            },
            Token::KwDevice => {
                let device_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "device")));
                self.device_ctx = Some(device_ctx.clone());
                Some(device_ctx)
            },
            Token::KwNatHack => {
                let nathack_ctx = Rc::new(Mutex::new(NatHackConfigParsingContext::new(Rc::clone(&ctx))));
                self.nathack_ctx = Some(nathack_ctx.clone());
                Some(nathack_ctx)
            },
            Token::KwPersist => {
                let persist_ctx = Rc::new(Mutex::new(BoolOptionParsingContext::new(Rc::clone(&ctx), "persist")));
                self.persist_ctx = Some(persist_ctx.clone());
                Some(persist_ctx)
            },
            Token::KwKeep => {
                let keep_ctx = Rc::new(Mutex::new(BoolOptionParsingContext::new(Rc::clone(&ctx), "keep")));
                self.keep_ctx = Some(keep_ctx.clone());
                Some(keep_ctx)
            },
            Token::KwStat => {
                let stat_ctx = Rc::new(Mutex::new(BoolOptionParsingContext::new(Rc::clone(&ctx), "stat")));
                self.stat_ctx = Some(stat_ctx.clone());
                Some(stat_ctx)
            },
            Token::KwExperimental => {
                let experimental_ctx = Rc::new(Mutex::new(BoolOptionParsingContext::new(Rc::clone(&ctx), "experimental")));
                self.experimental_ctx = Some(experimental_ctx.clone());
                Some(experimental_ctx)
            },
            Token::KwRequires => {
                let requires_ctx = Rc::new(Mutex::new(KwRequiresParsingContext::new(Rc::clone(&ctx))));
                if self.requires_ctx.is_none() {
                    self.requires_ctx = Some(requires_ctx.clone());
                    Some(requires_ctx)
                } else {
                    vtunctx.syslog(lfd_mod::LOG_ERR, "Duplicate requires statement");
                    self.set_failed(vtunctx);
                    None
                }
            },
            Token::KwAcceptEncrypt => {
                let accept_encrypt_ctx = Rc::new(Mutex::new(KwAcceptEncryptParsingContext::new(Rc::clone(&ctx))));
                self.accept_encrypt_ctx.push(accept_encrypt_ctx.clone());
                Some(accept_encrypt_ctx)
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
                        vtunctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                        self.set_failed(vtunctx);
                        None
                    }
                }
            }
            Token::Semicolon => None,
            Token::RBrace => {
                self.parent.upgrade()
            },
            _ => {
                vtunctx.syslog(lfd_mod::LOG_ERR, "Unexpected token in host configuration section");
                self.set_failed(vtunctx);
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
    pub fn apply(&self, host: &mut VtunHost) {
        host.flags = host.flags & !(linkfd::VTUN_ZLIB | linkfd::VTUN_LZO);
        host.flags = host.flags | self.compress_type;
        host.zlevel = self.compress_level;
    }
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        ctx.syslog(lfd_mod::LOG_ERR, "Unexpected token after compress");
        self.set_failed(ctx);
        None
    }
}

impl ParsingContext for CompressConfigParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        ctx.syslog(lfd_mod::LOG_ERR, "Parse error in compress");
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }

    fn token(&mut self, vtunctx: &VtunContext, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwNo => {
                if self.compress_type != -1 {
                    return self.unexpected_token(vtunctx);
                }
                self.compress_type = 0;
                None
            },
            Token::Ident(ident) => {
                if self.compress_type != -1 {
                    return self.unexpected_token(vtunctx);
                }
                self.compress_type = match ident.as_str() {
                    "zlib" => linkfd::VTUN_ZLIB,
                    "lzo" => linkfd::VTUN_LZO,
                    _ => return self.unexpected_token(vtunctx)
                };
                None
            }
            Token::Colon => {
                if self.compress_type == -1 || self.separator {
                    return self.unexpected_token(vtunctx);
                }
                self.separator = true;
                None
            }
            Token::Number(num) => {
                if self.compress_type == -1 || !self.separator || self.compress_level != -1 {
                    return self.unexpected_token(vtunctx);
                }
                self.compress_level = num as i32;
                None
            }
            Token::Semicolon => {
                if self.compress_type == -1 || (self.separator && self.compress_level == -1) {
                    return self.unexpected_token(vtunctx);
                }
                if self.compress_level == -1 {
                    self.compress_level = 1;
                }
                self.parent.upgrade()
            }
            _ => {
                self.unexpected_token(vtunctx)
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
    pub fn apply(&self, host: &mut VtunHost) {
        if self.encrypt_type != 0 {
            host.flags = host.flags | linkfd::VTUN_ENCRYPT;
            host.cipher = self.encrypt_type;
        } else {
            host.flags = host.flags & !linkfd::VTUN_ENCRYPT;
            host.cipher = 0;
        }
    }
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        ctx.syslog(lfd_mod::LOG_ERR, "Unexpected token after encrypt");
        self.set_failed(ctx);
        None
    }
}

impl ParsingContext for EncryptConfigParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        ctx.syslog(lfd_mod::LOG_ERR, "Parse error in encrypt");
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }

    fn token(&mut self, ctx: &VtunContext, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwNo => {
                if self.encrypt_type != -1 {
                    return self.unexpected_token(ctx);
                }
                self.encrypt_type = 0;
                None
            },
            Token::KwYes => {
                if self.encrypt_type != -1 {
                    return self.unexpected_token(ctx);
                }
                self.encrypt_type = lfd_mod::VTUN_ENC_BF128ECB;
                None
            },
            Token::Ident(ident) => {
                if self.encrypt_type != -1 {
                    return self.unexpected_token(ctx);
                }
                self.encrypt_type = match cipher_from_string(ident.as_str()) {
                    Ok(cipher) => cipher,
                    Err(_) => return self.unexpected_token(ctx)
                };
                None
            }
            Token::Semicolon => {
                if self.encrypt_type == -1 {
                    return self.unexpected_token(ctx);
                }
                self.parent.upgrade()
            }
            _ => {
                self.unexpected_token(ctx)
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
    pub fn apply(&self, host: &mut VtunHost) {
        host.flags = host.flags & !(linkfd::VTUN_TUN | linkfd::VTUN_ETHER | linkfd::VTUN_TTY | linkfd::VTUN_PIPE);
        host.flags = host.flags | self.type_value;
    }
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        ctx.syslog(lfd_mod::LOG_ERR, "Unexpected token after type");
        self.set_failed(ctx);
        None
    }
}

impl ParsingContext for TypeConfigParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        ctx.syslog(lfd_mod::LOG_ERR, "Parse error in type");
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }

    fn token(&mut self, ctx: &VtunContext, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwTun => {
                if self.type_value != -1 {
                    return self.unexpected_token(ctx);
                }
                self.type_value = linkfd::VTUN_TUN;
                None
            },
            Token::KwEther => {
                if self.type_value != -1 {
                    return self.unexpected_token(ctx);
                }
                self.type_value = linkfd::VTUN_ETHER;
                None
            },
            Token::KwTty => {
                if self.type_value != -1 {
                    return self.unexpected_token(ctx);
                }
                self.type_value = linkfd::VTUN_TTY;
                None
            },
            Token::KwPipe => {
                if self.type_value != -1 {
                    return self.unexpected_token(ctx);
                }
                self.type_value = linkfd::VTUN_PIPE;
                None
            },
            Token::Semicolon => {
                if self.type_value == -1 {
                    return self.unexpected_token(ctx);
                }
                self.parent.upgrade()
            }
            _ => {
                self.unexpected_token(ctx)
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
    pub fn apply(&self, host: &mut VtunHost) {
        host.flags = host.flags & !(linkfd::VTUN_TCP | linkfd::VTUN_UDP);
        host.flags = host.flags | self.proto_value;
    }
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        ctx.syslog(lfd_mod::LOG_ERR, "Unexpected token after proto");
        self.set_failed(ctx);
        None
    }
}

impl ParsingContext for ProtoConfigParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        ctx.syslog(lfd_mod::LOG_ERR, "Parse error in proto");
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }

    fn token(&mut self, ctx: &VtunContext, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwTcp => {
                if self.proto_value != -1 {
                    return self.unexpected_token(ctx);
                }
                self.proto_value = linkfd::VTUN_TCP;
                None
            },
            Token::KwUdp => {
                if self.proto_value != -1 {
                    return self.unexpected_token(ctx);
                }
                self.proto_value = linkfd::VTUN_UDP;
                None
            },
            Token::Semicolon => {
                if self.proto_value == -1 {
                    return self.unexpected_token(ctx);
                }
                self.parent.upgrade()
            }
            _ => {
                self.unexpected_token(ctx)
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
    pub fn apply(&self, host: &mut VtunHost) {
        host.ka_interval = self.keepalive_interval;
        host.ka_maxfail = self.keepalive_count;
    }
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        ctx.syslog(lfd_mod::LOG_ERR, "Unexpected token after keepalive");
        self.set_failed(ctx);
        None
    }
}

impl ParsingContext for KeepaliveConfigParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        ctx.syslog(lfd_mod::LOG_ERR, "Parse error in keepalive");
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }

    fn token(&mut self, ctx: &VtunContext, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwNo => {
                if self.interval_set || self.count_set {
                    return self.unexpected_token(ctx);
                }
                self.interval_set = true;
                self.keepalive_interval = -1;
                self.count_set = true;
                self.keepalive_count = -1;
                None
            },
            Token::KwYes => {
                if self.interval_set || self.count_set {
                    return self.unexpected_token(ctx);
                }
                self.keepalive_interval = 30;
                self.keepalive_count = 4;
                self.interval_set = true;
                self.count_set = true;
                None
            }
            Token::Number(num) => {
                if self.count_set {
                    return self.unexpected_token(ctx);
                }
                if self.interval_set {
                    self.keepalive_count = num as i32;
                    self.count_set = true;
                } else {
                    self.keepalive_interval = num as i32;
                    self.interval_set = true;
                }
                None
            },
            Token::Colon => {
                if self.sep_once {
                    return self.unexpected_token(ctx);
                }
                self.sep_once = true;
                None
            },
            Token::Semicolon => {
                if !self.interval_set || !self.count_set {
                    return self.unexpected_token(ctx);
                }
                self.parent.upgrade()
            }
            _ => {
                self.unexpected_token(ctx)
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
    fn apply(&self, host: &mut VtunHost) {
        host.flags = host.flags & !(lfd_mod::VTUN_NAT_HACK_CLIENT | lfd_mod::VTUN_NAT_HACK_SERVER);
        if self.nat_hack_client {
            host.flags = host.flags | lfd_mod::VTUN_NAT_HACK_CLIENT;
        }
        if self.nat_hack_server {
            host.flags = host.flags | lfd_mod::VTUN_NAT_HACK_SERVER;
        }
    }
    fn server(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        if self.nat_hack_disabled || self.nat_hack_server || self.nat_hack_client {
            return self.unexpected_token(ctx);
        }
        self.nat_hack_server = true;
        None
    }
    fn client(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        if self.nat_hack_disabled || self.nat_hack_server || self.nat_hack_client {
            return self.unexpected_token(ctx);
        }
        self.nat_hack_client = true;
        None
    }
    fn str(&mut self, ctx: &VtunContext, s: &str) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match s {
            "server" => self.server(ctx),
            "client" => self.client(ctx),
            "no" => {
                if self.nat_hack_disabled || self.nat_hack_server || self.nat_hack_client {
                    return self.unexpected_token(ctx);
                }
                self.nat_hack_disabled = true;
                None
            },
            _ => self.unexpected_token(ctx)
        }
    }
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        ctx.syslog(lfd_mod::LOG_ERR, "Unexpected token after nat_hack");
        self.set_failed(ctx);
        None
    }
}

impl ParsingContext for NatHackConfigParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        ctx.syslog(lfd_mod::LOG_ERR, "Parse error in nat_hack");
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }

    fn token(&mut self, vtunctx: &VtunContext, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwNo => {
                if self.nat_hack_disabled || self.nat_hack_server || self.nat_hack_client {
                    return self.unexpected_token(vtunctx);
                }
                self.nat_hack_disabled = true;
                None
            },
            Token::KwServer => self.server(vtunctx),
            Token::Ident(ident) => self.str(vtunctx, ident.as_str()),
            Token::Quoted(ident) => self.str(vtunctx, ident.as_str()),
            Token::Semicolon => {
                if !self.nat_hack_disabled && !self.nat_hack_server && !self.nat_hack_client {
                    return self.unexpected_token(vtunctx);
                }
                self.parent.upgrade()
            }
            _ => {
                self.unexpected_token(vtunctx)
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
    fn apply(&self, ctx: &mut VtunContext) {
        match self.options_ctx {
            None => {},
            Some(ref options_ctx) => options_ctx.lock().unwrap().apply(ctx)
        }
    }
}

impl ParsingContext for KwOptionsParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        ctx.syslog(lfd_mod::LOG_ERR, "Parse error in default");
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }
    fn token(&mut self, vtunctx: &VtunContext, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
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
                vtunctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                self.set_failed(vtunctx);
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
    shell_ctx: Option<Rc<Mutex<StringOptionParsingContext>>>,
    bindaddr_ctx: Option<Rc<Mutex<KwBindaddrConfigParsingContext>>>,
    persist_ctx: Option<Rc<Mutex<BoolOptionParsingContext>>>,
    syslog_ctx: Option<Rc<Mutex<SyslogOptionParsingContext>>>,
    experimental_ctx: Option<Rc<Mutex<BoolOptionParsingContext>>>,
    hardening_ctx: Vec<Rc<Mutex<HardeningOptionParsingContext>>>,
    setuid_ctx: Option<Rc<Mutex<KwSetuidSetgidConfigParsingContext>>>,
    setgid_ctx: Option<Rc<Mutex<KwSetuidSetgidConfigParsingContext>>>,
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
            shell_ctx: None,
            bindaddr_ctx: None,
            persist_ctx: None,
            syslog_ctx: None,
            experimental_ctx: None,
            hardening_ctx: Vec::new(),
            setuid_ctx: None,
            setgid_ctx: None,
        }
    }
    fn apply(&self, ctx: &mut VtunContext) {
        match self.port_ctx {
            None => {},
            Some(ref port_ctx) => ctx.vtun.bind_addr.port = port_ctx.lock().unwrap().value as libc::c_int
        }
        match self.timeout_ctx {
            None => {},
            Some(ref timeout_ctx) => ctx.vtun.timeout = timeout_ctx.lock().unwrap().value as libc::c_int
        }
        match self.ppp_ctx {
            None => {},
            Some(ref ppp_ctx) => {
                let ppp_ctx = ppp_ctx.lock().unwrap();
                ctx.vtun.ppp = Some(ppp_ctx.value.clone());
            }
        }
        match self.ifconfig_ctx {
            None => {},
            Some(ref ifconfig_ctx) => {
                let ifconfig_ctx = ifconfig_ctx.lock().unwrap();
                ctx.vtun.ifcfg = Some(ifconfig_ctx.value.clone());
            }
        }
        match self.route_ctx {
            None => {},
            Some(ref route_ctx) => {
                let route_ctx = route_ctx.lock().unwrap();
                ctx.vtun.route = Some(route_ctx.value.clone());
            }
        }
        match self.firewall_ctx {
            None => {},
            Some(ref firewall_ctx) => {
                let firewall_ctx = firewall_ctx.lock().unwrap();
                ctx.vtun.fwall = Some(firewall_ctx.value.clone());
            }
        }
        match self.ip_ctx {
            None => {},
            Some(ref ip_ctx) => {
                let ip_ctx = ip_ctx.lock().unwrap();
                ctx.vtun.iproute = Some(ip_ctx.value.clone());
            }
        }
        match self.shell_ctx {
            None => {},
            Some(ref shell_ctx) => {
                let shell_ctx = shell_ctx.lock().unwrap();
                ctx.vtun.shell = Some(shell_ctx.value.clone());
            }
        }
        match self.bindaddr_ctx {
            None => {},
            Some(ref bindaddr_ctx) => {
                let bindaddr_ctx = bindaddr_ctx.lock().unwrap();
                let mut bind_addr = ctx.vtun.bind_addr.clone();
                bindaddr_ctx.apply(ctx, &mut bind_addr);
                ctx.vtun.bind_addr = bind_addr;
            }
        }
        match self.persist_ctx {
            None => {},
            Some(ref persist_ctx) => ctx.vtun.persist = if persist_ctx.lock().unwrap().value { 1 } else { 0 }
        }
        match self.syslog_ctx {
            None => {},
            Some(ref syslog_ctx) => {
                ctx.vtun.syslog = syslog_ctx.lock().unwrap().value;
            }
        }
        match self.experimental_ctx {
            None => {},
            Some(ref experimental_ctx) => {
                ctx.vtun.experimental = experimental_ctx.lock().unwrap().value;
            }
        }
        for hardening_ctx in &self.hardening_ctx {
            let hardening_ctx = hardening_ctx.lock().unwrap();
            ctx.vtun.dropcaps |= hardening_ctx.dropcaps;
            ctx.vtun.setuid |= hardening_ctx.setuid;
            ctx.vtun.setgid |= hardening_ctx.setgid;
        }
        match self.setuid_ctx {
            None => {},
            Some(ref setuid_ctx) => {
                setuid_ctx.lock().unwrap().apply(ctx);
            }
        }
        match self.setgid_ctx {
            None => {},
            Some(ref setgid_ctx) => {
                setgid_ctx.lock().unwrap().apply(ctx);
            }
        }
    }
}

impl ParsingContext for OptionsConfigParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        ctx.syslog(lfd_mod::LOG_ERR, "Parse error in options section");
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }
    fn token(&mut self, vtunctx: &VtunContext, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwPort => {
                let port_ctx = Rc::new(Mutex::new(IntegerOptionParsingContext::new(Rc::clone(&ctx), "port")));
                self.port_ctx = Some(port_ctx.clone());
                Some(port_ctx)
            },
            Token::KwTimeout => {
                let timeout_ctx = Rc::new(Mutex::new(IntegerOptionParsingContext::new(Rc::clone(&ctx), "timeout")));
                self.timeout_ctx = Some(timeout_ctx.clone());
                Some(timeout_ctx)
            },
            Token::KwPpp => {
                let ppp_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "ppp")));
                self.ppp_ctx = Some(ppp_ctx.clone());
                Some(ppp_ctx)
            },
            Token::KwIfconfig => {
                let ifconfig_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "ifconfig")));
                self.ifconfig_ctx = Some(ifconfig_ctx.clone());
                Some(ifconfig_ctx)
            },
            Token::KwRoute => {
                let route_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "route")));
                self.route_ctx = Some(route_ctx.clone());
                Some(route_ctx)
            },
            Token::KwFirewall => {
                let firewall_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "firewall")));
                self.firewall_ctx = Some(firewall_ctx.clone());
                Some(firewall_ctx)
            },
            Token::KwIp => {
                let ip_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "ip")));
                self.ip_ctx = Some(ip_ctx.clone());
                Some(ip_ctx)
            },
            Token::KwShell => {
                let shell_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "shell")));
                self.shell_ctx = Some(shell_ctx.clone());
                Some(shell_ctx)
            },
            Token::KwBindaddr => {
                let bindaddr_ctx = Rc::new(Mutex::new(KwBindaddrConfigParsingContext::new(Rc::clone(&ctx), "bindaddr")));
                self.bindaddr_ctx = Some(bindaddr_ctx.clone());
                Some(bindaddr_ctx)
            },
            Token::KwPersist => {
                let persist_ctx = Rc::new(Mutex::new(BoolOptionParsingContext::new(Rc::clone(&ctx), "persist")));
                self.persist_ctx = Some(persist_ctx.clone());
                Some(persist_ctx)
            },
            Token::KwSyslog => {
                let syslog_ctx = Rc::new(Mutex::new(SyslogOptionParsingContext::new(Rc::clone(&ctx))));
                self.syslog_ctx = Some(syslog_ctx.clone());
                Some(syslog_ctx)
            },
            Token::KwExperimental => {
                let experimental_ctx = Rc::new(Mutex::new(BoolOptionParsingContext::new(Rc::clone(&ctx), "experimental")));
                self.experimental_ctx = Some(experimental_ctx.clone());
                Some(experimental_ctx)
            },
            Token::KwHardening => {
                let hardening_ctx = Rc::new(Mutex::new(HardeningOptionParsingContext::new(Rc::clone(&ctx))));
                self.hardening_ctx.push(hardening_ctx.clone());
                Some(hardening_ctx)
            },
            Token::KwSetuid => {
                let setuid_ctx = Rc::new(Mutex::new(KwSetuidSetgidConfigParsingContext::new(Rc::clone(&ctx), "setuid")));
                self.setuid_ctx = Some(setuid_ctx.clone());
                Some(setuid_ctx)
            },
            Token::KwSetgid => {
                let setuid_ctx = Rc::new(Mutex::new(KwSetuidSetgidConfigParsingContext::new(Rc::clone(&ctx), "setgid")));
                self.setgid_ctx = Some(setuid_ctx.clone());
                Some(setuid_ctx)
            },
            Token::Semicolon => None,
            Token::RBrace => {
                self.parent.upgrade()
            },
            _ => {
                vtunctx.syslog(lfd_mod::LOG_ERR, "Unexpected token in options section");
                self.set_failed(vtunctx);
                None
            }
        }
    }
}

struct KwBindaddrConfigParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    token_name: &'static str,
    bindaddr_ctx: Option<Rc<Mutex<BindaddrConfigParsingContext>>>
}

impl KwBindaddrConfigParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>, token_name: &'static str) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            token_name,
            bindaddr_ctx: None
        }
    }pub fn apply(&self, ctx: &VtunContext, bindaddr: &mut VtunAddr) {
        match self.bindaddr_ctx {
            None => {},
            Some(ref bindaddr_ctx) => bindaddr_ctx.lock().unwrap().apply(ctx, bindaddr)
        }
    }
}

impl ParsingContext for KwBindaddrConfigParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        let msg = format!("Parse error in {}", self.token_name);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }
    fn token(&mut self, vtunctx: &VtunContext, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
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
                vtunctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                self.set_failed(vtunctx);
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
    pub fn apply(&self, ctx: &VtunContext, bindaddr: &mut VtunAddr) {
        match self.iface_ctx {
            None => {},
            Some(ref iface_ctx) => {
                if self.addr_ctx.is_some() {
                    let msg = format!("In '{}' iface overrides addr", self.token_name);
                    ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                }
                bindaddr.name = Some(iface_ctx.lock().unwrap().value.clone());
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
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token afer {}", self.token_name);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.set_failed(ctx);
        None
    }
}

impl ParsingContext for BindaddrConfigParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        let msg = format!("Parse error in {}", self.token_name);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }
    fn token(&mut self, vtunctx: &VtunContext, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwAddr => {
                let addr_ctx = Rc::new(Mutex::new(AddrConfigParsingContext::new(Rc::clone(&ctx))));
                self.addr_ctx = Some(addr_ctx.clone());
                Some(addr_ctx)
            },
            Token::KwIface => {
                let iface_ctx = Rc::new(Mutex::new(StringOptionParsingContext::new(Rc::clone(&ctx), "iface")));
                self.iface_ctx = Some(iface_ctx.clone());
                Some(iface_ctx)
            },
            Token::RBrace => self.parent.upgrade(),
            _ => self.unexpected_token(vtunctx)
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
    pub fn apply(&self, bindaddr: &mut VtunAddr) {
        match self.hostname {
            Some(ref hostname) => {
                bindaddr.name = Some(hostname.clone());
                bindaddr.type_ = lfd_mod::VTUN_ADDR_NAME;
                return;
            }
            None => {}
        }
        match self.ipv4 {
            Some(ipv4) => {
                let ipv4 = format!("{}", std::net::Ipv4Addr::from(ipv4).to_string());
                bindaddr.ip = Some(ipv4);
            },
            None => {}
        }
    }
    fn hostname(&mut self, ctx: &VtunContext, hostname: String) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        if self.hostname.is_some() || self.ipv4.is_some() {
            return self.unexpected_token(ctx);
        }
        self.hostname = Some(hostname);
        None
    }
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        ctx.syslog(lfd_mod::LOG_ERR, "Unexpected token after addr");
        self.set_failed(ctx);
        None
    }
}

impl ParsingContext for AddrConfigParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        ctx.syslog(lfd_mod::LOG_ERR, "Parse error after addr");
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }
    fn token(&mut self, ctx: &VtunContext, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::IPv4(ipv4) => {
                if self.hostname.is_some() || self.ipv4.is_some() {
                    return self.unexpected_token(ctx);
                }
                self.ipv4 = Some(ipv4);
                None
            },
            Token::Ident(hostname) => self.hostname(ctx, hostname),
            Token::Quoted(hostname) => self.hostname(ctx, hostname),
            Token::Semicolon => {
                if self.hostname.is_none() && self.ipv4.is_none() {
                    return self.unexpected_token(ctx);
                }
                self.parent.upgrade()
            },
            _ => self.unexpected_token(ctx)
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
    fn handle_token(&mut self, ctx: &VtunContext, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        if self.is_set {
            return self.unexpected_token(ctx);
        }
        self.value = match token {
            Token::KwSyslog => libc::LOG_SYSLOG,
            _ => return self.unexpected_token(ctx)
        };
        self.is_set = true;
        None
    }
    fn str(&mut self, ctx: &VtunContext, s: &str) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        if self.is_set {
            return self.unexpected_token(ctx);
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
            _ => return self.unexpected_token(ctx)
        };
        self.is_set = true;
        None
    }
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        ctx.syslog(lfd_mod::LOG_ERR, "Unexpected token after syslog");
        self.set_failed(ctx);
        None
    }
}

impl ParsingContext for SyslogOptionParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        ctx.syslog(lfd_mod::LOG_ERR, "Parse error after syslog");
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }
    fn token(&mut self, vtunctx: &VtunContext, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::Ident(ident) => self.str(vtunctx, ident.as_str()),
            Token::Quoted(quoted) => self.str(vtunctx, quoted.as_str()),
            Token::Semicolon => {
                if !self.is_set {
                    return self.unexpected_token(vtunctx);
                }
                self.parent.upgrade()
            },
            _ => self.handle_token(vtunctx, token)
        }
    }
}

struct HardeningOptionParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    dropcaps: bool,
    setuid: bool,
    setgid: bool
}

impl HardeningOptionParsingContext {
    fn new(parent: Rc<Mutex<dyn ParsingContext>>) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            dropcaps: false,
            setuid: false,
            setgid: false
        }
    }
    fn handle_string(&mut self, ctx: &VtunContext, str: &str) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match str {
            "dropcaps" => {
                if self.dropcaps {
                    return self.unexpected_token(ctx);
                }
                self.dropcaps = true;
            },
            "setuid" => {
                if self.setuid {
                    return self.unexpected_token(ctx);
                }
                self.setuid = true;
            },
            "setgid" => {
                if self.setgid {
                    return self.unexpected_token(ctx);
                }
                self.setgid = true;
            },
            _ => return self.unexpected_token(ctx)
        }
        None
    }
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        ctx.syslog(lfd_mod::LOG_ERR, "Unexpected token after hardening");
        self.set_failed(ctx);
        None
    }
}
impl ParsingContext for HardeningOptionParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        ctx.syslog(lfd_mod::LOG_ERR, "Parse error after syslog");
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }

    fn token(&mut self, vtunctx: &VtunContext, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::Semicolon => {
                if !self.dropcaps && !self.setuid && !self.setgid {
                    return self.unexpected_token(vtunctx);
                }
                self.parent.upgrade()
            },
            Token::Ident(ident) => self.handle_string(vtunctx, ident.as_str()),
            Token::KwSetuid => self.handle_string(vtunctx, "setuid"),
            Token::KwSetgid => self.handle_string(vtunctx, "setgid"),
            Token::Quoted(str) => self.handle_string(vtunctx, str.as_str()),
            _ => self.unexpected_token(vtunctx)
        }
    }
}

struct KwSetuidSetgidConfigParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    ident: &'static str,
    uidgid: lfd_mod::SetUidIdentifier
}

impl KwSetuidSetgidConfigParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>, ident: &'static str) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            ident,
            uidgid: lfd_mod::SetUidIdentifier::Default
        }
    }
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after {}", self.ident);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.set_failed(ctx);
        None
    }
    fn string_token(&mut self, ctx: &VtunContext, str: &str) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        if !matches!(self.uidgid, lfd_mod::SetUidIdentifier::Default) {
            return self.unexpected_token(ctx);
        }
        self.uidgid = lfd_mod::SetUidIdentifier::Name(str.to_string());
        None
    }
    fn number_token(&mut self, ctx: &VtunContext, num: u64) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        if !matches!(self.uidgid, lfd_mod::SetUidIdentifier::Default) {
            return self.unexpected_token(ctx);
        }
        self.uidgid = lfd_mod::SetUidIdentifier::Id(num);
        None
    }
    pub fn apply(&self, vtun_ctx: &mut VtunContext) {
        match self.ident {
            "setuid" => {
                if !matches!(self.uidgid, lfd_mod::SetUidIdentifier::Default) {
                    vtun_ctx.vtun.setuid = true;
                }
                vtun_ctx.vtun.set_uid_user = self.uidgid.clone();
            },
            "setgid" => {
                if !matches!(self.uidgid, lfd_mod::SetUidIdentifier::Default) {
                    vtun_ctx.vtun.setgid = true;
                }
                vtun_ctx.vtun.set_gid_user = self.uidgid.clone();
            }
            _ => {}
        }
    }
}

impl ParsingContext for KwSetuidSetgidConfigParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        let msg = format!("Parse error in {}", self.ident);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }

    fn token(&mut self, vtunctx: &VtunContext, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::Ident(ident) => self.string_token(vtunctx, ident.as_str()),
            Token::Quoted(str) => self.string_token(vtunctx, str.as_str()),
            Token::Number(num) => self.number_token(vtunctx, num),
            Token::Semicolon => {
                if matches!(self.uidgid, lfd_mod::SetUidIdentifier::Default) {
                    return self.unexpected_token(vtunctx);
                }
                self.parent.upgrade()
            },
            _ => self.unexpected_token(vtunctx)
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
    pub fn apply(&self, vtun_ctx: &VtunContext, list: &mut Vec<VtunCmd>) {
        match self.updown_ctx {
            None => {},
            Some(ref ctx) => ctx.lock().unwrap().apply(vtun_ctx, list)
        }
    }
}

impl ParsingContext for KwUpDownParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        let msg = format!("Parse error in {}", self.ident);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }
    fn token(&mut self, vtunctx: &VtunContext, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
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
                vtunctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                self.set_failed(vtunctx);
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
    pub fn apply(&self, ctx: &VtunContext, list: &mut Vec<VtunCmd>) {
        for cmdmtx in self.cmds.iter() {
            let final_cmd;
            let final_args;
            let mut flags: libc::c_int = 0;
            {
                let cmd = cmdmtx.lock().unwrap();
                let perhaps_cmd = match match cmd.token {
                    Token::KwFirewall => &ctx.vtun.fwall,
                    Token::KwIp => &ctx.vtun.iproute,
                    Token::KwIfconfig => &ctx.vtun.ifcfg,
                    Token::KwPpp => &ctx.vtun.ppp,
                    Token::KwRoute => &ctx.vtun.route,
                    Token::KwProgram => &cmd.path,
                    _ => continue
                } {
                    Some(perhaps_cmd) => Some(perhaps_cmd.clone()),
                    None => None
                };
                let mut use_shell = false;
                final_cmd = match perhaps_cmd {
                    Some(cmd) => Some(cmd),
                    None => {
                        use_shell = true;
                        match ctx.vtun.shell {
                            Some(ref shell) => {
                                Some(shell.clone())
                            },
                            None => {
                                None
                            }
                        }
                    }
                };
                final_args = match cmd.args {
                    Some(ref args) => args.clone(),
                    None => "".to_string()
                };
                if cmd.wait {
                    flags = flags | linkfd::VTUN_CMD_WAIT;
                }
                if cmd.delay {
                    flags = flags | linkfd::VTUN_CMD_DELAY;
                }
                if use_shell {
                    flags = flags | linkfd::VTUN_CMD_SHELL;
                }
            }
            let cmdobj = VtunCmd {
                prog: final_cmd,
                args: Some(final_args),
                flags,
            };
            list.push(cmdobj);
        }
    }
}

impl ParsingContext for UpDownParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        let msg = format!("Parse error in {}", self.ident);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }
    fn token(&mut self, vtunctx: &VtunContext, ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
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
                vtunctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                self.set_failed(vtunctx);
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
    pub delay: bool
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
            delay: false
        }
    }
    fn handle_string(&mut self, ctx: &VtunContext, str: &str) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match &self.args {
            Some(_) => match str {
                "wait" => {
                    if self.wait {
                        return self.unexpected_token(ctx);
                    }
                    self.wait = true;
                    None
                },
                "delay" => {
                    if self.delay {
                        return self.unexpected_token(ctx);
                    }
                    self.delay = true;
                    None
                },
                _ => {
                    if matches!(self.token, Token::KwProgram) && self.path.is_none() {
                        self.path = self.args.clone();
                        self.args = Some(str.to_string());
                        return None;
                    }
                    self.unexpected_token(ctx)
                }
            },
            None => {
                self.args = Some(str.to_string());
                None
            }
        }
    }
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after {}", self.token_name);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.set_failed(ctx);
        None
    }
}

impl ParsingContext for CommandConfigParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        let msg = format!("Parse error in {}", self.token_name);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }

    fn token(&mut self, vtunctx: &VtunContext, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::Ident(ident) => self.handle_string(vtunctx, ident.as_str()),
            Token::Quoted(quoted) => self.handle_string(vtunctx, quoted.as_str()),
            Token::Semicolon => {
                match &self.args {
                    None => self.unexpected_token(vtunctx),
                    Some(_) => self.parent.upgrade()
                }
            }
            _ => {
                self.unexpected_token(vtunctx)
            }
        }
    }
}

struct KwRequiresParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    flags: vtun_host::RequiresFlags
}

impl KwRequiresParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            flags: vtun_host::RequiresFlags::NONE
        }
    }
    fn handle_string(&mut self, vtunctx: &VtunContext, str: &str) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match str {
            "client" => {
                self.flags = self.flags | vtun_host::RequiresFlags::CLIENT_ONLY;
                None
            },
            "bidirauth" => {
                self.flags = self.flags | vtun_host::RequiresFlags::BIDIRECTIONAL_AUTH;
                None
            },
            "encryption" => {
                self.flags = self.flags | vtun_host::RequiresFlags::ENCRYPTION;
                None
            },
            "integrity" => {
                self.flags = self.flags | vtun_host::RequiresFlags::INTEGRITY_PROTECTION;
                None
            },
            "3.1" => {
                self.flags = self.flags | vtun_host::RequiresFlags::BIDIRECTIONAL_AUTH;
                None
            },
            _ => self.unexpected_token(vtunctx)
        }
    }
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        ctx.syslog(lfd_mod::LOG_ERR, "Unexpected token after requires");
        self.set_failed(ctx);
        None
    }
}

impl ParsingContext for KwRequiresParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        ctx.syslog(lfd_mod::LOG_ERR, "Parse error in requires");
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }

    fn token(&mut self, vtunctx: &VtunContext, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::Ident(str) => self.handle_string(vtunctx, str.as_str()),
            Token::Quoted(str) => self.handle_string(vtunctx, str.as_str()),
            Token::Semicolon => {
                if self.flags == 0 {
                    return self.unexpected_token(vtunctx);
                }
                self.parent.upgrade()
            }
            _ => {
                self.unexpected_token(vtunctx)
            }
        }
    }
}

struct KwAcceptEncryptParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    ciphers: Vec<i32>
}

impl KwAcceptEncryptParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            ciphers: Vec::new()
        }
    }
    fn handle_string(&mut self, vtunctx: &VtunContext, str: &str) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let cipher = match cipher_from_string(str) {
            Ok(cipher) => cipher,
            Err(_) => return self.unexpected_token(vtunctx)
        };
        if !self.ciphers.contains(&cipher) {
            self.ciphers.push(cipher);
        }
        None
    }
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        ctx.syslog(lfd_mod::LOG_ERR, "Unexpected token after requires");
        self.set_failed(ctx);
        None
    }
}

impl ParsingContext for KwAcceptEncryptParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        ctx.syslog(lfd_mod::LOG_ERR, "Parse error in requires");
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }

    fn token(&mut self, vtunctx: &VtunContext, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::Ident(str) => self.handle_string(vtunctx, str.as_str()),
            Token::Quoted(str) => self.handle_string(vtunctx, str.as_str()),
            Token::Semicolon => {
                if self.ciphers.is_empty() {
                    return self.unexpected_token(vtunctx);
                }
                self.parent.upgrade()
            }
            _ => {
                self.unexpected_token(vtunctx)
            }
        }
    }
}

struct IntegerOptionParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    token_name: &'static str,
    value: i32,
    is_set: bool
}

impl IntegerOptionParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>, token_name: &'static str) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            token_name,
            value: -1,
            is_set: false
        }
    }
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after {}", self.token_name);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.set_failed(ctx);
        None
    }
}

impl ParsingContext for IntegerOptionParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        let msg = format!("Parse error in {}", self.token_name);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }

    fn token(&mut self, vtunctx: &VtunContext, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::Number(value) => {
                if self.is_set {
                    return self.unexpected_token(vtunctx);
                }
                self.value = value as i32;
                self.is_set = true;
                None
            },
            Token::Semicolon => {
                if !self.is_set {
                    return self.unexpected_token(vtunctx);
                }
                self.parent.upgrade()
            }
            _ => {
                self.unexpected_token(vtunctx)
            }
        }
    }
}

struct StringOptionParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    token_name: &'static str,
    value: String,
    is_set: bool
}

impl StringOptionParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>, token_name: &'static str) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            token_name,
            value: "".to_string(),
            is_set: false
        }
    }
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after {}", self.token_name);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.set_failed(ctx);
        None
    }
}

impl ParsingContext for StringOptionParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        let msg = format!("Parse error in {}", self.token_name);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }

    fn token(&mut self, vtunctx: &VtunContext, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::Ident(value) => {
                if self.is_set {
                    return self.unexpected_token(vtunctx);
                }
                self.value = value.to_string();
                self.is_set = true;
                None
            },
            Token::Quoted(value) => {
                if self.is_set {
                    return self.unexpected_token(vtunctx);
                }
                self.value = value;
                self.is_set = true;
                None
            },
            Token::Semicolon => {
                if !self.is_set {
                    return self.unexpected_token(vtunctx);
                }
                self.parent.upgrade()
            }
            _ => {
                self.unexpected_token(vtunctx)
            }
        }
    }
}

struct BoolOptionParsingContext {
    parent: Weak<Mutex<dyn ParsingContext>>,
    token_name: &'static str,
    value: bool,
    is_set: bool
}

impl BoolOptionParsingContext {
    pub fn new(parent: Rc<Mutex<dyn ParsingContext>>, token_name: &'static str) -> Self {
        Self {
            parent: Rc::downgrade(&parent),
            token_name,
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
    fn unexpected_token(&mut self, ctx: &VtunContext) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        let msg = format!("Unexpected token after {}", self.token_name);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        self.set_failed(ctx);
        None
    }
}

impl ParsingContext for BoolOptionParsingContext {
    fn set_failed(&mut self, ctx: &VtunContext) {
        let msg = format!("Parse error in {}", self.token_name);
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        match self.parent.upgrade() {
            Some(parent) => parent.lock().unwrap().set_failed(ctx),
            None => {}
        }
    }

    fn token(&mut self, vtunctx: &VtunContext, _ctx: &Rc<Mutex<dyn ParsingContext>>, token: Token) -> Option<Rc<Mutex<dyn ParsingContext>>> {
        match token {
            Token::KwYes => self.yes(),
            Token::KwNo => self.no(),
            Token::Quoted(value) => {
                match value.as_str() {
                    "yes" => self.yes(),
                    "no" => self.no(),
                    _ => self.unexpected_token(vtunctx)
                }
            },
            Token::Semicolon => {
                if !self.is_set {
                    return self.unexpected_token(vtunctx);
                }
                self.parent.upgrade()
            }
            _ => {
                self.unexpected_token(vtunctx)
            }
        }
    }
}

impl VtunConfigRoot {
    pub fn new(vtun_ctx: &mut VtunContext, file: &str) -> Option<Self> {
        let content = match fs::read_to_string(file) {
            Ok(c) => c,
            Err(_) => {
                let msg = format!("Failed to read config file '{}'", file);
                vtun_ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                return None;
            }
        };
        Self::new_from_string(vtun_ctx, content.as_str())
    }
    pub fn new_from_string(vtun_ctx: &mut VtunContext, content: &str) -> Option<Self> {
        let rootctx = Rc::new(Mutex::new(RootParsingContext::new()));
        {
            let mut ctx: Rc<Mutex<dyn ParsingContext>> = rootctx.clone();
            let mut lexer = Token::lexer(content);
            while let Some(result) = lexer.next() {
                match result {
                    Ok(token) => {
                        let mut nctx = None;
                        {
                            let mut mctx = ctx.lock().unwrap();
                            match token {
                                Token::_Comment => {},
                                _ => {
                                    nctx = mctx.token(vtun_ctx, &ctx, token);
                                }
                            }
                        }
                        {
                            let rctx = rootctx.lock().unwrap();
                            if rctx.failed {
                                let msg = format!("Parse error at: {}", lexer.slice());
                                vtun_ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
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
                        vtun_ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                        return None;
                    }
                }
            }
            let mctx = ctx.lock().unwrap();
            if !mctx.end_of_file_ok() {
                vtun_ctx.syslog(lfd_mod::LOG_ERR, "Parse error at: End of file");
                return None;
            }
        }
        let parsed = rootctx.lock().unwrap();
        parsed.apply(vtun_ctx);

        let root = VtunConfigRoot {
            host_list: parsed.get_hosts(vtun_ctx)
        };

        Some(root)
    }
    pub fn clear_nat_hack_flags(&mut self, server: bool) {
        for host in &mut self.host_list {
            if server {
                host.clear_nat_hack_server();
            } else {
                host.clear_nat_hack_client();
            }
        }
    }
    pub fn find_host(&self, name: &str) -> Option<&VtunHost> {
        for host in &self.host_list {
            if host.host_name() == name {
                return Some(host);
            }
        }
        None
    }
}

#[cfg(test)]
fn test_context() -> VtunContext {
    VtunContext {
        config: None,
        vtun: VtunOpts {
            timeout: 0,
            persist: 0,
            cfg_file: None,
            shell: None,
            ppp: None,
            ifcfg: None,
            route: None,
            fwall: None,
            iproute: None,
            svr_name: None,
            svr_addr: None,
            bind_addr: VtunAddr {
                name: None,
                ip: None,
                port: 0,
                type_: 0,
            },
            svr_type: 0,
            syslog: 0,
            log_to_syslog: false,
            quiet: 0,
            set_uid_user: lfd_mod::SetUidIdentifier::Default,
            set_gid_user: lfd_mod::SetUidIdentifier::Default,
            experimental: false,
            dropcaps: false,
            setuid: false,
            setgid: false,
        },
        is_rmt_fd_connected: false,
    }
}

#[cfg(test)]
#[test]
fn test_not_dropcaps_and_not_setuid() {
    let test_config = "options {
    };";
    let mut ctx = test_context();
    assert!(match VtunConfigRoot::new_from_string(&mut ctx, test_config) {
        Some(_) => true,
        None => false
    });
    assert!(!ctx.vtun.dropcaps);
    assert!(!ctx.vtun.setuid);
    assert!(!ctx.vtun.setgid);
}

#[cfg(test)]
#[test]
fn test_dropcaps_and_not_setuid() {
    let test_config = "options {
        hardening dropcaps;
    };";
    let mut ctx = test_context();
    assert!(match VtunConfigRoot::new_from_string(&mut ctx, test_config) {
        Some(_) => true,
        None => false
    });
    assert!(ctx.vtun.dropcaps);
    assert!(!ctx.vtun.setuid);
    assert!(!ctx.vtun.setgid);
}

#[cfg(test)]
#[test]
fn test_setuid_and_not_dropcaps() {
    let test_config = "options {
        hardening setuid;
    };";
    let mut ctx = test_context();
    assert!(match VtunConfigRoot::new_from_string(&mut ctx, test_config) {
        Some(_) => true,
        None => false
    });
    assert!(ctx.vtun.setuid);
    assert!(!ctx.vtun.dropcaps);
}

#[cfg(test)]
#[test]
fn test_setgid_and_not_dropcaps() {
    let test_config = "options {
        hardening setgid;
    };";
    let mut ctx = test_context();
    assert!(match VtunConfigRoot::new_from_string(&mut ctx, test_config) {
        Some(_) => true,
        None => false
    });
    assert!(!ctx.vtun.setuid);
    assert!(ctx.vtun.setgid);
    assert!(!ctx.vtun.dropcaps);
}

#[cfg(test)]
#[test]
fn test_setuid_and_dropcaps() {
    let test_config = "options {
        hardening setuid dropcaps;
    };";
    let mut ctx = test_context();
    assert!(match VtunConfigRoot::new_from_string(&mut ctx, test_config) {
        Some(_) => true,
        None => false
    });
    assert!(ctx.vtun.setuid);
    assert!(ctx.vtun.dropcaps);
}

#[cfg(test)]
#[test]
fn test_setuid_and_dropcaps2() {
    let test_config = "options {
        hardening setuid;
        hardening dropcaps;
    };";
    let mut ctx = test_context();
    assert!(match VtunConfigRoot::new_from_string(&mut ctx, test_config) {
        Some(_) => true,
        None => false
    });
    assert!(ctx.vtun.setuid);
    assert!(ctx.vtun.dropcaps);
}

#[cfg(test)]
#[test]
fn test_setuid_nobody() {
    let test_config = "options {
        setuid nobody;
    };";
    let mut ctx = test_context();
    assert!(match VtunConfigRoot::new_from_string(&mut ctx, test_config) {
        Some(_) => true,
        None => false
    });
    assert!(ctx.vtun.setuid);
    assert!(!ctx.vtun.setgid);
    assert!(match ctx.vtun.set_uid_user {
        lfd_mod::SetUidIdentifier::Name(name) => name == "nobody",
        _ => false
    });
}

#[cfg(test)]
#[test]
fn test_setgid_nobody() {
    let test_config = "options {
        setgid nobody;
    };";
    let mut ctx = test_context();
    assert!(match VtunConfigRoot::new_from_string(&mut ctx, test_config) {
        Some(_) => true,
        None => false
    });
    assert!(!ctx.vtun.setuid);
    assert!(ctx.vtun.setgid);
    assert!(match ctx.vtun.set_gid_user {
        lfd_mod::SetUidIdentifier::Name(name) => name == "nobody",
        _ => false
    });
}

#[cfg(test)]
#[test]
fn test_cfg_host_requires_client_encryption_bidirauth_integrity() {
    let test_config = "hostconf {
        requires client encryption bidirauth integrity;
    };";
    let mut ctx = test_context();
    ctx.config = VtunConfigRoot::new_from_string(&mut ctx, test_config);
    assert!(ctx.config.is_some());
    let config = &ctx.config.unwrap();
    let hostcfg = config.find_host("hostconf");
    assert!(hostcfg.is_some());
    let hostcfg = hostcfg.unwrap();
    assert!((hostcfg.requires & vtun_host::RequiresFlags::CLIENT_ONLY) != 0);
    assert!((hostcfg.requires & vtun_host::RequiresFlags::BIDIRECTIONAL_AUTH) != 0);
    assert!((hostcfg.requires & vtun_host::RequiresFlags::ENCRYPTION) != 0);
    assert!((hostcfg.requires & vtun_host::RequiresFlags::INTEGRITY_PROTECTION) != 0);
}

#[cfg(test)]
#[test]
fn test_cfg_host_requires_3_1() {
    let test_config = "hostconf {
        requires \"3.1\";
    };";
    let mut ctx = test_context();
    ctx.config = VtunConfigRoot::new_from_string(&mut ctx, test_config);
    assert!(ctx.config.is_some());
    let config = &ctx.config.unwrap();
    let hostcfg = config.find_host("hostconf");
    assert!(hostcfg.is_some());
    let hostcfg = hostcfg.unwrap();
    assert!(hostcfg.requires == vtun_host::RequiresFlags::BIDIRECTIONAL_AUTH);
}

#[cfg(test)]
#[test]
fn test_cfg_host_requires_integrity_with_wrong_cipher() {
    let test_config = "hostconf {
        encrypt aes256cbc;
        requires integrity;
    };";
    let mut ctx = test_context();
    ctx.config = VtunConfigRoot::new_from_string(&mut ctx, test_config);
    assert!(ctx.config.is_some());
    let config = &ctx.config.unwrap();
    let hostcfg = config.find_host("hostconf");
    assert!(hostcfg.is_some());
    let hostcfg = hostcfg.unwrap();
    assert!(hostcfg.requires == (vtun_host::RequiresFlags::INTEGRITY_PROTECTION | vtun_host::RequiresFlags::CLIENT_ONLY));
}


#[cfg(test)]
#[test]
fn test_cfg_host_requires_integrity_without_cipher() {
    let test_config = "hostconf {
        requires integrity;
    };";
    let mut ctx = test_context();
    ctx.config = VtunConfigRoot::new_from_string(&mut ctx, test_config);
    assert!(ctx.config.is_some());
    let config = &ctx.config.unwrap();
    let hostcfg = config.find_host("hostconf");
    assert!(hostcfg.is_some());
    let hostcfg = hostcfg.unwrap();
    assert!(hostcfg.requires == (vtun_host::RequiresFlags::INTEGRITY_PROTECTION | vtun_host::RequiresFlags::CLIENT_ONLY));
}

#[cfg(test)]
#[test]
fn test_cfg_host_requires_encryption_without_cipher() {
    let test_config = "hostconf {
        requires encryption;
    };";
    let mut ctx = test_context();
    ctx.config = VtunConfigRoot::new_from_string(&mut ctx, test_config);
    assert!(ctx.config.is_some());
    let config = &ctx.config.unwrap();
    let hostcfg = config.find_host("hostconf");
    assert!(hostcfg.is_some());
    let hostcfg = hostcfg.unwrap();
    assert!(hostcfg.requires == (vtun_host::RequiresFlags::ENCRYPTION | vtun_host::RequiresFlags::CLIENT_ONLY));
}

#[cfg(test)]
#[test]
fn test_cfg_host_requires_encryption_and_integrity_without_cipher() {
    let test_config = "hostconf {
        requires encryption integrity;
    };";
    let mut ctx = test_context();
    ctx.config = VtunConfigRoot::new_from_string(&mut ctx, test_config);
    assert!(ctx.config.is_some());
    let config = &ctx.config.unwrap();
    let hostcfg = config.find_host("hostconf");
    assert!(hostcfg.is_some());
    let hostcfg = hostcfg.unwrap();
    assert!(hostcfg.requires == (vtun_host::RequiresFlags::ENCRYPTION | vtun_host::RequiresFlags::INTEGRITY_PROTECTION | vtun_host::RequiresFlags::CLIENT_ONLY));
}

#[cfg(test)]
#[test]
fn test_cfg_no_accept_encrypt() {
    let test_config = "hostconf {
    };";
    let mut ctx = test_context();
    ctx.config = VtunConfigRoot::new_from_string(&mut ctx, test_config);
    assert!(ctx.config.is_some());
    let config = &ctx.config.unwrap();
    let hostcfg = config.find_host("hostconf");
    assert!(hostcfg.is_some());
    let hostcfg = hostcfg.unwrap();
    assert!(hostcfg.accepted_cipher.is_none());
}

#[cfg(test)]
#[test]
fn test_cfg_accept_encrypt() {
    let test_config = "hostconf {
        accept_encrypt aes128cbc;
        accept_encrypt aes256cbc;
        accept_encrypt aes128gcm aes256gcm;
        accept_encrypt aes256ofb;
        accept_encrypt aes256ofb;
    };";
    let mut ctx = test_context();
    ctx.config = VtunConfigRoot::new_from_string(&mut ctx, test_config);
    assert!(ctx.config.is_some());
    let config = &ctx.config.unwrap();
    let hostcfg = config.find_host("hostconf");
    assert!(hostcfg.is_some());
    let hostcfg = hostcfg.unwrap();
    assert!(hostcfg.accepted_cipher.is_some());
    let accepted_cipher = match hostcfg.accepted_cipher {
        Some(ref accepted_cipher) => accepted_cipher,
        None => panic!("accepted_cipher is None")
    };
    assert!(!accepted_cipher.is_empty());
    assert!(!accepted_cipher.contains(&cipher_from_string("aes128ecb").unwrap()));
    assert!(accepted_cipher.contains(&cipher_from_string("aes128cbc").unwrap()));
    assert!(accepted_cipher.contains(&cipher_from_string("aes256cbc").unwrap()));
    assert!(accepted_cipher.contains(&cipher_from_string("aes128gcm").unwrap()));
    assert!(accepted_cipher.contains(&cipher_from_string("aes256gcm").unwrap()));
    assert!(accepted_cipher.contains(&cipher_from_string("aes256ofb").unwrap()));
    assert!(accepted_cipher.len() == 5);
}
