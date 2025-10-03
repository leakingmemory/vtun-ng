/*
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2016  Maxim Krasnyansky <max_mk@yahoo.com>
    Copyright (C) 2025 Jan-Espen Oversand <sigsegv@radiotube.org>

    VTun has been derived from VPPP package by Maxim Krasnyansky.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 */

/* ZLIB compression module */
#[cfg(feature = "zlib")]
use std::io::Write;
use crate::{lfd_mod, vtun_host};
use crate::linkfd::{LfdMod, LfdModFactory};
use crate::mainvtun::VtunContext;
use crate::syslog::SyslogObject;

#[cfg(feature = "zlib")]
struct LfdZlib {
    pub encoder: flate2::write::ZlibEncoder<Vec<u8>>,
    pub decoder: flate2::write::ZlibDecoder<Vec<u8>>
}

#[cfg(feature = "zlib")]
impl LfdZlib {
    pub fn new(ctx: &VtunContext, host: &vtun_host::VtunHost) -> LfdZlib {
        ctx.syslog(lfd_mod::LOG_INFO, "ZLIB compression initialized");
        LfdZlib {
            encoder: flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(host.zlevel as u32)),
            decoder: flate2::write::ZlibDecoder::new(Vec::new())
        }
    }
}

pub(crate) struct LfdZlibFactory {
}

impl LfdZlibFactory {
    pub fn new() -> LfdZlibFactory {
        LfdZlibFactory {
        }
    }
}
#[cfg(feature = "zlib")]
impl LfdModFactory for LfdZlibFactory {
    fn create(&self, ctx: &VtunContext, host: &mut vtun_host::VtunHost) -> Result<Box<dyn LfdMod>,i32> {
        Ok(Box::new(LfdZlib::new(ctx, host)))
    }
}

#[cfg(not(feature = "zlib"))]
impl LfdModFactory for LfdZlibFactory {
    fn create(&self, ctx: &VtunContext, _host: &mut vtun_host::VtunHost) -> Result<Box<dyn LfdMod>,i32> {
        ctx.syslog(lfd_mod::LOG_ERR, "ZLIB compression is not supported, rebuild with zlib enabled");
        Err(2)
    }
}

#[cfg(feature = "zlib")]
impl LfdMod for LfdZlib {
    fn encode(&mut self, ctx: &VtunContext, buf: &mut Vec<u8>) -> Result<(),()> {
        match self.encoder.write_all(buf) {
            Ok(_) => (),
            Err(_) => {
                ctx.syslog(lfd_mod::LOG_ERR, "ZLIB compression error");
                return Err(())
            }
        };
        match self.encoder.flush() {
            Ok(()) => {},
            Err(_) => {
                ctx.syslog(lfd_mod::LOG_ERR, "ZLIB compression error (flush failed)");
                return Err(())
            },
        };
        buf.resize(self.encoder.get_ref().len(), 0u8);
        for i in 0..buf.len() {
            buf[i] = self.encoder.get_ref()[i];
        }
        self.encoder.get_mut().clear();
        Ok(())
    }
    fn decode(&mut self, ctx: &VtunContext, buf: &mut Vec<u8>) -> Result<(),()> {
        match self.decoder.write_all(buf) {
            Ok(_) => (),
            Err(_) => {
                ctx.syslog(lfd_mod::LOG_ERR, "ZLIB decompression error");
                return Err(());
            }
        };
        match self.decoder.flush() {
            Ok(()) => {},
            Err(_) => {
                ctx.syslog(lfd_mod::LOG_ERR, "ZLIB decompression error (flush failed)");
                return Err(())
            },
        };
        buf.resize(self.decoder.get_ref().len(), 0u8);
        for i in 0..buf.len() {
            buf[i] = self.decoder.get_ref()[i];       
        }
        self.decoder.get_mut().clear();
        Ok(())
    }

    fn request_send(&mut self) -> bool {
        false
    }
}
