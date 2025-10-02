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
use std::io::{PipeReader, PipeWriter, Read, Write};
#[cfg(test)]
use std::sync::{Arc, Condvar};
#[cfg(test)]
use std::sync::Mutex;
#[cfg(test)]
use std::thread;
use libc::time_t;
use crate::filedes::FileDes;
use crate::linkfd::LinkfdCtx;
use crate::mainvtun::VtunContext;
#[cfg(test)]
use crate::{cfg_file, mainvtun};
use crate::{auth, challenge, challenge2, lfd_mod, libfuncs, setproctitle, vtun_host};
use crate::auth::VTUN_MESG_SIZE;
use crate::challenge2::mix_in_bytes;
use crate::challenge::VTUN_CHAL_SIZE;
use crate::exitcode::ExitCode;
use crate::libfuncs::print_p;
use crate::lowpriv::{run_lowpriv_section, LowprivReturnable};
use crate::syslog::SyslogObject;
use crate::vtun_host::RequiresFlags;

trait ToWireForm {
    fn size_for_to_wire_form(&self) -> usize;
    fn to_wire_form(&self, buf: &mut [u8]);
}

trait FromWireForm {
    fn size_for_to_binary_form(&self) -> usize;
    fn to_binary_form(&self, buf: &mut [u8]) -> Result<(),()>;
}

impl ToWireForm for [u8] {
    fn size_for_to_wire_form(&self) -> usize {
        self.len()*2+2
    }
    fn to_wire_form(&self, buf: &mut [u8]) {
        buf[0] = b'<';
        buf[self.len()*2+1] = b'>';
        for i in 0..self.len() {
            buf[i*2+1] = (self[i] >> 4) + b'a';
            buf[i*2+2] = (self[i] & 0xf) + b'a';
        }
    }
}

impl FromWireForm for [u8] {
    fn size_for_to_binary_form(&self) -> usize {
        if self.len() < 2 {
            return 0;
        }
        let payload = self.len()-2;
        let remainder = payload % 2;
        (payload / 2) + remainder
    }
    fn to_binary_form(&self, buf: &mut [u8]) -> Result<(),()> {
        if self[self.len()-1] != b'>' || self[0] != b'<' {
            return Err(());
        }
        for i in 1..self.len()-1 {
            if (i & 1) == 0 {
                let ind = (i-1)/2;
                let mut val = self[i];
                if val < b'a' {
                    return Err(());
                }
                val = val - b'a';
                if val > 0xf {
                    return Err(());
                }
                buf[ind] |= val;
            } else {
                let ind = (i-1)/2;
                buf[ind] = self[i];
                if buf[ind] < b'a' {
                    return Err(());
                }
                buf[ind] -= b'a';
                if buf[ind] > 0xf {
                    return Err(());
                }
                buf[ind] <<= 4;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[test]
fn test_to_wire_form() {
    let mut orig = [0u8; 256];
    let mut wire = [0u8; 514];
    for i in 0..255 {
        let orig = &mut orig[0..i];
        for j in 0..i {
            orig[j] = j as u8;
        }
        let wire = &mut wire[0..orig.size_for_to_wire_form()];
        for i in 0..wire.len() {
            wire[i] = 0;
        }
        orig.to_wire_form(wire);
        for i in 0..orig.len() {
            orig[i] = 0;
        }
        assert_eq!(orig.len(), wire.size_for_to_binary_form());
        wire.to_binary_form(orig).unwrap();
        for i in 0..orig.len() {
            assert_eq!(orig[i], i as u8);
        }
    }
}

fn zeropad_to_slice(slice: &mut [u8], msgparts: &[&[u8]]) {
    let mut off: usize = 0;
    let mut remaining = slice.len();
    for part in msgparts {
        let mut partlen = part.len();
        if partlen > remaining {
            partlen = remaining;
        }
        remaining -= partlen;
        for i in 0..partlen {
            slice[off+i] = part[i];
        }
        off += partlen;
    }
}

trait AuthCandidateConnection {
    fn write(&self, buf: &[u8]) -> Result<(),()>;
    fn read_timeout_zeropad(&self, buf: &mut [u8], linkfdctx: &LinkfdCtx, timeout: time_t) -> Result<(), ()>;
}

fn write(fd: &FileDes, buf: &[u8]) -> Result<(), ()> {
    match fd.write(buf) {
        Ok(written) => {
            if written < buf.len() {
                return write(fd, &buf[written..]);
            }
            Ok(())
        },
        Err(_) => Err(())
    }
}

impl AuthCandidateConnection for FileDes {
    fn write(&self, buf: &[u8]) -> Result<(), ()> {
        write(self, buf)
    }
    fn read_timeout_zeropad(&self, buf: &mut [u8], linkfdctx: &LinkfdCtx, timeout: time_t) -> Result<(), ()> {
        let rd = libfuncs::readn_t(linkfdctx, self, buf, timeout);
        if rd <= 0 {
            return Err(());
        }
        let len = buf.len();
        if (rd as usize) < len {
            for i in (rd as usize)..len {
                buf[i] = 0;
            }
        }
        Ok(())
    }
}

/*
 * The purpose of this data object is to make sure that the decision
 * to allow a connection is not accidental. The authentication might
 * run in a low privileged child process, and only if this object
 * holds a valid digest together with the expected service name the
 * connection is allowed.
 */
pub(crate) struct AuthDecision {
    pub(crate) service_name: String,
    pub(crate) passwd_digest: [u8; 32]
}

impl LowprivReturnable<AuthDecision> for AuthDecision {
    fn write_to_pipe(&self, w: &mut PipeWriter) -> Result<(), ()> {
        match w.write_all(self.passwd_digest.as_ref()) {
            Ok(_) => {},
            Err(_) => return Err(())
        };
        let service_name_len: u64 = self.service_name.as_bytes().len() as u64;
        match w.write_all(&service_name_len.to_ne_bytes()) {
            Ok(_) => {},
            Err(_) => return Err(())
        };
        match w.write_all(self.service_name.as_bytes()) {
            Ok(_) => Ok(()),
            Err(_) => Err(())
        }
    }

    fn read_from_pipe(r: &mut PipeReader) -> Result<AuthDecision, ()> {
        let mut passwd_digest: [u8; 32] = [0u8; 32];
        match r.read_exact(&mut passwd_digest) {
            Ok(_) => {},
            Err(_) => return Err(())
        };
        let mut service_name_len: [u8; 8] = [0u8; 8];
        match r.read_exact(&mut service_name_len) {
            Ok(_) => {},
            Err(_) => return Err(())
        };
        let service_name_len: u64 = u64::from_ne_bytes(service_name_len);
        let mut service_name = Vec::<u8>::new();
        service_name.resize(service_name_len as usize, 0u8);
        match r.read_exact(&mut service_name) {
            Ok(_) => {},
            Err(_) => return Err(())
        };
        let service_name = String::from_utf8_lossy(service_name.as_ref()).to_string();
        Ok(AuthDecision {
            service_name,
            passwd_digest
        })
    }
}

pub fn auth_server(ctx: &mut VtunContext, linkfdctx: &LinkfdCtx, fd: &FileDes) -> Result<vtun_host::VtunHost,ExitCode> {
    setproctitle::set_title("protocol negotiation");
    let experimental_enabled = ctx.vtun.experimental;
    let greeting;
    if experimental_enabled {
        greeting = format!("VTUN server ver {}\n", lfd_mod::VTUN_EXPERIMENTAL_VER);
        ctx.syslog(lfd_mod::LOG_WARNING, "Experimental mode enabled, compatibility is not guaranteed");
    } else {
        greeting = format!("VTUN server ver {}\n", lfd_mod::VTUN_VER);
    }
    let salt = challenge2::gen_digest_salt();
    let mut is_forked = false;
    let decision: Result<AuthDecision,ExitCode> = run_lowpriv_section(ctx, "authentication", &mut is_forked, &mut |ctx: &mut VtunContext| -> Result<AuthDecision,()> {
        print_p(fd, greeting.as_bytes());

        let mut buf = [0u8; VTUN_MESG_SIZE];
        if libfuncs::readn_t(linkfdctx, fd, &mut buf, ctx.vtun.timeout as time_t + 1) <= 0 {
            ctx.syslog(lfd_mod::LOG_ERR, "Read from client failed, terminating connection");
            return Err(());
        }

        let mut auth2_enabled = true;
        buf[3] = match buf[3] {
            b'T' => {
                auth2_enabled = false;
                b'T'
            },
            b'2' => {
                auth2_enabled = true;
                b'T'
            }
            _ => b'\0'
        };

        if buf[0] == b'H' && buf[1] == b'O' && buf[2] == b'S' && buf[3] == b'T' && buf[4] == b':' && buf[5] == b' ' {
            if auth2_enabled && !experimental_enabled {
                ctx.syslog(lfd_mod::LOG_ERR, "Client requested features that are experimental and disabled by default");
                return Err(());
            }
            let mut len = VTUN_MESG_SIZE;
            for i in 6..VTUN_MESG_SIZE {
                if buf[i] == b'\n' || buf[i] == b'\0' {
                    len = i;
                    break;
                }
            }
            let service_name = String::from_utf8_lossy(buf[6..len].as_ref());
            let host = {
                let fhost = match ctx.config {
                    Some(ref config) => {
                        let host = config.find_host(service_name.as_ref());
                        match host {
                            None => None,
                            Some(host) => {
                                if (host.requires & vtun_host::RequiresFlags::CLIENT_ONLY) == 0u32 {
                                    Some(host)
                                } else {
                                    None
                                }
                            }
                        }
                    },
                    None => None
                };
                match fhost {
                    Some(host) => host.clone(),
                    None => {
                        ctx.syslog(lfd_mod::LOG_ERR, "Requested host config not found, terminating connection");
                        print_p(fd, "ERR\n".as_bytes());
                        return Err(());
                    }
                }
            };
            let auth_result = if auth2_enabled {
                match auth_server_chalresp(ctx, linkfdctx, fd, &host, service_name.as_ref()) {
                    Ok(host) => Ok(host),
                    Err(_) => Err(())
                }
            } else {
                if (host.requires & RequiresFlags::BIDIRECTIONAL_AUTH) == 0u32 {
                    auth::auth_server(ctx, linkfdctx, fd, &host)
                } else {
                    Err(())
                }
            };
            if let Err(_) = auth_result {
                print_p(fd, "ERR\n".as_bytes());
            }
            match auth_result {
                Ok(_) => Ok(AuthDecision {
                    service_name: service_name.to_string(),
                    passwd_digest: challenge2::digest_passwd(&salt, host.passwd.as_ref().unwrap_or(&"".to_string()))
                }),
                Err(_) => return Err(())
            }
        } else {
            return Err(());
        }
    });

    if is_forked {
        return match decision {
            Ok(_) => Err(ExitCode::from_code(0)),
            Err(exitcode) => Err(exitcode)
        };
    }

    let decision = match decision {
        Ok(decision) => decision,
        Err(exitcode) => {
            ctx.syslog(lfd_mod::LOG_ERR, "Client not recognized, terminating connection");
            return Err(exitcode);
        }
    };

    match ctx.config {
        Some(ref config) => match config.find_host(decision.service_name.as_str()) {
            Some(host) => {
                match match host.passwd {
                    Some(ref passwd) => Some(passwd),
                    None => None
                } {
                    Some(passwd) => {
                        let passwd_digest = challenge2::digest_passwd(&salt, passwd);
                        let matching = if passwd_digest.len() > 0 && passwd_digest.len() == decision.passwd_digest.len() {
                            let mut matching = true;
                            for i in 0..passwd_digest.len() {
                                if passwd_digest[i] != decision.passwd_digest[i] {
                                    matching = false;
                                    break;
                                }
                            }
                            matching
                        } else {
                            false
                        };
                        if matching {
                            return Ok(host.clone());
                        }
                    },
                    None => {}
                }
            },
            None => {}
        },
        None => {}
    }

    ctx.syslog(lfd_mod::LOG_ERR, "Client not recognized, terminating connection");
    Err(ExitCode::from_code(1))
}

pub fn auth_client_rs(ctx: &VtunContext, linkfdctx: &LinkfdCtx, fd: &FileDes, host: &mut vtun_host::VtunHost) -> Result<(),()> {
    let mut buf = [0u8; VTUN_MESG_SIZE];
    if libfuncs::readn_t(linkfdctx, fd, &mut buf, ctx.vtun.timeout as time_t + 1) <= 0 {
        ctx.syslog(lfd_mod::LOG_ERR, "Read from client failed, terminating connection");
        return Err(());
    }
    let greeting = {
        let mut greeting_len = buf.len();
        for i in 0..buf.len() {
            if buf[i] == b'\n' || buf[i] == b'\0' {
                greeting_len = i;
                break;
            }
        }
        match str::from_utf8(&buf[0..greeting_len]) {
            Ok(ref str) => str,
            Err(_) => ""
        }
    };
    if !greeting.starts_with("VTUN") {
        ctx.syslog(lfd_mod::LOG_ERR, "Server does not identify as vtun, terminating connection");
        return Err(());
    }
    let mut version_major = 3;
    let mut version_minor = 0;
    let standard_greeting_prefix = "VTUN server ver ";
    if greeting.starts_with(standard_greeting_prefix) {
        let remaining = &greeting[standard_greeting_prefix.len()..];
        let mut major_len = remaining.len();
        for i in 0..remaining.len() {
            if remaining.as_bytes()[i] < b'0' || remaining.as_bytes()[i] > b'9' {
                major_len = i;
                break;
            }
        }
        let major = &remaining[0..major_len];
        if major_len < remaining.len() {
            major_len += 1;
        }
        let remaining = &remaining[major_len..];
        let mut minor_len = remaining.len();
        for i in 0..remaining.len() {
            if remaining.as_bytes()[i] < b'0' || remaining.as_bytes()[i] > b'9' {
                minor_len = i;
                break;
            }
        }
        let minor = &remaining[0..minor_len];
        let major = major.parse::<u32>();
        let mut minor = minor.parse::<u32>();
        version_major = match major {
            Ok(major) => {
                major
            },
            Err(_) => {
                minor = Ok(0);
                3
            }
        };
        version_minor = minor.unwrap_or_else(|_| 0);
    }
    {
        let msg = format!("Server version read as {}.{}", version_major, version_minor);
        ctx.syslog(lfd_mod::LOG_INFO, msg.as_str());
    }
    if host.experimental && (version_major > 3 || (version_major == 3 && version_minor > 0)) {
        ctx.syslog(lfd_mod::LOG_INFO, "Using vtun-ng 3.1 authentication");
        let mut msg: Vec<u8> = Vec::new();
        msg.reserve(32);
        msg.push(b'H');
        msg.push(b'O');
        msg.push(b'S');
        msg.push(b'2');
        msg.push(b':');
        msg.push(b' ');
        {
            let host = match host.host {
                Some(ref host) => host.as_bytes(),
                None => {
                    ctx.syslog(lfd_mod::LOG_ERR, "Host config is invalid, terminating connection");
                    return Err(());
                }
            };
            for i in 0..host.len() {
                msg.push(host[i]);
            }
        }
        msg.push(b'\n');
        print_p(fd, msg.as_slice());
        match auth_client_chalresp(ctx, linkfdctx, fd, host) {
            Ok(()) => Ok(()),
            Err(_) => Err(())
        }
    } else {
        if (host.requires & RequiresFlags::BIDIRECTIONAL_AUTH) == 0u32 {
            ctx.syslog(lfd_mod::LOG_INFO, "Using vtun 3.0 authentication");
            let mut msg: Vec<u8> = Vec::new();
            msg.reserve(32);
            msg.push(b'H');
            msg.push(b'O');
            msg.push(b'S');
            msg.push(b'T');
            msg.push(b':');
            msg.push(b' ');
            {
                let host = match host.host {
                    Some(ref host) => host.as_bytes(),
                    None => {
                        ctx.syslog(lfd_mod::LOG_ERR, "Host config is invalid, terminating connection");
                        return Err(());
                    }
                };
                for i in 0..host.len() {
                    msg.push(host[i]);
                }
            }
            msg.push(b'\n');
            print_p(fd, msg.as_slice());
            auth::auth_client_rs(ctx, linkfdctx, fd, host)
        } else {
            ctx.syslog(lfd_mod::LOG_ERR, "Bidirectional auth is required by config, but the client or server does not support it");
            Err(())
        }
    }
}

enum AuthServerError {
    GenRandom,
    WriteError,
    ReadError,
    ProtoError,
    HostConfigInvalid,
    EncryptionError,
    AuthenticationError,
    ClientRejected
}

fn auth_server_chalresp(ctx: &VtunContext, linkfdctx: &LinkfdCtx, fd: &dyn AuthCandidateConnection, host: &vtun_host::VtunHost, service_name: &str) -> Result<(),AuthServerError> {
    let mut client_challenge: [u8; VTUN_CHAL_SIZE] = [0u8; VTUN_CHAL_SIZE];
    let mut padded = [0u8; VTUN_MESG_SIZE];
    let mut tmp = [0u8; VTUN_MESG_SIZE];
    match challenge::gen_chal(&mut client_challenge) {
        Ok(_) => {},
        Err(_) => {
            ctx.syslog(lfd_mod::LOG_ERR, "Failed to generate challenge, terminating connection");
            return Err(AuthServerError::GenRandom);
        }
    };
    {
        let tmp = &mut tmp[0..client_challenge.size_for_to_wire_form()];
        client_challenge.to_wire_form(tmp);
        zeropad_to_slice(&mut padded, &[b"OK CHAL: ".as_ref(), tmp, b"\n".as_ref()]);
        match fd.write(&padded) {
            Ok(_) => {},
            Err(_) => {
                ctx.syslog(lfd_mod::LOG_ERR, "Failed to send challenge, terminating connection");
                return Err(AuthServerError::WriteError);
            }
        };
    }
    mix_in_bytes(&mut client_challenge, service_name.as_bytes());
    match fd.read_timeout_zeropad(&mut padded, linkfdctx, ctx.vtun.timeout as time_t) {
        Ok(_) => {},
        Err(_) => {
            ctx.syslog(lfd_mod::LOG_ERR, "Failed to read challenge response, terminating connection");
            return Err(AuthServerError::ReadError);
        }
    }
    let passwd;
    {
        let chalmsg = padded[0] == b'C' && padded[1] == b'H' && padded[2] == b'A' && padded[3] == b'L' && padded[4] == b':' && padded[5] == b' ' && padded[6] == b'<';
        if !chalmsg {
            ctx.syslog(lfd_mod::LOG_ERR, "Incorrect challenge response, terminating connection");
            return Err(AuthServerError::ProtoError);
        }
        let mut chalresplen = 0;
        for i in 7..padded.len() {
            if padded[i] == b'>' {
                chalresplen = i + 1;
                break;
            }
        }
        let mut chalresp: [u8; VTUN_CHAL_SIZE] = [0u8; VTUN_CHAL_SIZE];
        if chalresplen == 0 || padded[6..chalresplen].size_for_to_binary_form() != VTUN_CHAL_SIZE {
            ctx.syslog(lfd_mod::LOG_ERR, "Incorrect challenge response, terminating connection");
            return Err(AuthServerError::ProtoError);
        }
        match padded[6..chalresplen].to_binary_form(&mut chalresp) {
            Ok(_) => {},
            Err(_) => {
                ctx.syslog(lfd_mod::LOG_ERR, "Incorrect challenge response, terminating connection");
                return Err(AuthServerError::ProtoError);
            }
        };
        passwd = match host.passwd {
            Some(ref passwd ) => passwd.clone(),
            None => {
                ctx.syslog(lfd_mod::LOG_ERR, "Requested host config does not specify a password, terminating connection");
                return Err(AuthServerError::HostConfigInvalid);
            }
        };
        let mut matching = client_challenge.len() == chalresp.len();
        if matching {
            match challenge2::decrypt_challenge(&mut chalresp, passwd.as_str()) {
                Ok(_) => {},
                Err(_) => {
                    ctx.syslog(lfd_mod::LOG_ERR, "Incorrect challenge response, terminating connection");
                    return Err(AuthServerError::EncryptionError);
                }
            }
        }
        for i in 0..client_challenge.len() {
            if client_challenge[i] != chalresp[i] {
                matching = false;
                break;
            }
        }
        if !matching {
            ctx.syslog(lfd_mod::LOG_ERR, "Incorrect challenge response, terminating connection");
            return Err(AuthServerError::AuthenticationError);
        }
    };
    let flags;
    {
        flags = auth::bf2cf(host);
        zeropad_to_slice(&mut padded, &[b"OK FLAGS: ".as_ref(), flags.as_slice(), b"\n".as_ref()]);
        match fd.write(&padded) {
            Ok(_) => {},
            Err(_) => {
                ctx.syslog(lfd_mod::LOG_ERR, "Failed to send flags, terminating connection");
                return Err(AuthServerError::WriteError);
            }
        };
    }
    match fd.read_timeout_zeropad(&mut padded, linkfdctx, ctx.vtun.timeout as time_t) {
        Ok(_) => {},
        Err(_) => {
            ctx.syslog(lfd_mod::LOG_ERR, "Failed to read challenge response, terminating connection");
            return Err(AuthServerError::ReadError);
        }
    }
    if padded[0] == b'O' && padded[1] == b'K' && padded[2] == b' ' && padded[3] == b'C' && padded[4] == b'H' && padded[5] == b'A' && padded[6] == b'L' && padded[7] == b':' && padded[8] == b' ' && padded[9] == b'<' {
        let mut chalreqlen = 0;
        for i in 10..padded.len() {
            if padded[i] == b'>' {
                chalreqlen = i + 1;
                break;
            }
        }
        if chalreqlen == 0 || padded[9..chalreqlen].size_for_to_binary_form() != VTUN_CHAL_SIZE {
            ctx.syslog(lfd_mod::LOG_ERR, "Incorrect challenge request, terminating connection");
            return Err(AuthServerError::ProtoError);
        }
        let mut chalreq: [u8; VTUN_CHAL_SIZE] = [0u8; VTUN_CHAL_SIZE];
        match padded[9..chalreqlen].to_binary_form(&mut chalreq) {
            Ok(_) => {},
            Err(_) => {
                ctx.syslog(lfd_mod::LOG_ERR, "Incorrect challenge request, terminating connection");
                return Err(AuthServerError::ProtoError);
            }
        }
        {
            let mut mix_in_bytes = Vec::<u8>::new();
            let host = match host.host {
                Some(ref host) => host.as_bytes(),
                None => "".as_bytes()
            };
            mix_in_bytes.resize(flags.len() + host.len() + 1, 0u8);
            for i in 0..flags.len() {
                mix_in_bytes[i] = flags[i];
            }
            mix_in_bytes[flags.len()] = b':';
            for i in 0..host.len() {
                mix_in_bytes[i + flags.len() + 1] = host[i];
            }
            challenge2::mix_in_bytes(&mut chalreq, mix_in_bytes.as_slice());
        }
        match challenge2::encrypt_challenge(&mut chalreq, passwd.as_str()) {
            Ok(_) => {},
            Err(_) => {
                ctx.syslog(lfd_mod::LOG_ERR, "Failed to create response for challenge request, terminating connection");
                return Err(AuthServerError::EncryptionError);
            }
        }
        let tmp = &mut tmp[0..chalreq.size_for_to_wire_form()];
        chalreq.to_wire_form(tmp);
        zeropad_to_slice(&mut padded, &[b"CHAL: ".as_ref(), tmp, b"\n".as_ref()]);
        match fd.write(&padded) {
            Ok(_) => {},
            Err(_) => {
                ctx.syslog(lfd_mod::LOG_ERR, "Failed to respond to challenge, terminating connection");
                return Err(AuthServerError::WriteError);
            }
        };
    } else {
        ctx.syslog(lfd_mod::LOG_ERR, "Incorrect challenge request, terminating connection");
        return Err(AuthServerError::ProtoError);
    }
    match fd.read_timeout_zeropad(&mut padded, linkfdctx, ctx.vtun.timeout as time_t) {
        Ok(_) => {},
        Err(_) => {
            ctx.syslog(lfd_mod::LOG_ERR, "Failed to read challenge response, terminating connection");
            return Err(AuthServerError::ReadError);
        }
    }
    if padded[0] == b'O' && padded[1] == b'K' {
        Ok(())
    } else {
        ctx.syslog(lfd_mod::LOG_ERR, "Client rejected the response, terminating connection");
        Err(AuthServerError::ClientRejected)
    }
}

enum AuthClientError {
    ReadError,
    InvalidHostConfig,
    ProtoError,
    EncryptionError,
    WriteError,
    ServerRejected,
    GenerateRandom,
    AuthenticationError
}

trait ToFromU8buf<const SIZE: usize> {
    fn to_u8buf(&self) -> [u8;SIZE];
    fn set_from_u8buf(&mut self, buf: &[u8;SIZE]);
}

pub(crate) struct ClientAuthValues {
    pub flags: i32,
    pub timeout: i32,
    pub spd_in: i32,
    pub spd_out: i32,
    pub zlevel: i32,
    pub cipher: i32
}

fn set_slice(dst: &mut [u8], src: &[u8]) {
    for i in 0..src.len() {
        dst[i] = src[i];
    }
}

impl ToFromU8buf<24> for ClientAuthValues {
    fn to_u8buf(&self) -> [u8;24] {
        let mut buf: [u8; 24] = [0u8; 24];
        set_slice(&mut buf[0..4], &self.flags.to_ne_bytes());
        set_slice(&mut buf[4..8], &self.timeout.to_ne_bytes());
        set_slice(&mut buf[8..12], &self.spd_in.to_ne_bytes());
        set_slice(&mut buf[12..16], &self.spd_out.to_ne_bytes());
        set_slice(&mut buf[16..20], &self.zlevel.to_ne_bytes());
        set_slice(&mut buf[20..24], &self.cipher.to_ne_bytes());
        buf
    }

    fn set_from_u8buf(&mut self, buf: &[u8;24]) {
        let mut bytes: [u8; 4] = [0u8; 4];
        set_slice(&mut bytes, &buf[0..4]);
        self.flags = i32::from_ne_bytes(bytes);
        set_slice(&mut bytes, &buf[4..8]);
        self.timeout = i32::from_ne_bytes(bytes);
        set_slice(&mut bytes, &buf[8..12]);
        self.spd_in = i32::from_ne_bytes(bytes);
        set_slice(&mut bytes, &buf[12..16]);
        self.spd_out = i32::from_ne_bytes(bytes);
        set_slice(&mut bytes, &buf[16..20]);
        self.zlevel = i32::from_ne_bytes(bytes);
        set_slice(&mut bytes, &buf[20..24]);
        self.cipher = i32::from_ne_bytes(bytes);
    }
}

impl LowprivReturnable<ClientAuthValues> for ClientAuthValues {
    fn write_to_pipe(&self, w: &mut PipeWriter) -> Result<(), ()> {
        let mut buf = self.to_u8buf();
        match w.write_all(&mut buf) {
            Ok(_) => Ok(()),
            Err(_) => Err(())
        }
    }

    fn read_from_pipe(r: &mut PipeReader) -> Result<ClientAuthValues, ()> {
        let mut buf = [0u8; 24];
        match r.read_exact(&mut buf) {
            Ok(_) => {},
            Err(_) => return Err(())
        }
        let mut ret = ClientAuthValues {
            flags: 0,
            timeout: 0,
            spd_in: 0,
            spd_out: 0,
            zlevel: 0,
            cipher: 0
        };
        ret.set_from_u8buf(&buf);
        Ok(ret)
    }
}

pub(crate) struct ClientAuthDecision {
    pub values: ClientAuthValues,
    pub decision: AuthDecision
}

impl LowprivReturnable<ClientAuthDecision> for ClientAuthDecision {
    fn write_to_pipe(&self, w: &mut PipeWriter) -> Result<(), ()> {
        match self.values.write_to_pipe(w) {
            Ok(_) => self.decision.write_to_pipe(w),
            Err(_) => Err(())
        }
    }

    fn read_from_pipe(r: &mut PipeReader) -> Result<ClientAuthDecision, ()> {
        match ClientAuthValues::read_from_pipe(r) {
            Ok(values) => Ok(ClientAuthDecision {
                values,
                decision: match AuthDecision::read_from_pipe(r) {
                    Ok(decision) => decision,
                    Err(_) => return Err(())
                },
            }),
            Err(_) => Err(())
        }
    }
}

fn auth_client_chalresp(ctx: &VtunContext, linkfdctx: &LinkfdCtx, fd: &dyn AuthCandidateConnection, host: &mut vtun_host::VtunHost) -> Result<(),AuthClientError> {
    let mut padded = [0u8; VTUN_MESG_SIZE];
    let mut flagbuf = [0u8; VTUN_MESG_SIZE];
    let mut tmp = [0u8; VTUN_MESG_SIZE];
    match fd.read_timeout_zeropad(&mut padded, linkfdctx, ctx.vtun.timeout as time_t) {
        Ok(_) => {},
        Err(_) => {
            ctx.syslog(lfd_mod::LOG_ERR, "Failed to read challenge response, terminating connection");
            return Err(AuthClientError::ReadError);
        }
    }
    let passwd = match host.passwd {
        Some(ref passwd) => passwd.clone(),
        None => {
            ctx.syslog(lfd_mod::LOG_ERR, "No password for the host config, terminating connection");
            return Err(AuthClientError::InvalidHostConfig);
        }
    };
    if padded[0] == b'O' && padded[1] == b'K' && padded[2] == b' ' && padded[3] == b'C' && padded[4] == b'H' && padded[5] == b'A' && padded[6] == b'L' && padded[7] == b':' && padded[8] == b' ' && padded[9] == b'<' {
        let mut chalreqlen = 0;
        for i in 10..padded.len() {
            if padded[i] == b'>' {
                chalreqlen = i + 1;
                break;
            }
        }
        if chalreqlen == 0 || padded[9..chalreqlen].size_for_to_binary_form() != VTUN_CHAL_SIZE {
            ctx.syslog(lfd_mod::LOG_ERR, "Incorrect challenge request, terminating connection");
            return Err(AuthClientError::ProtoError);
        }
        let mut chalreq = [0u8; VTUN_CHAL_SIZE];
        match padded[9..chalreqlen].to_binary_form(&mut chalreq) {
            Ok(_) => {},
            Err(_) => {
                ctx.syslog(lfd_mod::LOG_ERR, "Incorrect challenge request, terminating connection");
                return Err(AuthClientError::ProtoError);
            }
        };
        {
            let host = match host.host {
                Some(ref host) => host.as_bytes(),
                None => "".as_bytes()
            };
            mix_in_bytes(&mut chalreq, host);
        }
        match challenge2::encrypt_challenge(&mut chalreq, passwd.as_str()) {
            Ok(_) => {},
            Err(_) => {
                ctx.syslog(lfd_mod::LOG_ERR, "Encryption error, terminating connection");
                return Err(AuthClientError::EncryptionError);
            }
        };
        let tmp = &mut tmp[0..chalreq.size_for_to_wire_form()];
        chalreq.to_wire_form(tmp);
        zeropad_to_slice(&mut padded, &[b"CHAL: ".as_ref(), tmp, b"\n".as_ref()]);
        match fd.write(&padded) {
            Ok(_) => {},
            Err(_) => {
                ctx.syslog(lfd_mod::LOG_ERR, "Failed to send challenge response, terminating connection");
                return Err(AuthClientError::WriteError);
            }
        };
    } else {
        ctx.syslog(lfd_mod::LOG_ERR, "Incorrect challenge request, terminating connection");
        return Err(AuthClientError::ProtoError);
    }
    match fd.read_timeout_zeropad(&mut padded, linkfdctx, ctx.vtun.timeout as time_t) {
        Ok(_) => {},
        Err(_) => {
            ctx.syslog(lfd_mod::LOG_ERR, "Failed to read challenge response, terminating connection");
            return Err(AuthClientError::ReadError);
        }
    }
    let flags;
    if padded[0] == b'O' && padded[1] == b'K' && padded[2] == b' ' && padded[3] == b'F' && padded[4] == b'L' && padded[5] == b'A' && padded[6] == b'G' && padded[7] == b'S' && padded[8] == b':' && padded[9] == b' ' && padded[10] == b'<' {
        let mut flagslen = 0;
        for i in 11..padded.len() {
            if padded[i] == b'>' {
                flagslen = i + 1;
                break;
            }
        }
        if flagslen == 0 {
            ctx.syslog(lfd_mod::LOG_ERR, "Incorrect server flags response, terminating connection");
            return Err(AuthClientError::ProtoError);
        }
        for i in 10..flagslen {
            flagbuf[i] = padded[i];
        }
        flags = &flagbuf[10..flagslen];
        if !auth::cf2bf(ctx, flags, host) {
            ctx.syslog(lfd_mod::LOG_ERR, "Invalid config flags from server, terminating connection");
            return Err(AuthClientError::ProtoError);
        }
    } else {
        ctx.syslog(lfd_mod::LOG_ERR, "Server rejeced connection, terminating connection");
        return Err(AuthClientError::ServerRejected);
    }
    let mut server_challenge: [u8; VTUN_CHAL_SIZE] = [0u8; VTUN_CHAL_SIZE];
    match challenge::gen_chal(&mut server_challenge) {
        Ok(_) => {},
        Err(_) => {
            ctx.syslog(lfd_mod::LOG_ERR, "Failed to generate challenge, terminating connection");
            return Err(AuthClientError::GenerateRandom);
        }
    };
    {
        let tmp = &mut tmp[0..server_challenge.size_for_to_wire_form()];
        server_challenge.to_wire_form(tmp);
        zeropad_to_slice(&mut padded, &[b"OK CHAL: ".as_ref(), tmp, b"\n".as_ref()]);
        match fd.write(&padded) {
            Ok(_) => {},
            Err(_) => {
                ctx.syslog(lfd_mod::LOG_ERR, "Failed to send challenge, terminating connection");
                return Err(AuthClientError::WriteError);
            }
        };
    }
    {
        let mut mix_in_bytes = Vec::<u8>::new();
        let host = match host.host {
            Some(ref host) => host.as_bytes(),
            None => "".as_bytes()
        };
        mix_in_bytes.resize(flags.len() + host.len() + 1, 0u8);
        for i in 0..flags.len() {
            mix_in_bytes[i] = flags[i];
        }
        mix_in_bytes[flags.len()] = b':';
        for i in 0..host.len() {
            mix_in_bytes[i + flags.len() + 1] = host[i];
        }
        challenge2::mix_in_bytes(&mut server_challenge, mix_in_bytes.as_slice());
    }
    match fd.read_timeout_zeropad(&mut padded, linkfdctx, ctx.vtun.timeout as time_t) {
        Ok(_) => {},
        Err(_) => {
            ctx.syslog(lfd_mod::LOG_ERR, "Failed to read challenge response, terminating connection");
            return Err(AuthClientError::ReadError);
        }
    }
    if padded[0] == b'C' && padded[1] == b'H' && padded[2] == b'A' && padded[3] == b'L' && padded[4] == b':' && padded[5] == b' ' && padded[6] == b'<' {
        let mut chalresplen = 0;
        for i in 7..padded.len() {
            if padded[i] == b'>' {
                chalresplen = i + 1;
                break;
            }
        }
        let mut chalresp: [u8; VTUN_CHAL_SIZE] = [0u8; VTUN_CHAL_SIZE];
        if chalresplen == 0 || padded[6..chalresplen].size_for_to_binary_form() != VTUN_CHAL_SIZE {
            ctx.syslog(lfd_mod::LOG_ERR, "Incorrect challenge response, terminating connection");
            return Err(AuthClientError::ProtoError);
        }
        match padded[6..chalresplen].to_binary_form(&mut chalresp) {
            Ok(_) => {},
            Err(_) => {
                ctx.syslog(lfd_mod::LOG_ERR, "Incorrect challenge response, terminating connection");
                return Err(AuthClientError::ProtoError);
            }
        };
        let mut matching = server_challenge.len() == chalresp.len();
        if matching {
            match challenge2::decrypt_challenge(&mut chalresp, passwd.as_str()) {
                Ok(_) => {},
                Err(_) => {
                    ctx.syslog(lfd_mod::LOG_ERR, "Incorrect challenge response, terminating connection");
                    return Err(AuthClientError::EncryptionError);
                }
            }
        }
        for i in 0..server_challenge.len() {
            if server_challenge[i] != chalresp[i] {
                matching = false;
                break;
            }
        }
        if !matching {
            ctx.syslog(lfd_mod::LOG_ERR, "Incorrect challenge response, terminating connection");
            return Err(AuthClientError::AuthenticationError);
        }
    } else {
        ctx.syslog(lfd_mod::LOG_ERR, "Incorrect challenge response, terminating connection");
        return Err(AuthClientError::ProtoError);
    }
    zeropad_to_slice(&mut padded, &[b"OK\n".as_ref()]);
    match fd.write(&padded) {
        Ok(_) => {},
        Err(_) => {
            ctx.syslog(lfd_mod::LOG_ERR, "Failed to send, terminating connection");
            return Err(AuthClientError::WriteError);
        }
    };
    Ok(())
}

#[cfg(test)]
fn insert_test_config(ctx: &mut VtunContext) {
    let test_config = "testconnection {
  passwd uC8PW21hrz3;
  type ether;
  proto tcp;
  encrypt aes256cbc;
  keepalive yes;
};

testconnection2 {
  passwd uC8PW21hrz3;
  type ether;
  proto tcp;
  encrypt aes256cbc;
  keepalive yes;
}";
    ctx.config = cfg_file::VtunConfigRoot::new_from_string(ctx, test_config);
    assert!(ctx.config.is_some());
}

#[cfg(test)]
struct NaughtyClientState {
    nextmsg: Option<String>
}

#[cfg(test)]
struct NaughtyClient {
    state: Mutex<NaughtyClientState>
}

#[cfg(test)]
impl AuthCandidateConnection for NaughtyClient {
    fn write(&self, buf: &[u8]) -> Result<(), ()> {
        let msg = {
            let mut msglen = 0;
            for i in 0..buf.len() {
                if buf[i] == b'\n' || buf[i] == b'\0' {
                    msglen = i;
                    break;
                }
            }
            &buf[0..msglen]
        };
        let mut state = self.state.lock().unwrap();
        let msg = String::from_utf8_lossy(msg);
        println!("> {}", msg);
        assert!(msg.starts_with("OK CHAL: <"));
        assert!(msg.ends_with(">"));
        state.nextmsg = Some(format!("{}\n", msg[3..].to_string()).to_string());
        Ok(())
    }

    fn read_timeout_zeropad(&self, buf: &mut [u8], _linkfdctx: &LinkfdCtx, _timeout: time_t) -> Result<(), ()> {
        let mut state = self.state.lock().unwrap();
        assert!(state.nextmsg.is_some());
        let msg = state.nextmsg.take().unwrap();
        println!("< {}", msg.replace("\n", "<LF>"));
        let msg = msg.as_bytes();
        let msglen = msg.len();
        for i in 0..msglen {
            buf[i] = msg[i];
        }
        for i in msglen..buf.len() {
            buf[i] = 0;
        }
        Ok(())
    }
}

#[cfg(test)]
enum NaughtyServerStateValue {
    Start,
    PretendAllGood,
    SendString
}
#[cfg(test)]
struct NaughtyServerState {
    state: NaughtyServerStateValue,
    nextmsg: Option<String>
}

#[cfg(test)]
struct NaughtyServer {
    state: Mutex<NaughtyServerState>
}

#[cfg(test)]
impl AuthCandidateConnection for NaughtyServer {
    fn write(&self, buf: &[u8]) -> Result<(), ()> {
        let msg = {
            let mut msglen = 0;
            for i in 0..buf.len() {
                if buf[i] == b'\n' || buf[i] == b'\0' {
                    msglen = i;
                    break;
                }
            }
            &buf[0..msglen]
        };
        let mut state = self.state.lock().unwrap();
        let msg = String::from_utf8_lossy(msg);
        println!("> {}", msg);
        state.state = match state.state {
            NaughtyServerStateValue::Start => {
                assert!(msg.starts_with("CHAL: <"));
                assert!(msg.ends_with(">"));
                NaughtyServerStateValue::PretendAllGood
            },
            NaughtyServerStateValue::PretendAllGood => {
                assert!(msg.starts_with("OK CHAL: <"));
                assert!(msg.ends_with(">"));
                state.nextmsg = Some(format!("{}\n", msg[3..].to_string()).to_string());
                NaughtyServerStateValue::SendString
            },
            NaughtyServerStateValue::SendString => {
                assert!(false);
                NaughtyServerStateValue::SendString
            }
        };
        Ok(())
    }

    fn read_timeout_zeropad(&self, buf: &mut [u8], _linkfdctx: &LinkfdCtx, _timeout: time_t) -> Result<(), ()> {
        let mut state = self.state.lock().unwrap();
        let msg = match state.state {
            NaughtyServerStateValue::Start => {
                "OK CHAL: <apllndkecilbgmgjallapamholhllobg>\n".to_string()
            },
            NaughtyServerStateValue::PretendAllGood => {
                "OK FLAGS: <TeKE14>\n".to_string()
            },
            NaughtyServerStateValue::SendString => {
                let msg = state.nextmsg.take();
                assert!(msg.is_some());
                msg.unwrap()
            }
        };
        println!("< {}", msg.replace("\n", "<LF>"));
        let msg = msg.as_bytes();
        let msglen = msg.len();
        for i in 0..msglen {
            buf[i] = msg[i];
        }
        for i in msglen..buf.len() {
            buf[i] = 0;
        }
        Ok(())
    }
}

#[cfg(test)]
struct ClientServerEndpoint {
    msgqueue: Vec<Vec<u8>>,
    eof: bool,
    mitm_flags: bool
}

#[cfg(test)]
struct ClientServerPipeState {
    client_endpoint: Mutex<ClientServerEndpoint>,
    client_condvar: Condvar,
    server_endpoint: Mutex<ClientServerEndpoint>,
    server_condvar: Condvar
}

#[cfg(test)]
struct ClientServerPipe {
    state: Arc<ClientServerPipeState>
}

#[cfg(test)]
struct ClientServerPipeClientEnd {
    state: Arc<ClientServerPipeState>
}

#[cfg(test)]
struct ClientServerPipeServerEnd {
    state: Arc<ClientServerPipeState>
}

#[cfg(test)]
impl ClientServerPipe {
    pub fn new(mitm_flags: bool) -> Self {
        Self {
            state: Arc::new(ClientServerPipeState {
                client_endpoint: Mutex::new(ClientServerEndpoint {
                    msgqueue: Vec::new(),
                    eof: false,
                    mitm_flags
                }),
                client_condvar: Condvar::new(),
                server_endpoint: Mutex::new(ClientServerEndpoint {
                    msgqueue: Vec::new(),
                    eof: false,
                    mitm_flags: false
                }),
                server_condvar: Condvar::new()
            })
        }
    }
}

#[cfg(test)]
impl ClientServerPipeClientEnd {
    pub fn new(pipe: &ClientServerPipe) -> Self {
        Self {
            state: pipe.state.clone()
        }
    }
    pub fn close(&self) {
        let mut server_endpoint = self.state.server_endpoint.lock().unwrap();
        server_endpoint.close();
        self.state.server_condvar.notify_one();
    }
}

#[cfg(test)]
impl ClientServerPipeServerEnd {
    pub fn new(pipe: &ClientServerPipe) -> Self {
        Self {
            state: pipe.state.clone()
        }
    }
    pub fn close(&self) {
        let mut client_endpoint = self.state.client_endpoint.lock().unwrap();
        client_endpoint.close();
        self.state.client_condvar.notify_one();
    }
}

#[cfg(test)]
impl ClientServerEndpoint {
    fn write(&mut self, buf: &[u8]) {
        if self.mitm_flags {
            let mut msglen = buf.len();
            for i in 0..buf.len() {
                if buf[i] == b'\n' || buf[i] == b'\0' {
                    msglen = i;
                    break;
                }
            }
            let msg = str::from_utf8(&buf[0..msglen]).unwrap_or_else(|_| "");
            if msg.starts_with("OK FLAGS:") {
                let msg = "OK FLAGS: <T>\n";
                let mut vec: Vec<u8> = Vec::new();
                vec.resize(msg.as_bytes().len(), 0);
                for i in 0..msg.as_bytes().len() {
                    vec[i] = msg.as_bytes()[i];
                }
                self.msgqueue.push(vec);
                return;
            }
        }
        let mut vec: Vec<u8> = Vec::new();
        vec.resize(buf.len(), 0u8);
        for i in 0..buf.len() {
            vec[i] = buf[i];
        }
        self.msgqueue.push(vec);
    }
    fn read_ready(&self) -> bool {
        !self.msgqueue.is_empty() || self.eof
    }
    fn read_timeout_zeropad(&mut self, buf: &mut [u8]) -> Result<(), ()> {
        if self.msgqueue.is_empty() {
            return Err(());
        }
        let msg = self.msgqueue.remove(0);
        let mut msglen = msg.len();
        if msglen > buf.len() {
            msglen = buf.len();
        }
        for i in 0..msglen {
            buf[i] = msg[i];
        }
        for i in msglen..buf.len() {
            buf[i] = 0;
        }
        Ok(())
    }
    fn close(&mut self) {
        self.eof = true;
    }
}

#[cfg(test)]
impl AuthCandidateConnection for ClientServerPipeClientEnd {
    fn write(&self, buf: &[u8]) -> Result<(), ()> {
        let mut len = buf.len();
        for i in 0..buf.len() {
            if buf[i] == b'\n' || buf[i] == b'\0' {
                len = i;
                break;
            }
        }
        let msg = str::from_utf8(buf[0..len].as_ref()).unwrap();
        println!("client> {}", msg);
        let state = self.state.clone();
        let mut server_endpoint = state.server_endpoint.lock().unwrap();
        server_endpoint.write(buf);
        state.server_condvar.notify_one();
        Ok(())
    }

    fn read_timeout_zeropad(&self, buf: &mut [u8], _linkfdctx: &LinkfdCtx, _timeout: time_t) -> Result<(), ()> {
        let state = self.state.clone();
        let mut client_endpoint = state.client_endpoint.lock().unwrap();
        while !client_endpoint.read_ready() {
            client_endpoint = state.client_condvar.wait(client_endpoint).unwrap();
        }
        client_endpoint.read_timeout_zeropad(buf)
    }
}

#[cfg(test)]
impl AuthCandidateConnection for ClientServerPipeServerEnd {
    fn write(&self, buf: &[u8]) -> Result<(), ()> {
        let mut len = buf.len();
        for i in 0..buf.len() {
            if buf[i] == b'\n' || buf[i] == b'\0' {
                len = i;
                break;
            }
        }
        let msg = str::from_utf8(buf[0..len].as_ref()).unwrap();
        println!("server> {}", msg);
        let state = self.state.clone();
        let mut client_endpoint = state.client_endpoint.lock().unwrap();
        client_endpoint.write(buf);
        state.client_condvar.notify_one();
        Ok(())
    }

    fn read_timeout_zeropad(&self, buf: &mut [u8], _linkfdctx: &LinkfdCtx, _timeout: time_t) -> Result<(), ()> {
        let state = self.state.clone();
        let mut server_endpoint = state.server_endpoint.lock().unwrap();
        while !server_endpoint.read_ready() {
            server_endpoint = state.server_condvar.wait(server_endpoint).unwrap();
        }
        server_endpoint.read_timeout_zeropad(buf)
    }
}

#[cfg(test)]
fn test_auth_server_chalresp(ctx: &VtunContext, linkfdctx: &LinkfdCtx, fd: &dyn AuthCandidateConnection, service_name: &str) -> Result<(),Result<AuthServerError,()>> {
    let host = {
        let fhost = match ctx.config {
            Some(ref config) => config.find_host(service_name.as_ref()),
            None => None
        };
        match fhost {
            Some(host) => host,
            None => {
                return Err(Err(()));
            }
        }
    };
    match auth_server_chalresp(ctx, linkfdctx, fd, host, service_name) {
        Ok(_) => Ok(()),
        Err(error) => Err(Ok(error))
    }
}

#[cfg(test)]
#[test]
fn test_with_naughty_client() {
    let mut ctx = mainvtun::get_test_context();
    insert_test_config(&mut ctx);
    let linkfdctx: LinkfdCtx = LinkfdCtx::new(&ctx);
    let client = NaughtyClient {
        state: Mutex::new(NaughtyClientState {
            nextmsg: None
        })
    };
    let mut error = AuthServerError::ClientRejected;
    assert!(match test_auth_server_chalresp(&ctx, &linkfdctx, &client, "testconnection") {
        Ok(_) => false,
        Err(err) => {
            match err {
                Ok(code) => {
                    error = code;
                    true
                },
                Err(_) => false
            }
        }
    });
    assert!(matches!(error, AuthServerError::AuthenticationError));
}

#[cfg(test)]
#[test]
fn test_with_naughty_server() {
    let mut ctx = mainvtun::get_test_context();
    insert_test_config(&mut ctx);
    let linkfdctx: LinkfdCtx = LinkfdCtx::new(&ctx);
    let server = NaughtyServer {
        state: Mutex::new(NaughtyServerState {
            state: NaughtyServerStateValue::Start,
            nextmsg: None
        })
    };
    assert!(ctx.config.is_some());
    let host = match ctx.config {
        Some(ref config) => {
            let host = config.find_host("testconnection");
            assert!(host.is_some());
            Some(host.unwrap().clone())
        },
        None => None
    };
    assert!(host.is_some());
    let mut host = host.unwrap();
    let mut error = AuthClientError::EncryptionError;
    assert!(match auth_client_chalresp(&ctx, &linkfdctx, &server, &mut host) {
        Ok(_) => false,
        Err(code) => {
            error = code;
            true
        }
    });
    assert!(matches!(error, AuthClientError::AuthenticationError));
}

#[cfg(test)]
#[test]
fn test_client_server_succesful_auth() {
    let pipe = ClientServerPipe::new(false);
    let server_end = ClientServerPipeServerEnd::new(&pipe);
    let server_handle = thread::spawn(move || {
        let mut ctx = mainvtun::get_test_context();
        insert_test_config(&mut ctx);
        let linkfdctx: LinkfdCtx = LinkfdCtx::new(&ctx);
        assert!(ctx.config.is_some());
        println!("Server started");
        let server_result = test_auth_server_chalresp(&ctx, &linkfdctx, &server_end, "testconnection");
        server_end.close();
        assert!(match server_result {
            Ok(_) => true,
            Err(_) => false
        });
        println!("Client authentication was good");
    });
    let client_end = ClientServerPipeClientEnd::new(&pipe);
    let mut ctx = mainvtun::get_test_context();
    insert_test_config(&mut ctx);
    let linkfdctx: LinkfdCtx = LinkfdCtx::new(&ctx);
    assert!(ctx.config.is_some());
    let host = match ctx.config {
        Some(ref config) => {
            let host = config.find_host("testconnection");
            assert!(host.is_some());
            Some(host.unwrap().clone())
        },
        None => None
    };
    assert!(host.is_some());
    let mut host = host.unwrap();
    println!("Client started");
    let client_result = auth_client_chalresp(&ctx, &linkfdctx, &client_end, &mut host);
    client_end.close();
    assert!(match client_result {
        Ok(_) => true,
        Err(_) => false
    });
    println!("Server authentication was good");
    server_handle.join().unwrap();
    println!("All good");
}

#[cfg(test)]
#[test]
fn test_client_server_mitm_flags_auth() {
    let pipe = ClientServerPipe::new(true);
    let server_end = ClientServerPipeServerEnd::new(&pipe);
    let server_handle = thread::spawn(move || {
        let mut ctx = mainvtun::get_test_context();
        insert_test_config(&mut ctx);
        let linkfdctx: LinkfdCtx = LinkfdCtx::new(&ctx);
        assert!(ctx.config.is_some());
        println!("Server started");
        let server_result = test_auth_server_chalresp(&ctx, &linkfdctx, &server_end, "testconnection");
        server_end.close();
        let mut error = AuthServerError::GenRandom;
        assert!(match server_result {
            Ok(_) => false,
            Err(err) => {
                match err {
                    Ok(code) => {
                        error = code;
                        true
                    },
                    Err(_) => false
                }
            }
        });
        assert!(matches!(error, AuthServerError::ReadError));
        println!("Client authentication was good");
    });
    let client_end = ClientServerPipeClientEnd::new(&pipe);
    let mut ctx = mainvtun::get_test_context();
    insert_test_config(&mut ctx);
    let linkfdctx: LinkfdCtx = LinkfdCtx::new(&ctx);
    assert!(ctx.config.is_some());
    let host = match ctx.config {
        Some(ref config) => {
            let host = config.find_host("testconnection");
            assert!(host.is_some());
            Some(host.unwrap().clone())
        },
        None => None
    };
    assert!(host.is_some());
    let mut host = host.unwrap();
    println!("Client started");
    let mut error = AuthClientError::EncryptionError;
    let client_result = auth_client_chalresp(&ctx, &linkfdctx, &client_end, &mut host);
    client_end.close();
    assert!(match client_result {
        Ok(_) => false,
        Err(code) => {
            error = code;
            true
        }
    });
    assert!(matches!(error, AuthClientError::AuthenticationError));
    println!("Client finished");
    server_handle.join().unwrap();
}

#[cfg(test)]
#[test]
fn test_client_server_mitm_service_name() {
    let pipe = ClientServerPipe::new(false);
    let server_end = ClientServerPipeServerEnd::new(&pipe);
    let server_handle = thread::spawn(move || {
        let mut ctx = mainvtun::get_test_context();
        insert_test_config(&mut ctx);
        let linkfdctx: LinkfdCtx = LinkfdCtx::new(&ctx);
        assert!(ctx.config.is_some());
        println!("Server started");
        let result = test_auth_server_chalresp(&ctx, &linkfdctx, &server_end, "testconnection2");
        server_end.close();
        let mut error = AuthServerError::GenRandom;
        assert!(match result {
            Ok(_) => false,
            Err(err) => {
                match err {
                    Ok(code) => {
                        error = code;
                        true
                    },
                    Err(_) => false
                }
            }
        });
        assert!(matches!(error, AuthServerError::AuthenticationError));
    });
    let client_end = ClientServerPipeClientEnd::new(&pipe);
    let mut ctx = mainvtun::get_test_context();
    insert_test_config(&mut ctx);
    let linkfdctx: LinkfdCtx = LinkfdCtx::new(&ctx);
    assert!(ctx.config.is_some());
    let host = match ctx.config {
        Some(ref config) => {
            let host = config.find_host("testconnection");
            assert!(host.is_some());
            Some(host.unwrap().clone())
        },
        None => None
    };
    assert!(host.is_some());
    let mut host = host.unwrap();
    println!("Client started");
    let mut error = AuthClientError::EncryptionError;
    assert!(match auth_client_chalresp(&ctx, &linkfdctx, &client_end, &mut host) {
        Ok(_) => false,
        Err(code) => {
            error = code;
            true
        }
    });
    client_end.close();
    assert!(matches!(error, AuthClientError::ReadError));
    println!("Client finished");
    server_handle.join().unwrap();
}
