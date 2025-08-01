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

/*
 * Functions to convert binary flags to character string.
 * string format:  <CS64> 
 * C - compression, S - speed for shaper and so on.
 */
use crate::challenge::VTUN_CHAL_SIZE;
use crate::{challenge, lfd_mod, libfuncs, linkfd, lock, setproctitle, syslog, vtun_host};
use crate::filedes::FileDes;
use crate::libfuncs::print_p;
use crate::linkfd::LinkfdCtx;
use crate::mainvtun::VtunContext;

const ST_INIT: i32 =  0;
const ST_HOST: i32 =  1;
const ST_CHAL: i32 =  2;

/* Authentication message size */
pub(crate) const VTUN_MESG_SIZE: usize =	50;

fn bf2cf(host: &vtun_host::VtunHost) -> Vec<u8>
{
    let mut str: Vec<u8> = Vec::new();
    str.reserve(20);

    str.push(b'<');

    let protflags = host.flags & linkfd::VTUN_PROT_MASK;
    if protflags == linkfd::VTUN_TCP {
        str.push(b'T');
    } else if protflags == linkfd::VTUN_UDP {
        str.push(b'U');
    }

    let typeflags = host.flags & linkfd::VTUN_TYPE_MASK;
    if typeflags == linkfd::VTUN_TTY {
        str.push(b't');
    } else if typeflags == linkfd::VTUN_PIPE {
        str.push(b'p');
    } else if typeflags == linkfd::VTUN_ETHER {
        str.push(b'e');
    } else if typeflags == linkfd::VTUN_TUN {
        str.push(b'u');
    }

    if (host.flags & linkfd::VTUN_SHAPE) != 0 /* && host->spd_in != 0 */ {
        let fmt = format!("S{}", host.spd_in);
        str.extend(fmt.as_bytes());
    }

    if (host.flags & linkfd::VTUN_ZLIB) != 0 {
        let fmt = format!("C{}", host.zlevel);
        str.extend(fmt.as_bytes());
    }

    if (host.flags & linkfd::VTUN_LZO) != 0 {
        let fmt = format!("L{}", host.zlevel);
        str.extend(fmt.as_bytes());
    }

    if (host.flags & linkfd::VTUN_KEEP_ALIVE) != 0 {
        str.push(b'K');
    }

    if (host.flags & linkfd::VTUN_ENCRYPT) != 0 {
        if host.cipher == lfd_mod::VTUN_LEGACY_ENCRYPT { /* use old flag method */
            str.push(b'E');
        } else {
            let fmt = format!("E{}", host.cipher);
            str.extend(fmt.as_bytes());
        }
    }

    str.push(b'>');

    str
}

/* return 1 on success, otherwise 0 
   Example:
   FLAGS: <TuE1>
*/

fn length_of_number(str: &[u8]) -> usize {
    for i in 0..str.len() {
        if str[i] < b'0' || str[i] > b'9' {
            return i;
        }
    }
    str.len()
}

fn cf2bf(str: &[u8], host: &mut vtun_host::VtunHost) -> bool
{
    let mut off: usize = 0;

    while off < str.len() && str[off] != b'<' {
        off = off + 1;
    }
    {
        let msg = format!("Remote Server send {}.", str::from_utf8(&str[off..str.len()]).unwrap());
        syslog::vtun_syslog(lfd_mod::LOG_DEBUG, msg.as_str());
    }
    off = off + 1;
    while off < str.len() {
        if str[off] == b't' {
            host.flags = host.flags | linkfd::VTUN_TTY;
        } else if str[off] == b'p' {
            host.flags = host.flags | linkfd::VTUN_PIPE;
        } else if str[off] == b'e' {
            host.flags = host.flags | linkfd::VTUN_ETHER;
        } else if str[off] == b'u' {
            host.flags = host.flags | linkfd::VTUN_TUN;
        } else if str[off] == b'U' {
            host.flags = host.flags & !linkfd::VTUN_PROT_MASK;
            host.flags = host.flags | linkfd::VTUN_UDP;
        } else if str[off] == b'T' {
            host.flags = host.flags & !linkfd::VTUN_PROT_MASK;
            host.flags = host.flags | linkfd::VTUN_TCP;
        } else if str[off] == b'K' {
            host.flags = host.flags | linkfd::VTUN_KEEP_ALIVE;
        } else if str[off] == b'C' {
            let num_len = length_of_number(&str[off + 1..str.len()]);
            if num_len == 0 {
                return false;
            }
            let num = str[off + 1..off + 1 + num_len].iter().fold(0, |acc, &x| acc * 10 + (x - b'0') as i32);
            host.flags = host.flags | linkfd::VTUN_ZLIB;
            host.zlevel = num;
            off = off + num_len;
        } else if str[off] == b'L' {
            let num_len = length_of_number(&str[off + 1..str.len()]);
            if num_len == 0 {
                return false;
            }
            let num = str[off + 1..off + 1 + num_len].iter().fold(0, |acc, &x| acc * 10 + (x - b'0') as i32);
            host.flags = host.flags | linkfd::VTUN_LZO;
            host.zlevel = num;
            off = off + num_len;
        } else if str[off] == b'E' {
            let num_len = length_of_number(&str[off + 1..str.len()]);
            if num_len != 0 {
                let num = str[off + 1..off + 1 + num_len].iter().fold(0, |acc, &x| acc * 10 + (x - b'0') as i32);
                host.flags = host.flags | linkfd::VTUN_ENCRYPT;
                host.cipher = num;
                off = off + num_len;
            } else {
                host.flags = host.flags | linkfd::VTUN_ENCRYPT;
                host.cipher = lfd_mod::VTUN_LEGACY_ENCRYPT;
            }
        } else if str[off] == b'S' {
            let num_len = length_of_number(&str[off + 1..str.len()]);
            if num_len == 0 {
                return false;
            }
            let num = str[off + 1..off + 1 + num_len].iter().fold(0, |acc, &x| acc * 10 + (x - b'0') as i32);
            host.flags = host.flags | linkfd::VTUN_SHAPE;
            host.spd_out = num;
            off = off + num_len;
        } else if str[off] == b'F' {
            /* reserved for Feature transmit */
        } else if str[off] == b'>' {
            return true;
        } else {
            return false;
        }
        off = off + 1;
    }
    false
}

/* 
 * Functions to convert binary key data to character string.
 * string format:  <char_data> 
 */

fn cl2cs(chal: &[u8]) -> Vec<u8>
{
    let mut str: Vec<u8> = Vec::new();
    str.reserve(VTUN_CHAL_SIZE*2+2);
    let chr = "abcdefghijklmnop".as_bytes();

    str.push(b'<');
    for i in 0..VTUN_CHAL_SIZE {
        str.push(chr[(chal[i] >> 4) as usize]);
        str.push(chr[(chal[i] & 0x0f) as usize]);
    }

    str.push(b'>');

    str
}

fn cs2cl(str: &[u8], chal: &mut Vec<u8>) -> bool {
    let mut off: usize = 0;

    while off < str.len() && str[off] != b'<' {
        off = off + 1;
    }
    off = off + 1;
    if off >= str.len() {
        return false;
    }

    if chal.capacity() < VTUN_CHAL_SIZE {
        chal.reserve(VTUN_CHAL_SIZE);
    }
    chal.clear();
    for _ in 0..VTUN_CHAL_SIZE {
        if (off + 1) >= str.len() {
            return false;
        }
        chal.push(((str[off] - b'a') << 4) + (str[off + 1] - b'a'));
        off = off + 2;
    }
    true
}

fn get_tokenize_length(slice: &mut [u8]) -> usize {
    let mut len = slice.len();
    for i in 0..slice.len() {
        if slice[i] == b'\0' {
            len = i;
            break;
        }
        if slice[i] == b' ' || slice[i] == b':' {
            slice[i] = b'\0';
            len = i;
            break;
        }
    }
    len
}
/* Authentication (Server side) */
pub fn auth_server(ctx: &VtunContext, linkfdctx: &LinkfdCtx, fd: &FileDes) -> Option<vtun_host::VtunHost> {
    setproctitle::set_title("authentication");

    let fmt = format!("VTUN server ver {}\n", lfd_mod::VTUN_VER);
    print_p(fd, fmt.as_bytes());

    let mut stage = ST_HOST;
    let mut host = String::new();
    let mut h: Option<&vtun_host::VtunHost> = None;
    let mut chal_req: [u8; VTUN_CHAL_SIZE] = [0u8; VTUN_CHAL_SIZE];

    let mut buf = [0u8; VTUN_MESG_SIZE];
    loop {
        if libfuncs::readn_t(linkfdctx, fd, &mut buf, ctx.vtun.timeout as libc::time_t + 1) <= 0 {
            break;
        }
        buf[buf.len() - 1] = b'\0';
        let mut str1: Vec<u8>;
        let mut str2: Vec<u8>;
        {
            let mut slice: Vec<u8>;
            {
                let mut len: usize = VTUN_MESG_SIZE - 1;
                for i in 0..(VTUN_MESG_SIZE - 1) {
                    if buf[i] == b'\0' {
                        len = i;
                        break;
                    }
                    if buf[i] == b'\r' || buf[i] == b'\n' {
                        buf[i] = b'\0';
                        len = i;
                        break;
                    }
                }
                slice = Vec::new();
                slice.resize(len, 0u8);
                for i in 0..len {
                    slice[i] = buf[i];
                }
            }
            let len = get_tokenize_length(&mut slice);
            str1 = Vec::new();
            str1.resize(len, 0u8);
            for i in 0..len {
                str1[i] = slice[i];
            }
            if (slice.len() - len) > 1 {
                let mut chop = 1;
                for i in (len+1)..slice.len() {
                    if slice[i] != b'\0' && slice[i] != b' ' && slice[i] != b':' {
                        chop = i - len;
                        break;
                    }
                }
                for i in (len + chop)..slice.len() {
                    slice[i - len - chop] = slice[i];
                }
                slice.truncate(slice.len() - len - chop);
                let len = get_tokenize_length(&mut slice);
                str2 = Vec::new();
                str2.resize(len, 0u8);
                for i in 0..len {
                    str2[i] = slice[i];
                }
            } else {
                str2 = Vec::new();
            }
        }

        if stage == ST_HOST {
            if str1.len() == 4 && str1[0] == b'H' && str1[1] == b'O' && str1[2] == b'S' && str1[3] == b'T' {
                host = str::from_utf8(&str2).unwrap().to_string();

                challenge::gen_chal(&mut chal_req);
                let mut msg: Vec<u8> = Vec::new();
                msg.reserve(32);
                {
                    let part = "OK CHAL: ".as_bytes();
                    for i in 0..part.len() {
                        msg.push(part[i]);
                    }
                }
                let mut req = cl2cs(&chal_req);
                msg.append(&mut req);
                msg.push(b'\n');
                print_p(fd, msg.as_slice());
                stage = ST_CHAL;
                continue;
            }
        } else if stage == ST_CHAL {
            if str1.len() == 4 && str1[0] == b'C' && str1[1] == b'H' && str1[2] == b'A' && str1[3] == b'L' {
                let mut chal_res: Vec<u8> = Vec::new();
                if !cs2cl(&str2, &mut chal_res) {
                    break;
                }

                h = match ctx.config {
                    Some(ref config) => config.find_host(&host),
                    None => break
                };

                match h {
                    Some(ref mut h) => match h.passwd {
                        Some(ref passwd) => challenge::decrypt_chal(chal_res.as_mut_slice(), passwd.as_str()),
                        None => break
                    },
                    None => break
                };

                for i in 0..VTUN_CHAL_SIZE {
                    if chal_req[i] != chal_res[i] {
                        h = None;
                        break;
                    }
                }
                /* Lock host */
                if match h {
                    Some(ref mut h) => !lock::lock_host_rs(h),
                    None => true
                } {
                    /* Multiple connections are denied */
                    h = None;
                    break;
                }
                let mut msg: Vec<u8> = Vec::new();
                {
                    let part = "OK FLAGS: ".as_bytes();
                    for i in 0..part.len() {
                        msg.push(part[i]);
                    }
                }
                {
                    let part = match h {
                        Some(ref h) => bf2cf(h),
                        None => break
                    };
                    for i in 0..part.len() {
                        msg.push(part[i]);
                    }
                }
                msg.push(b'\n');
                print_p(fd, msg.as_slice());
                break;
            }
            break;
        }
    }

    match h {
        Some(ref mut h) => Some((*h).clone()),
        None => {
            print_p(fd, "ERR\n".as_bytes());
            None
        }
    }
}

/* Authentication (Client side) */
pub(crate) fn auth_client_rs(ctx: &VtunContext, linkfdctx: &LinkfdCtx, fd: &FileDes, host: &mut vtun_host::VtunHost) -> bool {
    let mut success = false;
    let mut stage = ST_INIT;

    let mut buf = [0u8; VTUN_MESG_SIZE];
    while libfuncs::readn_t(linkfdctx, fd, &mut buf, ctx.vtun.timeout as libc::time_t) > 0 {
        buf[buf.len() - 1] = b'\0';
        if stage == ST_INIT {
            if buf[0] == b'V' && buf[1] == b'T' && buf[2] == b'U' && buf[3] == b'N' {
                stage = ST_HOST;
                let mut msg: Vec<u8> = Vec::new();
                msg.reserve(32);
                msg.push(b'H');
                msg.push(b'O');
                msg.push(b'S');
                msg.push(b'T');
                msg.push(b':');
                msg.push(b' ');
                let host = match host.host {
                    Some(ref host) => host.as_bytes(),
                    None => break
                };
                for i in 0..host.len() {
                    msg.push(host[i]);
                }
                msg.push(b'\n');
                print_p(fd, msg.as_slice());
                continue;
            }
        } else if stage == ST_HOST {
            let mut chal: Vec<u8> = Vec::new();
            if buf[0] == b'O' && buf[1] == b'K' && cs2cl(&buf, &mut chal) {
                stage = ST_CHAL;

                match host.passwd {
                    Some(ref passwd) => challenge::encrypt_chal(chal.as_mut_slice(), passwd.as_str()),
                    None => break
                };
                let mut msg: Vec<u8> = Vec::new();
                msg.reserve(32);
                msg.push(b'C');
                msg.push(b'H');
                msg.push(b'A');
                msg.push(b'L');
                msg.push(b':');
                msg.push(b' ');
                msg.append(&mut cl2cs(chal.as_slice()));
                print_p(fd, msg.as_slice());

                continue;
            }
        } else if stage == ST_CHAL {
            if buf[0] == b'O' && buf[1] == b'K' && cf2bf(&buf, host) {
                success = true;
            }
            break;
        }
        break;
    }

    success
}
