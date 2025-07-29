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

use logos::Logos;

#[derive(Logos, Debug, PartialEq)]
pub enum Token {
    #[regex(r"[ \t\r\f]+", logos::skip)]
    #[regex(r"#.*", logos::skip)]
    #[regex(r"/\*([^*]|\n|\r|(\*+([^*/]|\n|\r)))*\*+/", logos::skip)]
    #[token("\n")]
    _Comment,

    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,

    #[token(";")]
    Semicolon,
    #[token(":")]
    Colon,

    // ----------------------------------------------------------------
    // Keywords (mirror the list from cfg_kwords.h)
    // ----------------------------------------------------------------
    #[token("default")]   KwDefault,
    #[token("options")]   KwOptions,
    #[token("port")]      KwPort,
    #[token("bindaddr")]  KwBindaddr,
    #[token("addr")]      KwAddr,
    #[token("iface")]     KwIface,
    #[token("vtun")]      KwVtun,
    #[token("tcp")]       KwTcp,
    #[token("udp")]       KwUdp,
    #[token("yes")]       KwYes,
    #[token("no")]        KwNo,
    #[token("server")]    KwServer,
    #[token("daemon")]    KwDaemon,
    #[token("syslog")]    KwSyslog,
    #[token("ppp")]       KwPpp,
    #[token("tun")]       KwTun,
    #[token("ether")]     KwEther,
    #[token("tty")]       KwTty,
    #[token("pipe")]      KwPipe,
    #[token("host")]      KwHost,
    #[token("timeout")]   KwTimeout,
    #[token("type")]      KwType,
    #[token("passwd")]    KwPasswd,
    #[token("compress")]  KwCompress,
    #[token("speed")]     KwSpeed,
    #[token("encrypt")]   KwEncrypt,
    #[token("keepalive")] KwKeepalive,
    #[token("stat")]      KwStat,
    #[token("proto")]     KwProto,
    #[token("multi")]     KwMulti,
    #[token("backup")]    KwBackup,
    #[token("program")]   KwProgram,
    #[token("route")]     KwRoute,
    #[token("ifconfig")]  KwIfconfig,
    #[token("ip")]        KwIp,
    #[token("firewall")]  KwFirewall,
    #[token("community")] KwCommunity,
    #[token("stat_user")] KwStatUser,
    #[token("stat_file")] KwStatFile,
    #[token("shaper")]    KwShaper,
    #[token("fd_pass")]   KwFdPass,
    #[token("queue")]     KwQueue,

    // ----------------------------------------------------------------
    // Literals
    // ----------------------------------------------------------------
    #[regex(r"((25[0-5])|(2[0-4][0-9])|([01]?[0-9][0-9]?)\.){3}((25[0-5])|(2[0-4][0-9])|([01]?[0-9][0-9]?))", priority = 3, callback = |lex| parse_ipv4(lex.slice()))]
    IPv4(u32),

    #[regex(r"[0-9]+", priority = 2, callback = |lex| parse_number(lex.slice()))]
    Number(u64),

    #[regex(r"([A-Za-z]:)?[A-Za-z0-9.\\/_-]+", priority = 1, callback = |lex| lex.slice().to_owned())]
    Ident(String),

    #[regex(r#""([^"\\]|\\.)*""#, |lex| unescape_dblq_string(lex.slice()))]
    Quoted(String),
}

fn parse_number(str: &str) -> u64 {
    str.parse().unwrap()
}

fn unescape_dblq_string(str: &str) -> String {
    let str = &str[1..str.len() - 1];
    let mut output = String::new();
    output.reserve(str.len());
    let mut escape = false;
    for ch in str.chars() {
        if !escape {
            match ch {
                '\\' => escape = true,
                _ => output.push(ch)
            }
        } else {
            match ch {
                'n' => output.push('\n'),
                'r' => output.push('\r'),
                't' => output.push('\t'),
                _ => output.push(ch)
            }
        }
        escape = false;
    }
    output
}

fn parse_ipv4(str: &str) -> u32 {
    let mut parts = str.split('.');
    let mut ip = 0;
    for part in parts {
        ip = ip << 8;
        let part: u8 = part.parse().unwrap();
        ip = ip + part as u32;
    }
    ip
}