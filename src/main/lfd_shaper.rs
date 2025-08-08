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
use std::{thread, time};
use std::time::SystemTime;
use crate::{lfd_mod, linkfd, syslog, vtun_host};
use crate::linkfd::LfdMod;

struct LfdShaper {
    pub bytes : usize,
    pub max_speed: u64,
    pub last_time: SystemTime
}

impl LfdShaper {
    pub fn new(host: *const vtun_host::VtunHost) -> LfdShaper {
        /* Calculate max speed bytes/sec */
        let spd_out = unsafe { (*host).spd_out } as u64;
        let mut max_speed: u64 = spd_out / 8 * 1024;

        /* Compensation for delays, nanosleep and so on */
        max_speed += 400;

        {
            let logmsg = format!("Traffic shaping(speed {}K) initialized.", spd_out);
            syslog::vtun_syslog(lfd_mod::LOG_INFO, logmsg.as_str());
        }

        LfdShaper {
            bytes: 0,
            max_speed,
            last_time: SystemTime::now()
        }
    }
    pub fn count(&mut self, len: usize) {
        /* Just count incoming bytes */
        self.bytes += len;
    }

    pub fn avail(&mut self) -> bool {
        let curr_time = SystemTime::now();
        let elapsed = match self.last_time.elapsed() {
            Ok(elap) => elap.as_millis() as u64,
            Err(_) => {
                self.last_time = curr_time;
                0
            }
        };

        let speed: u64;
        if elapsed > 0 {
            speed = (self.bytes as u64) * 1000 / elapsed;
        } else {
            speed = self.max_speed;
        };

        if speed >= self.max_speed && self.max_speed > 0 {
            /*
             * Sleep about 1 millisec(actual sleep might be longer).
             * This is actually the hack to reduce CPU usage.
             * Without this delay we will consume 100% CPU.
                 */
            thread::sleep(time::Duration::from_millis(1));

            /* Don't accept input */
            return false;
        }

        self.last_time = curr_time;
        if elapsed > 0 {
            self.bytes = 0;
        }

        /* Accept input */
        true
    }
}

pub(crate) struct LfdShaperFactory {
}

impl LfdShaperFactory {
    pub fn new() -> LfdShaperFactory {
        LfdShaperFactory {
        }
    }
}

impl linkfd::LfdModFactory for LfdShaperFactory {
    fn create(&self, host: &mut vtun_host::VtunHost) -> Result<Box<dyn LfdMod>,i32> {
        Ok(Box::new(LfdShaper::new(host)))
    }
}

impl LfdMod for LfdShaper {
    fn avail_encode(&mut self) -> bool {
        self.avail()
    }
    fn encode(&mut self, buf: &mut Vec<u8>) -> Result<(),()> {
        self.count(buf.len());
        Ok(())
    }
    fn decode(&mut self, _buf: &mut Vec<u8>) -> Result<(), ()> {
        Ok(())
    }

    fn request_send(&mut self) -> bool {
        false
    }
}
