use std::ffi::CStr;
use std::fmt::Debug;
use std::fs::OpenOptions;
use std::io::Write;
use std::{mem, ptr};
use std::sync::atomic::{AtomicBool, AtomicI32};
use std::time::SystemTime;
use errno::{errno, set_errno};
use libc::{SIGALRM, SIGHUP, SIGINT, SIGTERM, SIGUSR1};
use signal_hook::{low_level, SigId};
use time::OffsetDateTime;
use crate::{driver, lfd_encrypt, lfd_legacy_encrypt, lfd_lzo, lfd_mod, lfd_shaper, lfd_zlib, linkfd};
use crate::lfd_mod::{LINKFD_FRAME_APPEND, LINKFD_FRAME_RESERV};

pub const LINKFD_PRIO: libc::c_int = -1;

pub const VTUN_TTY: libc::c_int =       0x0100;
pub const VTUN_PIPE: libc::c_int =      0x0200;
pub const VTUN_ETHER: libc::c_int =     0x0400;
pub const VTUN_TUN: libc::c_int =       0x0800;
pub const VTUN_TYPE_MASK: libc::c_int = (VTUN_TTY | VTUN_PIPE | VTUN_ETHER | VTUN_TUN);

pub const VTUN_TCP: libc::c_int =       0x0010;
pub const VTUN_UDP: libc::c_int  =      0x0020;
pub const VTUN_PROT_MASK: libc::c_int = (VTUN_TCP | VTUN_UDP);
pub const VTUN_KEEP_ALIVE: libc::c_int = 0x0040;

pub const VTUN_ZLIB: libc::c_int = 0x0001;
pub const VTUN_LZO: libc::c_int = 0x0002;
pub const VTUN_SHAPE: libc::c_int = 0x0004;
pub const VTUN_ENCRYPT: libc::c_int = 0x0008;

pub const VTUN_SIG_TERM: i32 = 1;
pub const VTUN_SIG_HUP: i32 =  2;

pub const VTUN_STAT: libc::c_int =	0x1000;
pub const VTUN_PERSIST: libc::c_int =    0x2000;

pub const VTUN_STAT_IVAL: libc::c_uint =  5*60;  /* 5 min */

pub const VTUN_NAT_HACK_CLIENT: libc::c_int =	0x4000;
pub const VTUN_NAT_HACK_SERVER: libc::c_int =	0x8000;
pub const VTUN_NAT_HACK_MASK: libc::c_int =	(VTUN_NAT_HACK_CLIENT | VTUN_NAT_HACK_SERVER);

pub const VTUN_FRAME_SIZE: usize =     2048;
pub const VTUN_FRAME_OVERHEAD: usize = 100;
pub const VTUN_FSIZE_MASK: libc::c_int = 0x0fff;

pub const VTUN_CONN_CLOSE: libc::c_int = 0x1000;
pub const VTUN_ECHO_REQ: libc::c_int =	0x2000;
pub const VTUN_ECHO_REP: libc::c_int =	0x4000;
pub const VTUN_BAD_FRAME: libc::c_int =  0x8000;

const VTUN_STAT_DIR: &str = env!("VTUN_STAT_DIR");
const ENABLE_NAT_HACK: &str = env!("ENABLE_NAT_HACK");

pub fn is_enabled_nat_hack(host: &mut lfd_mod::VtunHost) -> bool {
    if (ENABLE_NAT_HACK == "true")
    {
        return (host.flags & VTUN_NAT_HACK_MASK) != 0;
    }
    return false;
}

pub static mut send_a_packet: bool = false;
pub static mut host_flags: libc::c_int = 0;
pub static mut host_ka_interval: libc::c_int = 0;

pub trait LfdMod {
    fn avail_encode(&mut self) -> bool {
        true
    }
    fn encode(&mut self, buf: &mut Vec<u8>) -> bool {
        true
    }
    fn avail_decode(&mut self) -> bool {
        true
    }
    fn decode(&mut self, buf: &mut Vec<u8>) -> bool {
        true
    }
}

pub trait LfdModFactory {
    fn name(&self) -> &'static str;
    fn create(&self, host: &mut lfd_mod::VtunHost) -> Option<Box<dyn linkfd::LfdMod>>;
}

struct LinkfdFactory {
    pub mod_factories: Vec<Box<dyn LfdModFactory>>
}

impl LinkfdFactory {
    pub fn new() -> LinkfdFactory {
        LinkfdFactory {
            mod_factories: Vec::new()
        }
    }
    pub fn add(&mut self, mod_factory: Box<dyn LfdModFactory>) {
        self.mod_factories.push(mod_factory);
    }
}

pub struct Linkfd {
    pub mods: Vec<Box<dyn LfdMod>>
}

impl Linkfd {
    pub fn new(factory: &LinkfdFactory, host: &mut lfd_mod::VtunHost) -> Linkfd {
        let mut linkfd = Linkfd {
            mods: Vec::new()
        };
        linkfd.mods.reserve(factory.mod_factories.len());
        for mod_factory in factory.mod_factories.iter() {
            match mod_factory.create(host) {
                Some(m) => linkfd.mods.push(m),
                None => ()
            }
        }
        return linkfd;
    }
    fn avail_encode(&mut self) -> bool {
        for m in self.mods.iter_mut() {
            if !m.avail_encode() {
                return false;
            }
        }
        return true;
    }
    fn encode(&mut self, buf: &mut Vec<u8>) -> bool {
        for m in self.mods.iter_mut() {
            if (!m.encode(buf)) {
                return false;
            }
        }
        return true;
    }
    fn avail_decode(&mut self) -> bool {
        for m in self.mods.iter_mut() {
            if !m.avail_encode() {
                return false;
            }
        }
        return true;
    }
    fn decode(&mut self, buf: &mut Vec<u8>) -> bool {
        for m in self.mods.iter_mut().rev() {
            if (!m.decode(buf)) {
                return false;
            }
        }
        return true;
    }
}

static mut io_cancelled : AtomicBool = AtomicBool::new(false);
static mut linker_term : AtomicI32 = AtomicI32::new(0);

pub fn io_cancel() {
    unsafe { io_cancelled.store(true, std::sync::atomic::Ordering::SeqCst); }
}

#[no_mangle]
pub extern "C" fn io_init() {
    unsafe { io_cancelled.store(false, std::sync::atomic::Ordering::SeqCst); }
}

pub fn sig_term() {
    unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "Closing connection\n\0".as_ptr() as *mut libc::c_char); }
    io_cancel();
    unsafe { linker_term.store(VTUN_SIG_TERM, std::sync::atomic::Ordering::SeqCst); }
}

pub fn sig_hup() {
    unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "Reestablishing connection".as_ptr() as *mut libc::c_char); }
    io_cancel();
    unsafe { linker_term.store(VTUN_SIG_HUP, std::sync::atomic::Ordering::SeqCst); }
}

static mut sig_alarm_tm_old: SystemTime = SystemTime::UNIX_EPOCH;
static mut sig_alarm_tm: SystemTime = SystemTime::UNIX_EPOCH;
static mut ka_timer: i64 = 0;
static mut stat_timer: i64 = 0;
static mut ka_need_verify: AtomicBool = AtomicBool::new(false);
static mut stat_file: Option<std::fs::File> = None;
static mut stat_byte_in: u64 = 0;
static mut stat_byte_out: u64 = 0;
static mut stat_comp_in: u64 = 0;
static mut stat_comp_out: u64 = 0;


pub fn sig_alarm() {
    let mut tm_old: SystemTime;
    let mut tm: SystemTime;
    let mut ka_timer_value: i64;
    let mut stat_timer_value: i64;
    let mut flags: i32;
    tm = SystemTime::now();
    unsafe {
        tm_old = sig_alarm_tm;
        sig_alarm_tm_old = tm_old;
        sig_alarm_tm = tm;
        ka_timer -= tm_old.elapsed().unwrap().as_secs() as i64;
        stat_timer -= tm_old.elapsed().unwrap().as_secs() as i64;
        ka_timer_value = ka_timer;
        stat_timer_value = stat_timer;
        flags = host_flags;
    }

    if (flags & VTUN_KEEP_ALIVE) != 0 && ka_timer_value <= 0 {
        unsafe {
            ka_need_verify.store(true, std::sync::atomic::Ordering::SeqCst);
            ka_timer = (host_ka_interval as i64)
                + 1; /* We have to complete select() on idle */
            ka_timer_value = ka_timer;
        }
    }

    if( (flags & VTUN_STAT) != 0 && stat_timer_value <= 0){
        let dt: OffsetDateTime = tm.into();
        let fmt = time::macros::format_description!("[month] [day] [hour]:[minute]:[second]");
        let stm = match dt.format(fmt) {
            Err(_) => "No time".to_string(),
            Ok(str) => str
        };
        let statmsg = unsafe {format!("{} {} {} {} {}", stm, stat_byte_in, stat_byte_out, stat_comp_in, stat_comp_out)};
        unsafe {
            match stat_file {
                None => {},
                Some(ref mut f) => match f.write(statmsg.as_bytes()) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            };
            stat_timer = VTUN_STAT_IVAL as i64;
            stat_timer_value = stat_timer;
        }
    }

    if ka_timer_value > 0 && stat_timer_value > 0 {
        if ka_timer_value < stat_timer_value {
            unsafe { libc::alarm(ka_timer_value as libc::c_uint); }
        } else {
            unsafe { libc::alarm(stat_timer_value as libc::c_uint); }
        }
    } else {
        if ka_timer_value > 0 {
            unsafe { libc::alarm(ka_timer_value as libc::c_uint); }
        } else if stat_timer_value > 0 {
            unsafe { libc::alarm(stat_timer_value as libc::c_uint); }
        }
    }
}

fn sig_usr1() {
    /* Reset statistic counters on SIGUSR1 */
    unsafe {
        stat_byte_in = 0;
        stat_byte_out = 0;
        stat_comp_in = 0;
        stat_comp_out = 0;
    }
}

#[no_mangle]
pub extern "C" fn is_io_cancelled() -> libc::c_int {
    let val = unsafe { io_cancelled.load(std::sync::atomic::Ordering::SeqCst) };
    if (val == true) {
        return 1;
    } else {
        return 0;
    }
}

/* Link remote and local file descriptors */
#[no_mangle]
pub extern "C" fn linkfd(hostptr: *mut lfd_mod::VtunHost) -> libc::c_int
{
    //struct sigaction sa, sa_oldterm, sa_oldint, sa_oldhup;
    //int old_prio;
    let host: &mut lfd_mod::VtunHost = unsafe { &mut *hostptr };

    //lfd_host = host;

    let old_prio = unsafe { libc::getpriority(libc::PRIO_PROCESS,0) };
    unsafe {libc::setpriority(libc::PRIO_PROCESS,0, LINKFD_PRIO); }

    let mut factory = LinkfdFactory::new();

    /* Build modules stack */
    let flags = host.flags;
    unsafe { host_flags = flags; }
    if (flags & VTUN_ZLIB) != 0 {
        factory.add(Box::new(lfd_zlib::LfdZlibFactory::new()));
    }

    if (flags & VTUN_LZO) != 0 {
        factory.add(Box::new(lfd_lzo::LfdLzoFactory::new()));
    }

    if (flags & VTUN_ENCRYPT) != 0 {
        let cipher = (*host).cipher;
        if cipher == lfd_mod::VTUN_LEGACY_ENCRYPT {
            factory.add(Box::new(lfd_legacy_encrypt::LfdLegacyEncryptFactory::new()));
        } else {
            factory.add(Box::new(lfd_encrypt::LfdEncryptFactory::new()));
        }
    }

    if(flags & VTUN_SHAPE) != 0 {
        factory.add(Box::new(lfd_shaper::LfdShaperFactory::new()));
    }

    let sigtermRestore = match unsafe { low_level::register(SIGTERM, || sig_term()) } {
        Ok(id) => Some(id),
        Err(_) => None
    };
    let sigintRestore = match unsafe { low_level::register(SIGINT, || sig_term()) } {
        Ok(id) => Some(id),
        Err(_) => None
    };
    let sighupRestore = match unsafe { low_level::register(SIGHUP, || sig_hup()) } {
        Ok(id) => Some(id),
        Err(_) => None
    };

    
    let mut sigalrmRestore: Option<SigId> = None;
    /* Initialize keep-alive timer */
    if (flags & (VTUN_STAT|VTUN_KEEP_ALIVE)) != 0 {
        sigalrmRestore = match unsafe { low_level::register(SIGALRM, || sig_alarm()) } {
            Ok(id) => Some(id),
            Err(_) => None
        };

        if host.ka_interval > 0 && (host.ka_interval as libc::c_uint) < VTUN_STAT_IVAL {
            unsafe { libc::alarm(host.ka_interval as libc::c_uint); }
        } else {
            unsafe { libc::alarm(VTUN_STAT_IVAL); }
        }
    }

    let mut sigusr1Restore: Option<SigId> = None;
    /* Initialize statstic dumps */
    unsafe {
        if (flags & VTUN_STAT) != 0 {
            sigusr1Restore = match unsafe { low_level::register(SIGUSR1, || sig_usr1()) } {
                Ok(id) => Some(id),
                Err(_) => None
            };

            let host_name = match CStr::from_ptr(host.host).to_str() {
                Ok(s) => s,
                Err(_) => "vtun.unknown"
            };
            let file = format!("{}/{}", VTUN_STAT_DIR, host_name);
            match OpenOptions::new()
                .append(true)
                .open(file.clone()) {
                Ok(f) => stat_file = Some(f),
                Err(_) => {
                    let msg = format!("Can't open stats file {}", file);
                    unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, msg.as_ptr() as *mut libc::c_char); }
                    stat_file = None;
                }
            };
        }
    }

    let mut lfd_stack: Linkfd = Linkfd::new(& mut factory, host);

    io_init();

    lfd_linker(&mut lfd_stack, host);

    if (flags & (VTUN_STAT|VTUN_KEEP_ALIVE)) != 0 {
        unsafe {
            libc::alarm(0);
            stat_file = None;
        }
    }

    match sigtermRestore {
        Some(sigId) => low_level::unregister(sigId),
        None => false
    };
    match sigintRestore {
        Some(sigId) => low_level::unregister(sigId),
        None => false
    };
    match sighupRestore {
        Some(sigId) => low_level::unregister(sigId),
        None => false
    };

    unsafe {
        libc::setpriority(libc::PRIO_PROCESS,0,old_prio);
        let term: i32 = linker_term.load(std::sync::atomic::Ordering::SeqCst);
        return term;
    }
}

fn lfd_linker(lfd_stack: &mut Linkfd, host: &mut lfd_mod::VtunHost) -> libc::c_int
{
    let fd1 = host.rmt_fd;
    let fd2 = host.loc_fd;
    //register int len, fl;
    let mut tv: libc::timeval;
    //char *buf, *out;
    let mut fdset = mem::MaybeUninit::<libc::fd_set>::uninit();
    unsafe { libc::FD_ZERO(&mut (fdset.assume_init())); }
    let mut fdset = unsafe { fdset.assume_init() };
    let mut idle: i32 = 0;

    let mut buf: Vec<u8> = Vec::new();
    buf.reserve(VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD + lfd_mod::LINKFD_FRAME_RESERV + lfd_mod::LINKFD_FRAME_APPEND);

    /* Delay sending of first UDP packet over broken NAT routers
    because we will probably be disconnected.  Wait for the remote
    end to send us something first, and use that connection. */
    if (!is_enabled_nat_hack(host)) {
        unsafe {
            buf.resize(VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD + lfd_mod::LINKFD_FRAME_RESERV + lfd_mod::LINKFD_FRAME_APPEND, 0u8);
            driver::proto_write(fd1, buf.as_ptr().add(LINKFD_FRAME_RESERV) as *mut libc::c_char, VTUN_ECHO_REQ);
        }
    }

    let maxfd =  (if fd1 > fd2 { fd1 } else { fd2 }) + 1;

    unsafe { linker_term.store(0, std::sync::atomic::Ordering::SeqCst); }
    while( unsafe { linker_term.load(std::sync::atomic::Ordering::SeqCst) == 0 } ) {
        //errno = 0;

        /* Wait for data */
        unsafe {
            libc::FD_ZERO(&mut fdset);
            libc::FD_SET(fd1, &mut fdset);
            libc::FD_SET(fd2, &mut fdset);
        }

        tv = libc::timeval {
            tv_sec: host.ka_interval as libc::time_t,
            tv_usec: 0,
        };

        set_errno(errno::Errno(0));
        let nullfds: *mut libc::fd_set = ptr::null_mut();
        let len = unsafe { libc::select(maxfd, &mut fdset, nullfds, nullfds, &mut tv) };
        if len < 0 {
            let errno = errno();
            if errno != errno::Errno(libc::EAGAIN) && errno != errno::Errno(libc::EINTR) {
                break;
            } else {
                continue;
            }
        }

        if unsafe { ka_need_verify.load(std::sync::atomic::Ordering::SeqCst) } {
            if idle > host.ka_maxfail {
                unsafe {
                    let msg = format!("Session {} network timeout\n\0", CStr::from_ptr(host.host).to_str().unwrap_or(""));
                    lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, msg.as_ptr() as *mut libc::c_char);
                }
                break;
            }
            idle += 1;
            if (idle > 0) {
                /* No input frames, check connection with ECHO */
                let retv: libc::c_int;
                unsafe {
                    buf.resize(VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD + lfd_mod::LINKFD_FRAME_RESERV + lfd_mod::LINKFD_FRAME_APPEND, 0u8);
                    retv = driver::proto_write(fd1, buf.as_ptr().add(LINKFD_FRAME_RESERV) as *mut libc::c_char, VTUN_ECHO_REQ);
                }
                if retv < 0 {
                    unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "Failed to send ECHO_REQ\n\0".as_ptr() as *mut libc::c_char); }
                    break;
                }
            }
            unsafe { ka_need_verify.store(false, std::sync::atomic::Ordering::SeqCst); }
        }

        if (unsafe { send_a_packet })
        {
            unsafe { send_a_packet = false; }
            let tmplen = 1;
            unsafe { stat_byte_out += tmplen; }
            buf.resize(1, 0u8);
            let encoded: usize;
            if (!lfd_stack.encode(&mut buf)) {
                break;
            }
            let encoded = buf.len();
            buf.resize(encoded + LINKFD_FRAME_RESERV, 0u8);
            for i in 0..encoded {
                buf[encoded - i - 1 + LINKFD_FRAME_RESERV] = buf[encoded - i - 1];
            }
            buf.resize(buf.len() + LINKFD_FRAME_APPEND, 0u8);
            if (encoded > 0) {
                let retv: libc::c_int;
                unsafe {
                    retv = driver::proto_write(fd1, buf.as_ptr().add(LINKFD_FRAME_RESERV) as *mut libc::c_char, encoded as libc::c_int);
                }
                if (retv < 0) {
                    break;
                }
                unsafe { stat_comp_out += encoded as u64; }
            }
        }

        /* Read frames from network(fd1), decode and pass them to
         * the local device (fd2) */
        if (unsafe { libc::FD_ISSET(fd1, &fdset) } && lfd_stack.avail_decode()) {
            idle = 0;
            unsafe { ka_need_verify.store(false, std::sync::atomic::Ordering::SeqCst); }
            buf.resize(VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD + lfd_mod::LINKFD_FRAME_RESERV + lfd_mod::LINKFD_FRAME_APPEND, 0u8);
            let mut len = unsafe { driver::proto_read(fd1, buf.as_ptr().add(LINKFD_FRAME_RESERV) as *mut libc::c_char) };
            if (len <= 0) {
                break;
            }
            let fl = len & (!VTUN_FSIZE_MASK);
            if (fl != VTUN_BAD_FRAME && fl != VTUN_ECHO_REQ && fl != VTUN_ECHO_REP && fl != VTUN_CONN_CLOSE) {
                for i in 0..len as usize {
                    buf[i] = buf[i + LINKFD_FRAME_RESERV];
                }
                buf.resize(len as usize, 0u8);
            }

            /* Handle frame flags */
            len = len & VTUN_FSIZE_MASK;
            if fl != 0 {
                if fl == VTUN_BAD_FRAME {
                    unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_ERR, "Received bad frame\n\0".as_ptr() as *mut libc::c_char); }
                    continue;
                }
                if (fl == VTUN_ECHO_REQ) {
                    /* Send ECHO reply */
                    let retv;
                    unsafe {
                        buf.resize(VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD + lfd_mod::LINKFD_FRAME_RESERV + lfd_mod::LINKFD_FRAME_APPEND, 0u8);
                        retv = driver::proto_write(fd1, buf.as_ptr().add(LINKFD_FRAME_RESERV) as *mut libc::c_char, VTUN_ECHO_REP);
                    }
                    if retv < 0 {
                        break;
                    }
                    continue;
                }
                if (fl == VTUN_ECHO_REP) {
                    /* Just ignore ECHO reply, ka_need_verify==0 already */
                    continue;
                }
                if (fl == VTUN_CONN_CLOSE) {
                    unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, "Connection closed by other side\n\0".as_ptr() as *mut libc::c_char); }
                    break;
                }
            }

            unsafe { stat_comp_in += len as u64; }
            buf.resize(len as usize, 0u8);
            if !lfd_stack.decode(&mut buf) {
                break;
            }
            let decoded = buf.len();
            buf.resize(decoded + LINKFD_FRAME_RESERV, 0u8);
            for i in 0..decoded {
                buf[decoded - i - 1 + LINKFD_FRAME_RESERV] = buf[decoded - i - 1];
            }
            buf.resize(buf.len() + LINKFD_FRAME_APPEND, 0u8);
            if (decoded > 0) {
                let retv;
                unsafe {
                    retv = driver::dev_write(fd2, buf.as_ptr().add(LINKFD_FRAME_RESERV) as *mut libc::c_char, decoded as libc::c_int);
                    stat_byte_in += decoded as u64;
                }
                if (retv < 0) {
                    let errno = errno();
                    if (errno != errno::Errno(libc::EAGAIN) && errno != errno::Errno(libc::EINTR)) {
                        break;
                    } else {
                        continue;
                    }
                }
                unsafe { stat_byte_in += decoded as u64; }
            }
        }

        /* Read data from the local device(fd2), encode and pass it to
         * the network (fd1) */
        if (unsafe { libc::FD_ISSET(fd2, &fdset) } && lfd_stack.avail_encode()) {
            buf.resize(VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD + lfd_mod::LINKFD_FRAME_RESERV + lfd_mod::LINKFD_FRAME_APPEND, 0u8);
            let mut len = unsafe { driver::dev_read(fd2, buf.as_ptr().add(LINKFD_FRAME_RESERV) as *mut libc::c_char, VTUN_FRAME_SIZE as libc::c_int) };

            if (len < 0) {
                let errno = errno();
                if (errno != errno::Errno(libc::EAGAIN) && errno != errno::Errno(libc::EINTR)) {
                    break;
                } else {
                    continue;
                }
            }
            if (len == 0) {
                break;
            }
            for i in 0..len as usize {
                buf[i] = buf[i + LINKFD_FRAME_RESERV];
            }
            buf.resize(len as usize, 0u8);

            unsafe { stat_byte_out += len as u64; }


            if !lfd_stack.encode(&mut buf) {
                break;
            }
            let encoded = buf.len();
            buf.resize(encoded + LINKFD_FRAME_RESERV, 0u8);
            for i in 0..encoded {
                buf[encoded - i - 1 + LINKFD_FRAME_RESERV] = buf[encoded - i - 1];
            }
            buf.resize(buf.len() + LINKFD_FRAME_APPEND, 0u8);
            if (encoded > 0) {
                let retv;
                unsafe {
                    retv = driver::proto_write(fd1, buf.as_ptr().add(LINKFD_FRAME_RESERV) as *mut libc::c_char, encoded as libc::c_int);
                    stat_comp_out += encoded as u64;
                }
                if (retv < 0) {
                    break;
                }
            }
        }
    }
    if( unsafe {(*linker_term.as_ptr())} != 0 && errno() != errno::Errno(0) ) {
        let errno = errno();
        let msg = format!("{}: {}\n\0", errno.to_string(), errno);
        unsafe { lfd_mod::vtun_syslog(lfd_mod::LOG_INFO, msg.as_ptr() as *mut libc::c_char); }
    }

    if ( unsafe {linker_term.load(std::sync::atomic::Ordering::SeqCst)} == VTUN_SIG_TERM) {
        host.persist = 0;
    }

    /* Notify other end about our close */
    buf.resize(VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD + lfd_mod::LINKFD_FRAME_RESERV + lfd_mod::LINKFD_FRAME_APPEND, 0u8);
    unsafe { driver::proto_write(fd1, buf.as_ptr().add(LINKFD_FRAME_RESERV) as *mut libc::c_char, VTUN_CONN_CLOSE); }

    return 0;
}
