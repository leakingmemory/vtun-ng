use std::ffi::CStr;
use std::fs::OpenOptions;
use std::io::Write;
use std::{mem, ptr};
use std::sync::atomic::{AtomicBool, AtomicI32};
use std::time::SystemTime;
use errno::{errno, set_errno};
use libc::{SIGALRM, SIGHUP, SIGINT, SIGTERM, SIGUSR1};
use signal_hook::{low_level, SigId};
use time::OffsetDateTime;
use crate::{driver, lfd_encrypt, lfd_legacy_encrypt, lfd_lzo, lfd_mod, lfd_shaper, lfd_zlib, main, mainvtun, syslog, vtun_host};

pub const LINKFD_PRIO: libc::c_int = -1;

pub const VTUN_TTY: libc::c_int =       0x0100;
pub const VTUN_PIPE: libc::c_int =      0x0200;
pub const VTUN_ETHER: libc::c_int =     0x0400;
pub const VTUN_TUN: libc::c_int =       0x0800;
pub const VTUN_TYPE_MASK: libc::c_int = VTUN_TTY | VTUN_PIPE | VTUN_ETHER | VTUN_TUN;

pub const VTUN_TCP: libc::c_int =       0x0010;
pub const VTUN_UDP: libc::c_int  =      0x0020;
pub const VTUN_PROT_MASK: libc::c_int = VTUN_TCP | VTUN_UDP;
pub const VTUN_KEEP_ALIVE: libc::c_int = 0x0040;

pub const VTUN_ZLIB: libc::c_int = 0x0001;
pub const VTUN_LZO: libc::c_int = 0x0002;
pub const VTUN_SHAPE: libc::c_int = 0x0004;
pub const VTUN_ENCRYPT: libc::c_int = 0x0008;

pub const VTUN_CMD_WAIT: libc::c_int =	0x01;
pub const VTUN_CMD_DELAY: libc::c_int =  0x02;
pub const VTUN_CMD_SHELL: libc::c_int =  0x04;

/* Number of seconds for delay after pppd startup*/
pub const VTUN_DELAY_SEC: u64 =  10;

pub const VTUN_SIG_TERM: i32 = 1;
pub const VTUN_SIG_HUP: i32 =  2;

pub const VTUN_STAT: libc::c_int =	0x1000;
pub const VTUN_PERSIST: libc::c_int =    0x2000;

pub const VTUN_STAT_IVAL: libc::c_uint =  5*60;  /* 5 min */

pub const VTUN_NAT_HACK_CLIENT: libc::c_int =	0x4000;
pub const VTUN_NAT_HACK_SERVER: libc::c_int =	0x8000;
pub const VTUN_NAT_HACK_MASK: libc::c_int =	VTUN_NAT_HACK_CLIENT | VTUN_NAT_HACK_SERVER;

pub const VTUN_FRAME_SIZE: usize =     2048;
pub const VTUN_FRAME_OVERHEAD: usize = 100;
pub const VTUN_FSIZE_MASK: libc::c_int = 0x0fff;

pub const VTUN_CONN_CLOSE: libc::c_int = 0x1000;
pub const VTUN_ECHO_REQ: libc::c_int =	0x2000;
pub const VTUN_ECHO_REP: libc::c_int =	0x4000;
pub const VTUN_BAD_FRAME: libc::c_int =  0x8000;

const VTUN_STAT_DIR: &str = env!("VTUN_STAT_DIR");
const ENABLE_NAT_HACK: &str = env!("ENABLE_NAT_HACK");

pub fn is_enabled_nat_hack(host: &mut vtun_host::VtunHost) -> bool {
    if ENABLE_NAT_HACK == "true"
    {
        return (host.flags & VTUN_NAT_HACK_MASK) != 0;
    }
    false
}

pub static mut SEND_A_PACKET: bool = false;
pub static mut HOST_FLAGS: libc::c_int = 0;
pub static mut HOST_KA_INTERVAL: libc::c_int = 0;

pub trait LfdMod {
    fn avail_encode(&mut self) -> bool {
        true
    }
    fn encode(&mut self, _buf: &mut Vec<u8>) -> bool {
        true
    }
    fn decode(&mut self, _buf: &mut Vec<u8>) -> bool {
        true
    }
}

pub trait LfdModFactory {
    fn create(&self, host: &mut vtun_host::VtunHost) -> Option<Box<dyn LfdMod>>;
}

pub struct LinkfdFactory {
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
    pub fn new(factory: &LinkfdFactory, host: &mut vtun_host::VtunHost) -> Linkfd {
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
        linkfd
    }
    fn avail_encode(&mut self) -> bool {
        for m in self.mods.iter_mut() {
            if !m.avail_encode() {
                return false;
            }
        }
        true
    }
    fn encode(&mut self, buf: &mut Vec<u8>) -> bool {
        for m in self.mods.iter_mut() {
            if !m.encode(buf) {
                return false;
            }
        }
        true
    }
    fn avail_decode(&mut self) -> bool {
        for m in self.mods.iter_mut() {
            if !m.avail_encode() {
                return false;
            }
        }
        true
    }
    fn decode(&mut self, buf: &mut Vec<u8>) -> bool {
        for m in self.mods.iter_mut().rev() {
            if !m.decode(buf) {
                return false;
            }
        }
        true
    }
}

static mut IO_CANCELLED: AtomicBool = AtomicBool::new(false);
static mut LINKER_TERM: AtomicI32 = AtomicI32::new(0);

pub fn io_cancel() {
    unsafe { IO_CANCELLED.store(true, std::sync::atomic::Ordering::SeqCst); }
}

#[no_mangle]
pub extern "C" fn io_init() {
    unsafe { IO_CANCELLED.store(false, std::sync::atomic::Ordering::SeqCst); }
}

pub fn sig_term() {
    syslog::vtun_syslog(lfd_mod::LOG_INFO, "Closing connection");
    io_cancel();
    unsafe { LINKER_TERM.store(VTUN_SIG_TERM, std::sync::atomic::Ordering::SeqCst); }
}

pub fn sig_hup() {
    syslog::vtun_syslog(lfd_mod::LOG_INFO, "Reestablishing connection");
    io_cancel();
    unsafe { LINKER_TERM.store(VTUN_SIG_HUP, std::sync::atomic::Ordering::SeqCst); }
}

static mut SIG_ALARM_TM_OLD: SystemTime = SystemTime::UNIX_EPOCH;
static mut SIG_ALARM_TM: SystemTime = SystemTime::UNIX_EPOCH;
static mut KA_TIMER: i64 = 0;
static mut STAT_TIMER: i64 = 0;
static mut KA_NEED_VERIFY: AtomicBool = AtomicBool::new(false);
static mut STAT_FILE: Option<std::fs::File> = None;
static mut STAT_BYTE_IN: u64 = 0;
static mut STAT_BYTE_OUT: u64 = 0;
static mut STAT_COMP_IN: u64 = 0;
static mut STAT_COMP_OUT: u64 = 0;


pub fn sig_alarm() {
    let tm_old: SystemTime;
    let tm: SystemTime;
    let mut ka_timer_value: i64;
    let mut stat_timer_value: i64;
    let flags: i32;
    tm = SystemTime::now();
    unsafe {
        tm_old = SIG_ALARM_TM;
        SIG_ALARM_TM_OLD = tm_old;
        SIG_ALARM_TM = tm;
        KA_TIMER -= tm_old.elapsed().unwrap().as_secs() as i64;
        STAT_TIMER -= tm_old.elapsed().unwrap().as_secs() as i64;
        ka_timer_value = KA_TIMER;
        stat_timer_value = STAT_TIMER;
        flags = HOST_FLAGS;
    }

    if (flags & VTUN_KEEP_ALIVE) != 0 && ka_timer_value <= 0 {
        unsafe {
            KA_NEED_VERIFY.store(true, std::sync::atomic::Ordering::SeqCst);
            KA_TIMER = (HOST_KA_INTERVAL as i64)
                + 1; /* We have to complete select() on idle */
            ka_timer_value = KA_TIMER;
        }
    }

    if (flags & VTUN_STAT) != 0 && stat_timer_value <= 0 {
        let dt: OffsetDateTime = tm.into();
        let fmt = time::macros::format_description!("[month] [day] [hour]:[minute]:[second]");
        let stm = dt.format(fmt).unwrap_or_else(|_| "No time".to_string());
        let statmsg = unsafe {format!("{} {} {} {} {}", stm, STAT_BYTE_IN, STAT_BYTE_OUT, STAT_COMP_IN, STAT_COMP_OUT)};
        unsafe {
            match STAT_FILE {
                None => {},
                Some(ref mut f) => match f.write(statmsg.as_bytes()) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            };
            STAT_TIMER = VTUN_STAT_IVAL as i64;
            stat_timer_value = STAT_TIMER;
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
        STAT_BYTE_IN = 0;
        STAT_BYTE_OUT = 0;
        STAT_COMP_IN = 0;
        STAT_COMP_OUT = 0;
    }
}

#[no_mangle]
pub extern "C" fn is_io_cancelled() -> libc::c_int {
    let val = unsafe { IO_CANCELLED.load(std::sync::atomic::Ordering::SeqCst) };
    if val == true {
        1
    } else {
        0
    }
}

/* Link remote and local file descriptors */
pub fn linkfd(ctx: &mut mainvtun::VtunContext, hostptr: *mut vtun_host::VtunHost, driver: &mut dyn driver::Driver, proto: &mut dyn driver::NetworkDriver) -> libc::c_int
{
    //struct sigaction sa, sa_oldterm, sa_oldint, sa_oldhup;
    //int old_prio;
    let host: &mut vtun_host::VtunHost = unsafe { &mut *hostptr };

    //lfd_host = host;

    let old_prio = unsafe { libc::getpriority(libc::PRIO_PROCESS,0) };
    unsafe {libc::setpriority(libc::PRIO_PROCESS,0, LINKFD_PRIO); }

    let mut factory = LinkfdFactory::new();

    /* Build modules stack */
    let flags = host.flags;
    unsafe { HOST_FLAGS = flags; }
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

    let sigterm_restore = match unsafe { low_level::register(SIGTERM, || sig_term()) } {
        Ok(id) => Some(id),
        Err(_) => None
    };
    let sigint_restore = match unsafe { low_level::register(SIGINT, || sig_term()) } {
        Ok(id) => Some(id),
        Err(_) => None
    };
    let sighup_restore = match unsafe { low_level::register(SIGHUP, || sig_hup()) } {
        Ok(id) => Some(id),
        Err(_) => None
    };

    
    let mut sigalrm_restore: Option<SigId> = None;
    /* Initialize keep-alive timer */
    if (flags & (VTUN_STAT|VTUN_KEEP_ALIVE)) != 0 {
        sigalrm_restore = match unsafe { low_level::register(SIGALRM, || sig_alarm()) } {
            Ok(id) => Some(id),
            Err(_) => None
        };

        if host.ka_interval > 0 && (host.ka_interval as libc::c_uint) < VTUN_STAT_IVAL {
            unsafe { libc::alarm(host.ka_interval as libc::c_uint); }
        } else {
            unsafe { libc::alarm(VTUN_STAT_IVAL); }
        }
    }

    let mut sigusr1restore: Option<SigId> = None;
    /* Initialize statstic dumps */
    if (flags & VTUN_STAT) != 0 {
        sigusr1restore = match unsafe { low_level::register(SIGUSR1, || sig_usr1()) } {
            Ok(id) => Some(id),
            Err(_) => None
        };

        let host_name = unsafe { CStr::from_ptr(host.host) }.to_str().unwrap_or_else(|_| "vtun.unknown");
        let file = format!("{}/{}", VTUN_STAT_DIR, host_name);
        match OpenOptions::new()
            .append(true)
            .open(file.clone()) {
            Ok(f) => unsafe { STAT_FILE = Some(f) },
            Err(_) => {
                let msg = format!("Can't open stats file {}", file);
                syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                unsafe {
                    STAT_FILE = None;
                }
            }
        };
    }

    let mut lfd_stack: Linkfd = Linkfd::new(& mut factory, host);

    io_init();

    lfd_linker(ctx, &mut lfd_stack, host, driver, proto);

    if (flags & (VTUN_STAT|VTUN_KEEP_ALIVE)) != 0 {
        unsafe {
            libc::alarm(0);
            STAT_FILE = None;
        }
    }

    match sigalrm_restore {
        Some(sig_id) => low_level::unregister(sig_id),
        None => false
    };
    match sigusr1restore {
        Some(sig_id) => low_level::unregister(sig_id),
        None => false
    };
    match sigterm_restore {
        Some(sig_id) => low_level::unregister(sig_id),
        None => false
    };
    match sigint_restore {
        Some(sig_id) => low_level::unregister(sig_id),
        None => false
    };
    match sighup_restore {
        Some(sig_id) => low_level::unregister(sig_id),
        None => false
    };

    unsafe {
        libc::setpriority(libc::PRIO_PROCESS,0,old_prio);
        let term: i32 = LINKER_TERM.load(std::sync::atomic::Ordering::SeqCst);
        term
    }
}

fn lfd_linker(ctx: &mut mainvtun::VtunContext, lfd_stack: &mut Linkfd, host: &mut vtun_host::VtunHost, driver: &mut dyn driver::Driver, proto: &mut dyn driver::NetworkDriver) -> libc::c_int
{
    let fd1 = host.rmt_fd;
    let fd2 = host.loc_fd;
    let mut tv: libc::timeval;
    let fdset = mem::MaybeUninit::<libc::fd_set>::uninit();
    unsafe { libc::FD_ZERO(&mut (fdset.assume_init())); }
    let mut fdset = unsafe { fdset.assume_init() };
    let mut idle: i32 = 0;

    let mut buf: Vec<u8> = Vec::new();
    buf.reserve(VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD);

    /* Delay sending of first UDP packet over broken NAT routers
    because we will probably be disconnected.  Wait for the remote
    end to send us something first, and use that connection. */
    if !is_enabled_nat_hack(host) {
        buf.clear();
        proto.write(&mut buf, VTUN_ECHO_REQ as u16);
    }

    let maxfd =  (if fd1 > fd2 { fd1 } else { fd2 }) + 1;

    unsafe { LINKER_TERM.store(0, std::sync::atomic::Ordering::SeqCst); }
    while unsafe { LINKER_TERM.load(std::sync::atomic::Ordering::SeqCst) == 0 } {
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
                syslog::vtun_syslog(lfd_mod::LOG_ERR, "Select error");
                break;
            } else {
                continue;
            }
        }

        if unsafe { KA_NEED_VERIFY.load(std::sync::atomic::Ordering::SeqCst) } {
            if idle > host.ka_maxfail {
                unsafe {
                    let msg = format!("Session {} network timeout", CStr::from_ptr(host.host).to_str().unwrap_or(""));
                    syslog::vtun_syslog(lfd_mod::LOG_INFO, msg.as_str());
                }
                break;
            }
            idle += 1;
            if idle > 0 {
                /* No input frames, check connection with ECHO */
                buf.clear();
                let retv = proto.write(&mut buf, VTUN_ECHO_REQ as u16);
                if retv.is_none() {
                    syslog::vtun_syslog(lfd_mod::LOG_ERR, "Failed to send ECHO_REQ");
                    break;
                }
            }
            unsafe { KA_NEED_VERIFY.store(false, std::sync::atomic::Ordering::SeqCst); }
        }

        if unsafe { SEND_A_PACKET }
        {
            unsafe { SEND_A_PACKET = false; }
            let tmplen = 1;
            unsafe { STAT_BYTE_OUT += tmplen; }
            buf.resize(1, 0u8);
            if !lfd_stack.encode(&mut buf) {
                syslog::vtun_syslog(lfd_mod::LOG_ERR, "Encoding failure");
                break;
            }
            let encoded = buf.len();
            if encoded > 0 {
                let retv = proto.write(&mut buf, 0);
                if retv.is_none() {
                    syslog::vtun_syslog(lfd_mod::LOG_ERR, "Network write failure");
                    break;
                }
                unsafe { STAT_COMP_OUT += encoded as u64; }
            }
        }

        /* Read frames from network(fd1), decode and pass them to
         * the local device (fd2) */
        if unsafe { libc::FD_ISSET(fd1, &fdset) } && lfd_stack.avail_decode() {
            idle = 0;
            unsafe { KA_NEED_VERIFY.store(false, std::sync::atomic::Ordering::SeqCst); }
            buf.clear();
            let fl = proto.read(ctx, &mut buf);
            if fl.is_none() {
                syslog::vtun_syslog(lfd_mod::LOG_ERR, "Network read failure");
                break;
            }
            let fl = fl.unwrap();

            /* Handle frame flags */
            if fl != 0 {
                if fl == VTUN_BAD_FRAME as u16 {
                    syslog::vtun_syslog(lfd_mod::LOG_ERR, "Received bad frame");
                    continue;
                }
                if fl == VTUN_ECHO_REQ as u16 {
                    /* Send ECHO reply */
                    buf.clear();
                    let retv = proto.write(&mut buf, VTUN_ECHO_REP as u16);
                    if retv.is_none() {
                        syslog::vtun_syslog(lfd_mod::LOG_ERR, "Network write failure");
                        break;
                    }
                    continue;
                }
                if fl == VTUN_ECHO_REP as u16 {
                    /* Just ignore ECHO reply, KA_NEED_VERIFY==0 already */
                    continue;
                }
                if fl == VTUN_CONN_CLOSE as u16 {
                    syslog::vtun_syslog(lfd_mod::LOG_INFO, "Connection closed by other side");
                    break;
                }
            }

            unsafe { STAT_COMP_IN += len as u64; }
            if !lfd_stack.decode(&mut buf) {
                syslog::vtun_syslog(lfd_mod::LOG_ERR, "Decoding failure");
                break;
            }
            let decoded = buf.len();
            if decoded > 0 {
                let retv;
                unsafe {
                    retv = driver.write(&mut buf);
                    STAT_BYTE_IN += decoded as u64;
                }
                if retv.is_none() {
                    let errno = errno();
                    if errno != errno::Errno(libc::EAGAIN) && errno != errno::Errno(libc::EINTR) {
                        let msg = format!("Driver write failed: {}", errno.to_string());
                        syslog::vtun_syslog(lfd_mod::LOG_ERR, msg.as_str());
                        break;
                    } else {
                        continue;
                    }
                }
                unsafe { STAT_BYTE_IN += decoded as u64; }
            }
        }

        /* Read data from the local device(fd2), encode and pass it to
         * the network (fd1) */
        if unsafe { libc::FD_ISSET(fd2, &fdset) } && lfd_stack.avail_encode() {
            buf.clear();
            let success = driver.read(&mut buf, VTUN_FRAME_SIZE);

            if !success {
                let errno = errno();
                if errno != errno::Errno(libc::EAGAIN) && errno != errno::Errno(libc::EINTR) {
                    break;
                } else {
                    continue;
                }
            }
            if buf.len() == 0 {
                break;
            }

            let len = buf.len();

            unsafe { STAT_BYTE_OUT += len as u64; }


            if !lfd_stack.encode(&mut buf) {
                break;
            }
            let encoded = buf.len();
            if encoded > 0 {
                let retv;
                unsafe {
                    retv = proto.write(&mut buf, 0);
                    STAT_COMP_OUT += encoded as u64;
                }
                if retv.is_none() {
                    break;
                }
            }
        }
    }
    if unsafe {*LINKER_TERM.as_ptr()} != 0 && errno() != errno::Errno(0) {
        let errno = errno();
        let msg = format!("{}: {}\n\0", errno.to_string(), errno);
        syslog::vtun_syslog(lfd_mod::LOG_INFO, msg.as_str());
    }

    if unsafe { LINKER_TERM.load(std::sync::atomic::Ordering::SeqCst)} == VTUN_SIG_TERM {
        host.persist = 0;
    }

    /* Notify other end about our close */
    buf.clear();
    proto.write(&mut buf, VTUN_CONN_CLOSE as u16);

    0
}
