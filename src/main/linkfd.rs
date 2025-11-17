use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use aes::{Aes128, Aes256};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv};
use blowfish::Blowfish;
use chacha20poly1305::ChaCha20Poly1305;
use cipher::consts::{U16, U32};
use ecb::{Decryptor, Encryptor};
use errno::{errno, set_errno};
use libc::{SIGALRM, SIGHUP, SIGINT, SIGTERM, SIGUSR1};
use signal_hook::{low_level, SigId};
use time::OffsetDateTime;
use crate::{driver, fdselect, lfd_gcm_encrypt, lfd_generic_encrypt, lfd_iv_encrypt, lfd_iv_stream_encrypt, lfd_legacy_encrypt, lfd_lzo, lfd_mod, lfd_shaper, lfd_zlib, syslog, vtun_host};
use crate::mainvtun::VtunContext;
use crate::syslog::SyslogObject;

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
pub const _VTUN_PERSIST: libc::c_int =    0x2000;

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

pub trait LfdMod {
    fn avail_encode(&mut self) -> bool {
        true
    }
    fn encode(&mut self, ctx: &VtunContext, buf: &mut Vec<u8>) -> Result<(),()>;
    fn decode(&mut self, ctx: &VtunContext, buf: &mut Vec<u8>) -> Result<(),()>;
    fn request_send(&mut self) -> bool;
}

pub trait LfdModFactory {
    fn create(&self, ctx: &VtunContext, host: &mut vtun_host::VtunHost) -> Result<Box<dyn LfdMod>,i32>;
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
    pub fn new(ctx: &VtunContext, factory: &LinkfdFactory, host: &mut vtun_host::VtunHost) -> Result<Linkfd,i32> {
        let mut linkfd = Linkfd {
            mods: Vec::new()
        };
        linkfd.mods.reserve(factory.mod_factories.len());
        for mod_factory in factory.mod_factories.iter() {
            match mod_factory.create(ctx, host) {
                Ok(m) => linkfd.mods.push(m),
                Err(err) => {
                    let msg = format!("Failed to set up connection encode/decode chain (code {})", err);
                    ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                    return Err(0)
                }
            }
        }
        Ok(linkfd)
    }
    fn avail_encode(&mut self) -> bool {
        for m in self.mods.iter_mut() {
            if !m.avail_encode() {
                return false;
            }
        }
        true
    }
    fn encode(&mut self, ctx: &VtunContext, buf: &mut Vec<u8>) -> Result<(),()> {
        for m in self.mods.iter_mut() {
            match m.encode(ctx, buf) {
                Ok(()) => {},
                Err(()) => return Err(())
            }
        }
        Ok(())
    }
    fn avail_decode(&mut self) -> bool {
        for m in self.mods.iter_mut() {
            if !m.avail_encode() {
                return false;
            }
        }
        true
    }
    fn decode(&mut self, ctx: &VtunContext, buf: &mut Vec<u8>) -> Result<(),()> {
        for m in self.mods.iter_mut().rev() {
            match m.decode(ctx, buf) {
                Ok(()) => {},
                Err(()) => return Err(())
            }
        }
        Ok(())
    }

    fn request_send(&mut self) -> bool {
        let mut req = false;
        for m in self.mods.iter_mut().rev() {
            if m.request_send() {
                req = true;
            }
        }
        req
    }
}

pub(crate) struct LinkfdCtx {
    log_to_syslog: bool,
    io_cancelled: AtomicBool,
    linker_term: AtomicI32,
    sig_alarm_tm_old: AtomicI64,
    sig_alarm_tm: AtomicI64,
    ka_timer: AtomicI64,
    stat_timer: AtomicI64,
    ka_need_verify: AtomicBool,
    stat_file: Mutex<Option<std::fs::File>>,
    stat_byte_in: AtomicU64,
    stat_byte_out: AtomicU64,
    stat_comp_in: AtomicU64,
    stat_comp_out: AtomicU64,
    send_a_packet: AtomicBool,
    host_flags: AtomicI32,
    host_ka_interval: libc::c_int
}

impl LinkfdCtx {
    pub(crate) fn new(ctx: &VtunContext) -> LinkfdCtx {
        LinkfdCtx {
            log_to_syslog: ctx.vtun.log_to_syslog,
            io_cancelled: AtomicBool::new(false),
            linker_term: AtomicI32::new(0),
            sig_alarm_tm_old: AtomicI64::new(0),
            sig_alarm_tm: AtomicI64::new(0),
            ka_timer: AtomicI64::new(0),
            stat_timer: AtomicI64::new(0),
            ka_need_verify: AtomicBool::new(false),
            stat_file: Mutex::new(None),
            stat_byte_in: AtomicU64::new(0),
            stat_byte_out: AtomicU64::new(0),
            stat_comp_in: AtomicU64::new(0),
            stat_comp_out: AtomicU64::new(0),
            send_a_packet: AtomicBool::new(false),
            host_flags: AtomicI32::new(0),
            host_ka_interval: 0
        }
    }
    fn io_cancel(&self) {
        self.io_cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn io_init(&self) {
        self.io_cancelled.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_io_cancelled(&self) -> bool {
        self.io_cancelled.load(std::sync::atomic::Ordering::SeqCst)
    }
}

pub fn sig_term(ctx: &LinkfdCtx) {
    syslog::vtun_syslog(ctx.log_to_syslog, lfd_mod::LOG_INFO, "Closing connection");
    ctx.io_cancel();
    ctx.linker_term.store(VTUN_SIG_TERM, std::sync::atomic::Ordering::SeqCst);
}

pub fn sig_hup(ctx: &LinkfdCtx) {
    syslog::vtun_syslog(ctx.log_to_syslog, lfd_mod::LOG_INFO, "Reestablishing connection");
    ctx.io_cancel();
    ctx.linker_term.store(VTUN_SIG_HUP, std::sync::atomic::Ordering::SeqCst);
}

pub fn sig_alarm(ctx: &LinkfdCtx) {
    let flags: i32;
    let tm = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;
    let tm_old = ctx.sig_alarm_tm.load(std::sync::atomic::Ordering::SeqCst);
    ctx.sig_alarm_tm_old.store(tm_old, std::sync::atomic::Ordering::SeqCst);
    ctx.sig_alarm_tm.store(tm, std::sync::atomic::Ordering::SeqCst);
    let mut ka_timer_value = ctx.ka_timer.load(std::sync::atomic::Ordering::SeqCst);
    let mut stat_timer_value = ctx.stat_timer.load(std::sync::atomic::Ordering::SeqCst);
    if tm_old < tm {
        ka_timer_value = ka_timer_value - (tm - tm_old);
        stat_timer_value = stat_timer_value - (tm - tm_old);
    }
    ctx.ka_timer.store(ka_timer_value, std::sync::atomic::Ordering::SeqCst);
    ctx.stat_timer.store(stat_timer_value, std::sync::atomic::Ordering::SeqCst);
    flags = ctx.host_flags.load(std::sync::atomic::Ordering::SeqCst);

    if (flags & VTUN_KEEP_ALIVE) != 0 && ka_timer_value <= 0 {
        ctx.ka_need_verify.store(true, std::sync::atomic::Ordering::SeqCst);
        ka_timer_value = ctx.host_ka_interval as i64 + 1;
        ctx.ka_timer.store(ka_timer_value, std::sync::atomic::Ordering::SeqCst);
    }

    if (flags & VTUN_STAT) != 0 && stat_timer_value <= 0 {
        let dt = if tm >= 0
            { UNIX_EPOCH + Duration::from_secs(tm as u64) }
            else
            { UNIX_EPOCH - Duration::from_secs((0 - tm) as u64) };
        let dt: OffsetDateTime = dt.into();
        let fmt = time::macros::format_description!("[month] [day] [hour]:[minute]:[second]");
        let stm = dt.format(fmt).unwrap_or_else(|_| "No time".to_string());
        let statmsg = format!("{} {} {} {} {}", stm,
                              ctx.stat_byte_in.load(std::sync::atomic::Ordering::SeqCst),
                              ctx.stat_byte_out.load(std::sync::atomic::Ordering::SeqCst),
                              ctx.stat_comp_in.load(std::sync::atomic::Ordering::SeqCst),
                              ctx.stat_comp_out.load(std::sync::atomic::Ordering::SeqCst));
        {
            let mut f = ctx.stat_file.lock().unwrap();
            if let Some(ref mut f) = *f {
                f.write(statmsg.as_bytes()).unwrap();
            }
        };
        stat_timer_value = VTUN_STAT_IVAL as i64;
        ctx.stat_timer.store(stat_timer_value, std::sync::atomic::Ordering::SeqCst);
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

fn sig_usr1(ctx: &LinkfdCtx) {
    /* Reset statistic counters on SIGUSR1 */
    ctx.stat_byte_in.store(0, std::sync::atomic::Ordering::SeqCst);
    ctx.stat_byte_out.store(0, std::sync::atomic::Ordering::SeqCst);
    ctx.stat_comp_in.store(0, std::sync::atomic::Ordering::SeqCst);
    ctx.stat_comp_out.store(0, std::sync::atomic::Ordering::SeqCst);
}


/* Link remote and local file descriptors */
pub fn linkfd(ctx: &mut VtunContext, linkfdctx: &Arc<LinkfdCtx>, host: &mut vtun_host::VtunHost, driver: &mut dyn driver::Driver, proto: &mut dyn driver::NetworkDriver) -> Result<libc::c_int,()>
{
    let old_prio = unsafe { libc::getpriority(libc::PRIO_PROCESS,0) };
    unsafe {libc::setpriority(libc::PRIO_PROCESS,0, LINKFD_PRIO); }

    let mut factory = LinkfdFactory::new();

    /* Build modules stack */
    let flags = host.flags;
    linkfdctx.host_flags.store(flags, std::sync::atomic::Ordering::SeqCst);
    if (flags & VTUN_ZLIB) != 0 {
        factory.add(Box::new(lfd_zlib::LfdZlibFactory::new()));
    }

    if (flags & VTUN_LZO) != 0 {
        factory.add(Box::new(lfd_lzo::LfdLzoFactory::new()));
    }

    if (flags & VTUN_ENCRYPT) != 0 {
        let cipher = (*host).cipher;
        factory.add(match cipher {
            lfd_mod::VTUN_LEGACY_ENCRYPT => Box::new(lfd_legacy_encrypt::LfdLegacyEncryptFactory::new()),
            lfd_mod::VTUN_ENC_BF128ECB => Box::new(lfd_generic_encrypt::LfdGenericEncryptFactory::<Encryptor<Blowfish>, Decryptor<Blowfish>, 16, 8>::new()),
            lfd_mod::VTUN_ENC_BF256ECB => Box::new(lfd_generic_encrypt::LfdGenericEncryptFactory::<Encryptor<Blowfish>, Decryptor<Blowfish>, 32, 8>::new()),
            lfd_mod::VTUN_ENC_AES128ECB => Box::new(lfd_generic_encrypt::LfdGenericEncryptFactory::<Encryptor<Aes128>, Decryptor<Aes128>, 16, 16>::new()),
            lfd_mod::VTUN_ENC_AES256ECB => Box::new(lfd_generic_encrypt::LfdGenericEncryptFactory::<Encryptor<Aes256>, Decryptor<Aes256>, 32, 16>::new()),
            lfd_mod::VTUN_ENC_BF128CBC => Box::new(lfd_iv_encrypt::LfdIvEncryptFactory::<Encryptor<Blowfish>, Decryptor<Blowfish>, cbc::Encryptor<Blowfish>, cbc::Decryptor<Blowfish>, 16, 8>::new()),
            lfd_mod::VTUN_ENC_BF256CBC => Box::new(lfd_iv_encrypt::LfdIvEncryptFactory::<Encryptor<Blowfish>, Decryptor<Blowfish>, cbc::Encryptor<Blowfish>, cbc::Decryptor<Blowfish>, 32, 8>::new()),
            lfd_mod::VTUN_ENC_AES128CBC => Box::new(lfd_iv_encrypt::LfdIvEncryptFactory::<Encryptor<Aes128>, Decryptor<Aes128>, cbc::Encryptor<Aes128>, cbc::Decryptor<Aes128>, 16, 16>::new()),
            lfd_mod::VTUN_ENC_AES256CBC => Box::new(lfd_iv_encrypt::LfdIvEncryptFactory::<Encryptor<Aes256>, Decryptor<Aes256>, cbc::Encryptor<Aes256>, cbc::Decryptor<Aes256>, 32, 16>::new()),
            lfd_mod::VTUN_ENC_BF128CFB => Box::new(lfd_iv_encrypt::LfdIvEncryptFactory::<Encryptor<Blowfish>, Decryptor<Blowfish>, cfb_mode::Encryptor<Blowfish>, cfb_mode::Decryptor<Blowfish>, 16, 8>::new()),
            lfd_mod::VTUN_ENC_BF256CFB => Box::new(lfd_iv_encrypt::LfdIvEncryptFactory::<Encryptor<Blowfish>, Decryptor<Blowfish>, cfb_mode::Encryptor<Blowfish>, cfb_mode::Decryptor<Blowfish>, 32, 8>::new()),
            lfd_mod::VTUN_ENC_AES128CFB => Box::new(lfd_iv_encrypt::LfdIvEncryptFactory::<Encryptor<Aes128>, Decryptor<Aes128>, cfb_mode::Encryptor<Aes128>, cfb_mode::Decryptor<Aes128>, 16, 16>::new()),
            lfd_mod::VTUN_ENC_AES256CFB => Box::new(lfd_iv_encrypt::LfdIvEncryptFactory::<Encryptor<Aes256>, Decryptor<Aes256>, cfb_mode::Encryptor<Aes256>, cfb_mode::Decryptor<Aes256>, 32, 16>::new()),
            lfd_mod::VTUN_ENC_BF128OFB => Box::new(lfd_iv_stream_encrypt::LfdIvStreamEncryptFactory::<Encryptor<Blowfish>, Decryptor<Blowfish>, ofb::Ofb<lfd_iv_stream_encrypt::FixedSizeForVariableKeySizeWrapper<Blowfish,U16>>, 16, 8>::new()),
            lfd_mod::VTUN_ENC_BF256OFB => Box::new(lfd_iv_stream_encrypt::LfdIvStreamEncryptFactory::<Encryptor<Blowfish>, Decryptor<Blowfish>, ofb::Ofb<lfd_iv_stream_encrypt::FixedSizeForVariableKeySizeWrapper<Blowfish,U32>>, 32, 8>::new()),
            lfd_mod::VTUN_ENC_AES128OFB => Box::new(lfd_iv_stream_encrypt::LfdIvStreamEncryptFactory::<Encryptor<Aes128>, Decryptor<Aes128>, ofb::Ofb<Aes128>, 16, 16>::new()),
            lfd_mod::VTUN_ENC_AES256OFB => Box::new(lfd_iv_stream_encrypt::LfdIvStreamEncryptFactory::<Encryptor<Aes256>, Decryptor<Aes256>, ofb::Ofb<Aes256>, 32, 16>::new()),
            lfd_mod::VTUN_ENC_AES128GCM => {
                ctx.syslog(lfd_mod::LOG_WARNING, "AES-GCM-mode is experimental");
                Box::new(lfd_iv_encrypt::LfdIvEncryptFactory::<Encryptor<Aes128>,Decryptor<Aes128>, lfd_gcm_encrypt::LfdGcmEncrypt<Aes128Gcm,16>, lfd_gcm_encrypt::LfdGcmDecrypt<Aes128Gcm,16>, 16, 16>::new())
            },
            lfd_mod::VTUN_ENC_AES256GCM => {
                ctx.syslog(lfd_mod::LOG_WARNING, "AES-GCM-mode is experimental");
                Box::new(lfd_iv_encrypt::LfdIvEncryptFactory::<Encryptor<Aes256>,Decryptor<Aes256>, lfd_gcm_encrypt::LfdGcmEncrypt<Aes256Gcm,16>, lfd_gcm_encrypt::LfdGcmDecrypt<Aes256Gcm,16>, 32, 16>::new())
            },
            lfd_mod::VTUN_ENC_AES128GCMSIV => {
                ctx.syslog(lfd_mod::LOG_WARNING, "AES-GCM-SIV-mode is experimental");
                Box::new(lfd_iv_encrypt::LfdIvEncryptFactory::<Encryptor<Aes128>,Decryptor<Aes128>, lfd_gcm_encrypt::LfdGcmEncrypt<Aes128GcmSiv,16>, lfd_gcm_encrypt::LfdGcmDecrypt<Aes128GcmSiv,16>, 16, 16>::new())
            },
            lfd_mod::VTUN_ENC_AES256GCMSIV => {
                ctx.syslog(lfd_mod::LOG_WARNING, "AES-GCM-SIV-mode is experimental");
                Box::new(lfd_iv_encrypt::LfdIvEncryptFactory::<Encryptor<Aes256>,Decryptor<Aes256>, lfd_gcm_encrypt::LfdGcmEncrypt<Aes256GcmSiv,16>, lfd_gcm_encrypt::LfdGcmDecrypt<Aes256GcmSiv,16>, 32, 16>::new())
            },
            lfd_mod::VTUN_ENC_CHACHA20POLY1305 => {
                ctx.syslog(lfd_mod::LOG_WARNING, "CHACHA20POLY1305-mode is experimental");
                Box::new(lfd_iv_encrypt::LfdIvEncryptFactory::<Encryptor<Aes256>,Decryptor<Aes256>, lfd_gcm_encrypt::LfdGcmEncrypt<ChaCha20Poly1305,16>, lfd_gcm_encrypt::LfdGcmDecrypt<ChaCha20Poly1305,16>, 32, 16>::new())
            },
            _ => {
                ctx.syslog(lfd_mod::LOG_ERR, "Unknown encryption algorithm");
                return Err(());
            }
        });
    }

    if(flags & VTUN_SHAPE) != 0 {
        factory.add(Box::new(lfd_shaper::LfdShaperFactory::new()));
    }

    let sigterm_restore;
    {
        let linkfdctx = linkfdctx.clone();
        sigterm_restore = match unsafe { low_level::register(SIGTERM, move || sig_term(&linkfdctx)) } {
            Ok(id) => Some(id),
            Err(_) => None
        };
    }
    let sigint_restore;
    {
        let linkfdctx = linkfdctx.clone();
        sigint_restore = match unsafe { low_level::register(SIGINT, move || sig_term(&linkfdctx)) } {
            Ok(id) => Some(id),
            Err(_) => None
        };
    }
    let sighup_restore;
    {
        let linkfdctx = linkfdctx.clone();
        sighup_restore = match unsafe { low_level::register(SIGHUP, move || sig_hup(&linkfdctx)) } {
            Ok(id) => Some(id),
            Err(_) => None
        };
    }

    
    let mut sigalrm_restore: Option<SigId> = None;
    /* Initialize keep-alive timer */
    if (flags & (VTUN_STAT|VTUN_KEEP_ALIVE)) != 0 {
        {
            let linkfdctx = linkfdctx.clone();
            sigalrm_restore = match unsafe { low_level::register(SIGALRM, move || sig_alarm(&linkfdctx)) } {
                Ok(id) => Some(id),
                Err(_) => None
            };
        }

        if host.ka_interval > 0 && (host.ka_interval as libc::c_uint) < VTUN_STAT_IVAL {
            unsafe { libc::alarm(host.ka_interval as libc::c_uint); }
        } else {
            unsafe { libc::alarm(VTUN_STAT_IVAL); }
        }
    }

    let mut sigusr1restore: Option<SigId> = None;
    /* Initialize statstic dumps */
    if (flags & VTUN_STAT) != 0 {
        {
            let linkfdctx = linkfdctx.clone();
            sigusr1restore = match unsafe { low_level::register(SIGUSR1, move || sig_usr1(&linkfdctx)) } {
                Ok(id) => Some(id),
                Err(_) => None
            };
        }

        let host_name = match host.host {
            Some(ref host_name) => host_name.as_str(),
            None => "vtun.unknown"
        };
        let file = format!("{}/{}", VTUN_STAT_DIR, host_name);
        match OpenOptions::new()
            .append(true)
            .open(file.clone()) {
            Ok(f) => {
                let mut l = linkfdctx.stat_file.lock().unwrap();
                *l = Some(f);
            },
            Err(_) => {
                let msg = format!("Can't open stats file {}", file);
                ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                let mut l = linkfdctx.stat_file.lock().unwrap();
                *l = None;
            }
        };
    }

    let mut lfd_stack: Linkfd = match Linkfd::new(ctx, & mut factory, host) {
        Ok(lfd) => lfd,
        Err(_) => return Err(())
    };

    linkfdctx.io_init();

    lfd_linker(ctx, & *linkfdctx, &mut lfd_stack, host, driver, proto);

    if (flags & (VTUN_STAT|VTUN_KEEP_ALIVE)) != 0 {
        unsafe {
            libc::alarm(0);
        }
        let mut l = linkfdctx.stat_file.lock().unwrap();
        *l = None;
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
        let term: i32 = linkfdctx.linker_term.load(std::sync::atomic::Ordering::SeqCst);
        Ok(term)
    }
}

fn lfd_linker(ctx: &mut VtunContext, linkfdctx: & LinkfdCtx, lfd_stack: &mut Linkfd, host: &mut vtun_host::VtunHost, driver: &mut dyn driver::Driver, proto: &mut dyn driver::NetworkDriver) -> libc::c_int
{
    let fd1 = proto.io_fd().i_absolutely_need_the_raw_value();
    let fd2 = driver.io_fd().unwrap().i_absolutely_need_the_raw_value();
    let mut fdset: Vec<libc::c_int> = Vec::new();
    fdset.reserve(2);
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

    linkfdctx.linker_term.store(0, std::sync::atomic::Ordering::SeqCst);
    while linkfdctx.linker_term.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        set_errno(errno::Errno(0));
        fdset.push(fd1);
        fdset.push(fd2);
        let len = fdselect::select_read_timeout(&mut fdset, host.ka_interval as libc::time_t);
        if len < 0 {
            let errno = errno();
            if errno != errno::Errno(libc::EAGAIN) && errno != errno::Errno(libc::EINTR) {
                ctx.syslog(lfd_mod::LOG_ERR, "Select error");
                break;
            } else {
                continue;
            }
        }

        if linkfdctx.ka_need_verify.load(std::sync::atomic::Ordering::SeqCst) {
            if idle > host.ka_maxfail {
                let msg = format!("Session {} network timeout", match host.host {Some(ref host) => host.as_str(), None => "<none>"});
                ctx.syslog(lfd_mod::LOG_INFO, msg.as_str());
                break;
            }
            idle += 1;
            if idle > 0 {
                /* No input frames, check connection with ECHO */
                buf.clear();
                let retv = proto.write(&mut buf, VTUN_ECHO_REQ as u16);
                if retv.is_none() {
                    ctx.syslog(lfd_mod::LOG_ERR, "Failed to send ECHO_REQ");
                    break;
                }
            }
            linkfdctx.ka_need_verify.store(false, std::sync::atomic::Ordering::SeqCst);
        }

        if linkfdctx.send_a_packet.load(std::sync::atomic::Ordering::SeqCst)
        {
            linkfdctx.send_a_packet.store(false, std::sync::atomic::Ordering::SeqCst);
            {
                let tmplen = linkfdctx.stat_byte_out.load(std::sync::atomic::Ordering::SeqCst) + 1;
                linkfdctx.stat_byte_out.store(tmplen, std::sync::atomic::Ordering::SeqCst);
            }
            buf.resize(1, 0u8);
            match lfd_stack.encode(ctx, &mut buf) {
                Ok(()) => {},
                Err(()) => {
                    ctx.syslog(lfd_mod::LOG_ERR, "Encoding failure");
                    break;
                }
            }
            let encoded = buf.len();
            if encoded > 0 {
                let retv = proto.write(&mut buf, 0);
                if retv.is_none() {
                    ctx.syslog(lfd_mod::LOG_ERR, "Network write failure");
                    break;
                }
                {
                    let tmplen = linkfdctx.stat_comp_out.load(std::sync::atomic::Ordering::SeqCst) + encoded as u64;
                    linkfdctx.stat_comp_out.store(tmplen, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }

        /* Read frames from network(fd1), decode and pass them to
         * the local device (fd2) */
        if fdset.contains(&fd1) && lfd_stack.avail_decode() {
            idle = 0;
            linkfdctx.ka_need_verify.store(false, std::sync::atomic::Ordering::SeqCst);
            buf.clear();
            let fl = proto.read(ctx, &mut buf);
            if fl.is_none() {
                let msg = format!("Network read failure: {}", errno::errno().to_string());
                ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                break;
            }
            let fl = fl.unwrap();

            /* Handle frame flags */
            if fl != 0 {
                if fl == VTUN_BAD_FRAME as u16 {
                    ctx.syslog(lfd_mod::LOG_ERR, "Received bad frame");
                    continue;
                }
                if fl == VTUN_ECHO_REQ as u16 {
                    /* Send ECHO reply */
                    buf.clear();
                    let retv = proto.write(&mut buf, VTUN_ECHO_REP as u16);
                    if retv.is_none() {
                        ctx.syslog(lfd_mod::LOG_ERR, "Network write failure");
                        break;
                    }
                    continue;
                }
                if fl == VTUN_ECHO_REP as u16 {
                    /* Just ignore ECHO reply, KA_NEED_VERIFY==0 already */
                    continue;
                }
                if fl == VTUN_CONN_CLOSE as u16 {
                    ctx.syslog(lfd_mod::LOG_INFO, "Connection closed by other side");
                    break;
                }
            }

            {
                let tmplen = linkfdctx.stat_comp_in.load(std::sync::atomic::Ordering::SeqCst) + len as u64;
                linkfdctx.stat_comp_in.store(tmplen, std::sync::atomic::Ordering::SeqCst);
            }
            match lfd_stack.decode(ctx, &mut buf) {
                Ok(()) => {},
                Err(()) => {
                    ctx.syslog(lfd_mod::LOG_ERR, "Decoding failure");
                    break;
                }
            }
            if lfd_stack.request_send() {
                linkfdctx.send_a_packet.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            let decoded = buf.len();
            if decoded > 0 {
                let retv;
                {
                    retv = driver.write(&mut buf);
                    let tmplen = linkfdctx.stat_byte_in.load(std::sync::atomic::Ordering::SeqCst) + decoded as u64;
                    linkfdctx.stat_byte_in.store(tmplen, std::sync::atomic::Ordering::SeqCst);
                }
                if retv.is_none() {
                    let errno = errno();
                    if errno != errno::Errno(libc::EAGAIN) && errno != errno::Errno(libc::EINTR) {
                        let msg = format!("Driver write failed: {}", errno.to_string());
                        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                        break;
                    } else {
                        continue;
                    }
                }
                {
                    let tmplen = linkfdctx.stat_byte_in.load(std::sync::atomic::Ordering::SeqCst) + decoded as u64;
                    linkfdctx.stat_byte_in.store(tmplen, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }

        /* Read data from the local device(fd2), encode and pass it to
         * the network (fd1) */
        if fdset.contains(&fd2) && lfd_stack.avail_encode() {
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

            {
                let tmplen = linkfdctx.stat_byte_out.load(std::sync::atomic::Ordering::SeqCst) + len as u64;
                linkfdctx.stat_byte_out.store(tmplen, std::sync::atomic::Ordering::SeqCst);
            }


            match lfd_stack.encode(ctx, &mut buf) {
                Ok(()) => {},
                Err(()) => {
                    ctx.syslog(lfd_mod::LOG_ERR, "Encoding failure");
                    break;
                }
            }
            let encoded = buf.len();
            if encoded > 0 {
                let retv = proto.write(&mut buf, 0);
                let tmplen = linkfdctx.stat_comp_out.load(std::sync::atomic::Ordering::SeqCst) + encoded as u64;
                linkfdctx.stat_comp_out.store(tmplen, std::sync::atomic::Ordering::SeqCst);
                if retv.is_none() {
                    break;
                }
            }
        }
    }
    if linkfdctx.linker_term.load(std::sync::atomic::Ordering::SeqCst) != 0 && errno() != errno::Errno(0) {
        let errno = errno();
        let msg = format!("{}: {}\n\0", errno.to_string(), errno);
        ctx.syslog(lfd_mod::LOG_INFO, msg.as_str());
    }

    if linkfdctx.linker_term.load(std::sync::atomic::Ordering::SeqCst) == VTUN_SIG_TERM {
        host.persist = 0;
    }

    /* Notify other end about our close */
    buf.clear();
    proto.write(&mut buf, VTUN_CONN_CLOSE as u16);

    0
}
