use crate::lfd_mod;
use crate::mainvtun::VtunContext;

pub fn vtun_syslog(log_to_syslog: bool, priority: libc::c_int, str: &str) {
    if log_to_syslog {
        let msg = format!("{}\n\0", str);
        unsafe {
            libc::syslog(priority, msg.as_ptr() as *const i8);
        }
    } else {
        println!("vtunngd[{}]: {}", unsafe { libc::getpid() }, str);
    }
}

pub trait SyslogObject {
    fn syslog(&self, priority: libc::c_int, str: &str);
}

impl SyslogObject for lfd_mod::VtunOpts {
    fn syslog(&self, priority: libc::c_int, str: &str) {
        vtun_syslog(self.log_to_syslog, priority, str);
    }
}

impl SyslogObject for VtunContext {
    fn syslog(&self, priority: libc::c_int, str: &str) {
        self.vtun.syslog(priority, str);
    }
}
