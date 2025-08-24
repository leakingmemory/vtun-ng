#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::io::{pipe, Read, Write};
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use libc::WEXITSTATUS;
use crate::exitcode::ExitCode;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::lfd_mod;
use crate::mainvtun::VtunContext;
use crate::setproctitle::set_title;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::syslog::{SyslogObject};

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub fn fork_lowpriv_worker<F>(ctx: &mut VtunContext, proc_title: &str, is_forked: &mut bool, worker_fn: &mut F) -> Result<i32, ExitCode> where F: FnMut(&mut VtunContext) -> Result<i32,()>
{
    let priv_proc_title = format!("masterproc {}", proc_title);
    {
        let setup_proc_title = format!("drop priv {}", proc_title);
        set_title(setup_proc_title.as_str());
    }
    let (mut r, mut w) = match pipe() {
        Ok(p) => p,
        Err(_) => {
            *is_forked = false;
            ctx.syslog(lfd_mod::LOG_ERR, "Unable to create pipe for return value from low privileged child");
            return Err(ExitCode::from_code(1));
        }
    };
    let res = unsafe { libc::fork() };
    if res < 0 {
        *is_forked = false;
        ctx.syslog(lfd_mod::LOG_ERR, "Unable to fork low privileged child");
        Err(ExitCode::from_code(1))
    } else if res == 0 {
        set_title(proc_title);
        *is_forked = true;
        drop(r);
        match drop_privileges(ctx) {
            Ok(_) => match worker_fn(ctx) {
                Ok(rv) => {
                    match w.write_all(&rv.to_ne_bytes()) {
                        Ok(_) => Err(ExitCode::from_code(0)),
                        Err(_) => {
                            ctx.syslog(lfd_mod::LOG_ERR, "Unable to write return value to pipe for low privileged child");
                            Err(ExitCode::from_code(1))
                        }
                    }
                },
                Err(_) => Err(ExitCode::from_code(1))
            },
            Err(_) => Err(ExitCode::from_code(1))
        }
    } else {
        set_title(priv_proc_title.as_str());
        *is_forked = false;
        drop(w);
        let mut wstatus: libc::c_int = 0;
        loop {
            if unsafe { libc::waitpid(res, &mut wstatus as *mut libc::c_int, 0) } < 0 {
                if errno::errno() == errno::Errno(libc::EINTR) {
                    continue;
                }
                *is_forked = false;
                drop(r);
                ctx.syslog(lfd_mod::LOG_ERR, "Unable to wait for low privileged child process");
                return Err(ExitCode::from_code(1));
            }
            break;
        }
        if !libc::WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0 {
            ctx.syslog(lfd_mod::LOG_ERR, "Low privileged child process returned with failure");
            return Err(ExitCode::from_code(1));
        }
        ctx.syslog(lfd_mod::LOG_INFO, "Low privileged child process exited successfully");
        let mut buffer = [0u8; 4];
        r.read_exact(&mut buffer).unwrap();
        let retval = i32::from_ne_bytes(buffer);
        Ok(retval)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
pub fn fork_lowpriv_worker<F>(ctx: &mut VtunContext, proc_title: &str, is_forked: &mut bool, worker_fn: &mut F) -> Result<i32, ExitCode> where F: FnMut(&mut VtunContext) -> Result<i32,()> {
    *is_forked = false;
    set_title(proc_title);
    match worker_fn(ctx) {
        Ok(rv) => Ok(rv),
        Err(_) => Err(ExitCode::from_code(1))
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn drop_privileges(ctx: &VtunContext) -> Result<(),()> {
    drop_caps(ctx)
}

#[cfg(target_os = "freebsd")]
fn drop_caps(ctx: &VtunContext) -> Result<(),()> {
    if (unsafe { libc::cap_enter() } < 0) {
        ctx.syslog(lfd_mod::LOG_ERR, "Unable to enter capability restricted mode");
        return Err(());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn drop_caps(ctx: &VtunContext) -> Result<(),()> {
    match set_no_new_privs(ctx) {
        Ok(_) => {},
        Err(_) => return Err(())
    }
    drop_capsets(ctx)
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct CapHdr {
    version: u32,
    pid: u32,
    padding: [u64; 7]
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct CapDataPoint {
    effective: u32,
    permitted: u32,
    inheritable: u32
}
#[cfg(target_os = "linux")]
#[repr(C)]
struct CapData {
    capabilities: [CapDataPoint; 8],
    padding: [u32; 8]
}

#[cfg(target_os = "linux")]
fn drop_capsets(ctx: &VtunContext) -> Result<(),()> {
    // Drop bounding set capabilities
    for cap in 0..=63 {
        let capread = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap) };
        if capread < 0 {
            break;
        }
        if (capread & 1) == 0 {
            continue;
        }
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } < 0 {
            ctx.syslog(lfd_mod::LOG_ERR, "Unable to drop capability from bounding set");
            return Err(());
        }
    }

    // Drop ambient set capabilities
    if unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) } != 0 {
        ctx.syslog(lfd_mod::LOG_ERR, "Unable to drop capabilities from ambient set");
        return Err(());
    }

    // Drop effective, permitted and inheritable capabilities
    let mut hdr: CapHdr = unsafe { std::mem::zeroed() };
    let mut data: CapData = unsafe { std::mem::zeroed() };
    hdr.version = 0x20080522;
    hdr.pid = 0;
    if unsafe { libc::syscall(libc::SYS_capget, &mut hdr as *mut CapHdr as *mut libc::c_void, &mut data as *mut CapData as *mut libc::c_void) } < 0 {
        let msg = format!("Unable to get capabilities: {}", errno::errno().to_string());
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        return Err(());
    }
    for i in 0..4 {
        data.capabilities[i].effective = 0;
        data.capabilities[i].permitted = 0;
        data.capabilities[i].inheritable = 0;
    }
    if unsafe { libc::syscall(libc::SYS_capset, &mut hdr as *mut CapHdr as *mut libc::c_void, &mut data as *mut CapData as *mut libc::c_void) } < 0 {
        let msg = format!("Unable to set capabilities: {}", errno::errno().to_string());
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
        return Err(());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_no_new_privs(ctx: &VtunContext) -> Result<(),()> {
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        ctx.syslog(lfd_mod::LOG_ERR, "Unable to set no_new_privs");
        return Err(());
    }
    Ok(())
}
