use std::io::{pipe, Read, Write};
use caps::{CapSet};
use libc::WEXITSTATUS;
use crate::exitcode::ExitCode;
use crate::lfd_mod;
use crate::mainvtun::VtunContext;
use crate::syslog::{SyslogObject};

pub fn fork_lowpriv_worker<F>(ctx: &mut VtunContext, is_forked: &mut bool, worker_fn: &mut F) -> Result<i32, ExitCode> where F: FnMut(&mut VtunContext) -> Result<i32,()>
{
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

fn drop_privileges(ctx: &VtunContext) -> Result<(),()> {
    match set_no_new_privs(ctx) {
        Ok(_) => {},
        Err(_) => return Err(())
    }
    drop_caps(ctx)
}

#[cfg(target_os = "linux")]
fn drop_caps(ctx: &VtunContext) -> Result<(),()> {
    for set in [CapSet::Bounding, CapSet::Ambient, CapSet::Effective, CapSet::Permitted, CapSet::Inheritable] {
        match caps::clear(None, set).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)) {
            Ok(_) => {},
            Err(_) => {
                ctx.syslog(lfd_mod::LOG_ERR, "Unable to clear capabilities");
                return Err(());
            }
        };
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn drop_caps(ctx: &VtunContext) -> Result<(),()> {
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

#[cfg(not(target_os = "linux"))]
fn set_no_new_privs(ctx: VtunContext) -> Result<(),()> {
    Ok(())
}
