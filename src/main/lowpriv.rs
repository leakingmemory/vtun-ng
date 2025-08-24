#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::io::{pipe, Read, Write, PipeWriter};
use std::io::PipeReader;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use libc::WEXITSTATUS;
use crate::exitcode::ExitCode;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::lfd_mod;
use crate::mainvtun;
use crate::mainvtun::VtunContext;
use crate::setproctitle::set_title;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::syslog::{SyslogObject};

trait LowprivReturnable<T> {
    fn write_to_pipe(&self, w: &mut PipeWriter) -> Result<(),()>;
    fn read_from_pipe(r: &mut PipeReader) -> Result<T,()>;
}

impl LowprivReturnable<i32> for i32 {
    fn write_to_pipe(&self, w: &mut PipeWriter) -> Result<(), ()> {
        match w.write_all(&self.to_ne_bytes()) {
            Ok(_) => Ok(()),
            Err(_) => Err(())
        }
    }

    fn read_from_pipe(r: &mut PipeReader) -> Result<i32, ()> {
        let mut buffer = [0u8; 4];
        match r.read_exact(&mut buffer) {
            Ok(_) => {},
            Err(_) => return Err(())
        };
        Ok(i32::from_ne_bytes(buffer))
    }
}

const MAGIC_RETURN_VALUE: i32 = 0x12345678;

impl LowprivReturnable<()> for () {
    fn write_to_pipe(&self, w: &mut PipeWriter) -> Result<(), ()> {
        match w.write_all(&MAGIC_RETURN_VALUE.to_ne_bytes()) {
            Ok(_) => Ok(()),
            Err(_) => Err(())
        }
    }

    fn read_from_pipe(r: &mut PipeReader) -> Result<(), ()> {
        let mut buffer = [0u8; 4];
        match r.read_exact(&mut buffer) {
            Ok(_) => {},
            Err(_) => return Err(())
        };
        if i32::from_ne_bytes(buffer) == MAGIC_RETURN_VALUE {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub fn fork_lowpriv_worker<T,F>(ctx: &mut VtunContext, proc_title: &str, is_forked: &mut bool, worker_fn: &mut F) -> Result<T, ExitCode> where T: LowprivReturnable<T>, F: FnMut(&mut VtunContext) -> Result<T,()>
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
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
    }
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
                    match rv.write_to_pipe(&mut w) {
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
                let err = errno::errno();
                if err == errno::Errno(libc::EINTR) {
                    continue;
                }
                *is_forked = false;
                drop(r);
                let msg = format!("Unable to wait for low privileged child process: {}", err.to_string());
                ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                return Err(ExitCode::from_code(1));
            }
            break;
        }
        if !libc::WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0 {
            ctx.syslog(lfd_mod::LOG_ERR, "Low privileged child process returned with failure");
            return Err(ExitCode::from_code(1));
        }
        ctx.syslog(lfd_mod::LOG_INFO, "Low privileged child process exited successfully");
        match T::read_from_pipe(&mut r) {
            Ok(rv) => Ok(rv),
            Err(_) => {
                Err(ExitCode::from_code(1))
            }
        }
    }
}


#[cfg(test)]
fn test_i32(exp_rv: Result<i32,()>)
{
    let mut testctx = mainvtun::get_test_context();
    let mut is_forked = false;
    let rv = exp_rv.clone();
    let result = fork_lowpriv_worker(&mut testctx, "test", &mut is_forked, &mut |_ctx: &mut VtunContext| -> Result<i32,()> {
        rv
    });
    if is_forked {
        match exp_rv {
            Ok(_) => {
                assert!(if let Err(e) = result {
                    assert!(e.get_exit_code().is_ok());
                    unsafe { libc::exit(0) };
                } else {
                    false
                });
            },
            Err(_) => {
                assert!(if let Err(e) = result {
                    assert!(e.get_exit_code().is_err());
                    // Test returning 0/success on error
                    unsafe { libc::exit(0) };
                } else {
                    false
                });
            }
        }
    } else {
        match exp_rv {
            Ok(ref exp_rv) => {
                assert!(if let Ok(rv) = result {
                    rv == *exp_rv
                } else {
                    false
                });
            },
            Err(_) => {
                assert!(result.is_err());
            }
        }
    }
}

#[cfg(test)]
fn test_novalue(exp_rv: Result<(),()>)
{
    let mut testctx = mainvtun::get_test_context();
    let mut is_forked = false;
    let rv = exp_rv.clone();
    let result = fork_lowpriv_worker(&mut testctx, "test", &mut is_forked, &mut |_ctx: &mut VtunContext| -> Result<(),()> {
        rv
    });
    if is_forked {
        match exp_rv {
            Ok(_) => {
                assert!(if let Err(e) = result {
                    assert!(e.get_exit_code().is_ok());
                    unsafe { libc::exit(0) };
                } else {
                    false
                });
            },
            Err(_) => {
                assert!(if let Err(e) = result {
                    assert!(e.get_exit_code().is_err());
                    // Test returning 0/success on error
                    unsafe { libc::exit(0) };
                } else {
                    false
                });
            }
        }
    } else {
        match exp_rv {
            Ok(ref exp_rv) => {
                assert!(result.is_ok());
            },
            Err(_) => {
                assert!(result.is_err());
            }
        }
    }
}

#[test]
#[cfg(test)]
fn test_i32_0()
{
    test_i32(Ok(0))
}

#[test]
#[cfg(test)]
fn test_i32_1()
{
    test_i32(Ok(1))
}

#[test]
#[cfg(test)]
fn test_i32_err()
{
    test_i32(Err(()))
}

#[test]
#[cfg(test)]
fn test_novalue_ok()
{
    test_novalue(Ok(()))
}

#[test]
#[cfg(test)]
fn test_novalue_err()
{
    test_novalue(Err(()))
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
