#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::io::{pipe, Read, Write, PipeWriter};
use std::io::PipeReader;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use libc::WEXITSTATUS;
use users::{Groups, Users, UsersCache};
use crate::exitcode::ExitCode;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::lfd_mod;
#[cfg(test)]
use crate::mainvtun;
use crate::mainvtun::VtunContext;
use crate::setproctitle::set_title;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::syslog::{SyslogObject};

pub trait LowprivReturnable<T> {
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

pub fn run_lowpriv_section<T,F>(ctx: &mut VtunContext, proc_title: &str, is_forked: &mut bool, worker_fn: &mut F) -> Result<T, ExitCode> where T: LowprivReturnable<T>, F: FnMut(&mut VtunContext) -> Result<T,()> {
    if ctx.vtun.dropcaps || ctx.vtun.setuid {
        fork_lowpriv_worker(ctx, proc_title, is_forked, worker_fn)
    } else {
        run_inline_section(ctx, proc_title, is_forked, worker_fn)
    }
}

fn fork_lowpriv_worker<T,F>(ctx: &mut VtunContext, proc_title: &str, is_forked: &mut bool, worker_fn: &mut F) -> Result<T, ExitCode> where T: LowprivReturnable<T>, F: FnMut(&mut VtunContext) -> Result<T,()>
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
                        Ok(_) => {
                            match w.flush() {
                                Ok(_) => Err(ExitCode::from_code(0)),
                                Err(_) => {
                                    ctx.syslog(lfd_mod::LOG_ERR, "Unable to flush writes to pipe for low privileged child");
                                    Err(ExitCode::from_code(1))
                                }
                            }
                        },
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
            Ok(_) => {
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
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn drop_privileges(ctx: &VtunContext) -> Result<(),()> {
    ctx.syslog(lfd_mod::LOG_ERR, "Security hardening option dropcaps is not supported on this platform");
    Err(ExitCode::from_code(1))
}

fn run_inline_section<T,F>(ctx: &mut VtunContext, proc_title: &str, is_forked: &mut bool, worker_fn: &mut F) -> Result<T, ExitCode> where T: LowprivReturnable<T>, F: FnMut(&mut VtunContext) -> Result<T,()> {
    *is_forked = false;
    set_title(proc_title);
    match worker_fn(ctx) {
        Ok(rv) => Ok(rv),
        Err(_) => Err(ExitCode::from_code(1))
    }
}

fn drop_privileges(ctx: &VtunContext) -> Result<(),()> {
    if ctx.vtun.dropcaps {
        match drop_caps(ctx, true, ctx.vtun.setuid || ctx.vtun.setgid) {
            Ok(_) => {},
            Err(_) => return Err(())
        }
    }
    if ctx.vtun.setuid || ctx.vtun.setgid {
        if ctx.vtun.setgid {
            match setgid(ctx) {
                Ok(_) => {},
                Err(_) => return Err(())
            };
        }
        if ctx.vtun.setuid {
            match setuid(ctx) {
                Ok(_) => {},
                Err(_) => return Err(())
            };
        }
        if ctx.vtun.dropcaps {
            match drop_caps(ctx, false, false) {
                Ok(_) => {},
                Err(_) => return Err(())
            }
        }
    }
    Ok(())
}

fn get_user_id(ctx: &VtunContext, user: &lfd_mod::SetUidIdentifier) -> Result<libc::uid_t,()> {
    let user = match user {
        lfd_mod::SetUidIdentifier::Id(id) => return Ok(*id as libc::uid_t),
        lfd_mod::SetUidIdentifier::Name(name) => name.as_str(),
        lfd_mod::SetUidIdentifier::Default => "nobody"
    };
    let uid = {
        let cache = UsersCache::new();
        match cache.get_user_by_name(user) {
            Some(passwd) => passwd.uid(),
            None => {
                let msg = format!("Failed to retrieve user information for setgid: {}", user);
                ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                return Err(());
            }
        }
    };
    Ok(uid)
}

fn get_group_id(ctx: &VtunContext, user: &lfd_mod::SetUidIdentifier) -> Result<libc::gid_t,()> {
    let user = match user {
        lfd_mod::SetUidIdentifier::Id(id) => return Ok(*id as libc::gid_t),
        lfd_mod::SetUidIdentifier::Name(name) => name.as_str(),
        lfd_mod::SetUidIdentifier::Default => "nobody"
    };
    let gid = {
        let cache = UsersCache::new();
        match cache.get_group_by_name(user) {
            Some(passwd) => passwd.gid(),
            None => {
                let msg = format!("Failed to retrieve user information for setgid: {}", user);
                ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
                return Err(());
            }
        }
    };
    Ok(gid)
}

fn setuid(ctx: &VtunContext) -> Result<(),()> {
    let uid = match get_user_id(ctx, &ctx.vtun.set_uid_user) {
        Ok(uid) => uid,
        Err(_) => return Err(())
    };
    if uid == 0 {
        ctx.syslog(lfd_mod::LOG_ERR, "Setting user id to root/0 is not allowed, remove 'hardening setuid' to run as root.");
        return Err(())
    }
    {
        let pid = unsafe { libc::getpid() };
        let msg = format!("Setting uid of pid {} to {}", pid, uid);
        ctx.syslog(lfd_mod::LOG_INFO, msg.as_str());
    }
    if unsafe { libc::setuid(uid) } != 0 {
        ctx.syslog(lfd_mod::LOG_ERR, "Failed to set user id (hardening setuid)");
        return Err(())
    }
    if unsafe { libc::seteuid(uid) } != 0 {
        ctx.syslog(lfd_mod::LOG_ERR, "Failed to set effective user id (hardening setuid)");
        return Err(())
    }
    Ok(())
}

fn setgid(ctx: &VtunContext) -> Result<(),()> {
    let gid = match get_group_id(ctx, &ctx.vtun.set_gid_user) {
        Ok(gid) => gid,
        Err(_) => return Err(())
    };
    if gid == 0 {
        ctx.syslog(lfd_mod::LOG_ERR, "Setting group id to root/0 is not allowed, remove 'hardening setgid' and 'setgid <group>' to run as root.");
        return Err(())
    }
    {
        let pid = unsafe { libc::getpid() };
        let msg = format!("Setting gid of pid {} to {}", pid, gid);
        ctx.syslog(lfd_mod::LOG_INFO, msg.as_str());
    }
    if unsafe { libc::setgid(gid) } != 0 {
        ctx.syslog(lfd_mod::LOG_ERR, "Failed to set user id (hardening setuid)");
        return Err(())
    }
    if unsafe { libc::setegid(gid) } != 0 {
        ctx.syslog(lfd_mod::LOG_ERR, "Failed to set effective user id (hardening setuid)");
        return Err(())
    }
    Ok(())
}

#[cfg(target_os = "freebsd")]
fn drop_caps(ctx: &VtunContext, is_root: bool, will_setuid: bool) -> Result<(),()> {
    if (!is_root || !will_setuid) {
        if (unsafe { libc::cap_enter() } < 0) {
            ctx.syslog(lfd_mod::LOG_ERR, "Unable to enter capability restricted mode");
            return Err(());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn drop_caps(ctx: &VtunContext, is_root: bool, will_setuid: bool) -> Result<(),()> {
    if !is_root || !will_setuid {
        match set_no_new_privs(ctx) {
            Ok(_) => {},
            Err(_) => return Err(())
        }
    }
    drop_capsets(ctx, is_root, !is_root)
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

const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;

#[cfg(target_os = "linux")]
fn drop_capsets(ctx: &VtunContext, drop_bounding: bool, drop_setuid: bool) -> Result<(),()> {
    if drop_bounding {
        for cap in 0..=63 {
            if !drop_setuid && (cap == CAP_SETGID || cap == CAP_SETUID) {
                continue;
            }
            let capread = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap) };
            if capread < 0 {
                break;
            }
            if (capread & 1) == 0 {
                continue;
            }
            if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } < 0 {
                ctx.syslog(lfd_mod::LOG_ERR, "Unable to drop capability from bounding set");
            }
        }
    }

    // Drop ambient set capabilities
    if unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) } != 0 {
        ctx.syslog(lfd_mod::LOG_ERR, "Unable to drop capabilities from ambient set");
    }

    // Drop effective, permitted and inheritable capabilities
    let mut hdr: CapHdr = unsafe { std::mem::zeroed() };
    let mut data: CapData = unsafe { std::mem::zeroed() };
    hdr.version = 0x20080522;
    hdr.pid = 0;
    if unsafe { libc::syscall(libc::SYS_capget, &mut hdr as *mut CapHdr as *mut libc::c_void, &mut data as *mut CapData as *mut libc::c_void) } < 0 {
        let msg = format!("Unable to get capabilities: {}", errno::errno().to_string());
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
    }
    for i in 0..4 {
        let base_cap = i * 32;
        let next_cap = base_cap + 32;
        let mut mask: u32 = 0;
        if !drop_setuid {
            if CAP_SETGID >= base_cap && CAP_SETGID < next_cap {
                mask |= 1 << (CAP_SETGID - base_cap);
            }
            if CAP_SETUID >= base_cap && CAP_SETUID < next_cap {
                mask |= 1 << (CAP_SETUID - base_cap);
            }
        }
        data.capabilities[i as usize].effective &= mask;
        data.capabilities[i as usize].permitted &= mask;
        data.capabilities[i as usize].inheritable &= mask;
    }
    if unsafe { libc::syscall(libc::SYS_capset, &mut hdr as *mut CapHdr as *mut libc::c_void, &mut data as *mut CapData as *mut libc::c_void) } < 0 {
        let msg = format!("Unable to set capabilities: {}", errno::errno().to_string());
        ctx.syslog(lfd_mod::LOG_ERR, msg.as_str());
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
