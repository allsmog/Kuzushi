use super::*;

impl RegisteredChild {
    pub fn try_wait(&self) -> Result<Option<ExitStatus>> {
        let mut children = self
            .children
            .lock()
            .map_err(|_| anyhow::anyhow!("scan cancellation registry was poisoned"))?;
        let Some(managed) = children.get_mut(&self.id) else {
            return Ok(None);
        };
        let status = managed.child.try_wait()?;
        if status.is_some() {
            // The process leader may exit while descendants still hold its
            // stdout/stderr pipes open. Reap the whole managed group before
            // output readers join so a descendant cannot outlive the tool.
            if let Some(mut managed) = children.remove(&self.id) {
                kill_managed_child(&mut managed);
            }
        }
        Ok(status)
    }

    pub fn kill_and_wait(&self) -> Result<()> {
        let mut children = self
            .children
            .lock()
            .map_err(|_| anyhow::anyhow!("scan cancellation registry was poisoned"))?;
        if let Some(mut child) = children.remove(&self.id) {
            kill_managed_child(&mut child);
            let _ = child.child.wait();
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(in crate::scan) struct ManagedChild {
    pub(in crate::scan) child: Child,
    pub(in crate::scan) process_group_id: Option<u32>,
    #[cfg(unix)]
    pub(in crate::scan) parent_death_guard: Option<ParentDeathGuard>,
    #[cfg(windows)]
    pub(in crate::scan) job_handle: Option<isize>,
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(mut guard) = self.parent_death_guard.take() {
            guard.finish();
        }
        #[cfg(windows)]
        {
            if let Some(job_handle) = self.job_handle.take() {
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(job_handle as _);
                }
            }
        }
    }
}

pub(in crate::scan) fn kill_managed_child(child: &mut ManagedChild) {
    #[cfg(unix)]
    {
        if let Some(process_group_id) = child.process_group_id {
            unsafe {
                libc::killpg(process_group_id as libc::pid_t, libc::SIGKILL);
            }
            if let Some(mut guard) = child.parent_death_guard.take() {
                guard.finish();
            }
            return;
        }
    }

    #[cfg(windows)]
    if let Some(job_handle) = child.job_handle.take() {
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(job_handle as _, 1);
            windows_sys::Win32::Foundation::CloseHandle(job_handle as _);
        }
        return;
    }

    let _ = child.child.kill();
}

#[cfg(windows)]
pub(in crate::scan) fn create_kill_on_close_job(child: &Child) -> Result<isize> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    let job = unsafe {
        windows_sys::Win32::System::JobObjects::CreateJobObjectW(std::ptr::null(), std::ptr::null())
    };
    if job.is_null() {
        return Err(std::io::Error::last_os_error()).context("create Windows child-process job");
    }
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let configured = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    let assigned = configured != 0
        && unsafe { AssignProcessToJobObject(job, child.as_raw_handle() as _) } != 0;
    if !assigned {
        let error = std::io::Error::last_os_error();
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(job);
        }
        return Err(error).context("assign child process to Windows kill-on-close job");
    }
    Ok(job as isize)
}

pub(crate) fn configure_scanner_process_group(
    command: &mut Command,
) -> Result<PreparedProcessGroup> {
    PreparedProcessGroup::configure(command)
}

pub(in crate::scan) const SCANNER_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "TMPDIR",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NO_COLOR",
    "TERM",
];

pub(crate) fn configure_scanner_subprocess_env(command: &mut Command) {
    command.env_clear();
    for (key, value) in scrubbed_scanner_environment() {
        command.env(key, value);
    }
}

pub(in crate::scan) fn scrubbed_scanner_environment(
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    env::vars_os()
        .filter(|(key, _)| key.to_str().is_some_and(|key| is_safe_scanner_env_key(key)))
        .collect()
}
