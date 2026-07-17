use anyhow::{Context, Result};
use tokio::process::Child;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

pub(super) fn create_kill_on_close_job(child: &Child) -> Result<isize> {
    let child_handle = child
        .raw_handle()
        .context("MCP subprocess has no Windows process handle")?;
    // SAFETY: null names/security attributes request a private unnamed job.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    anyhow::ensure!(!job.is_null(), std::io::Error::last_os_error());
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: pointers and sizes match the documented extended-limit structure.
    let configured = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    // SAFETY: both handles are live for the duration of the assignment call.
    let assigned =
        configured != 0 && unsafe { AssignProcessToJobObject(job, child_handle as _) } != 0;
    if !assigned {
        let error = std::io::Error::last_os_error();
        unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
        return Err(error).context("assign MCP subprocess to Windows kill-on-close job");
    }
    Ok(job as isize)
}

pub(super) fn terminate_job(job: Option<isize>) {
    if let Some(job) = job {
        // SAFETY: the handle is owned by the live process guard.
        unsafe { windows_sys::Win32::System::JobObjects::TerminateJobObject(job as _, 1) };
    }
}

pub(super) fn close_job(job: Option<isize>) {
    if let Some(job) = job {
        // SAFETY: `take` ensures the owned handle is closed exactly once.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(job as _) };
    }
}
