use super::{ProcessBirthIdentity, ProcessObservation};
use std::mem::{size_of, MaybeUninit};

pub(super) fn observe(process_id: u32) -> ProcessObservation {
    let Ok(pid) = libc::pid_t::try_from(process_id) else {
        return ProcessObservation::Dead;
    };
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = size_of::<libc::proc_bsdinfo>();
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            i32::try_from(size).unwrap_or(i32::MAX),
        )
    };
    if read != i32::try_from(size).unwrap_or(i32::MAX) {
        return missing_process_observation();
    }
    let info = unsafe { info.assume_init() };
    if info.pbi_status == libc::SZOMB {
        return ProcessObservation::Dead;
    }
    ProcessObservation::Alive(Some(ProcessBirthIdentity {
        platform: "macos".to_string(),
        boot_id: None,
        start_token: format!("{}:{}", info.pbi_start_tvsec, info.pbi_start_tvusec),
    }))
}

fn missing_process_observation() -> ProcessObservation {
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        ProcessObservation::Dead
    } else {
        ProcessObservation::Unknown
    }
}
