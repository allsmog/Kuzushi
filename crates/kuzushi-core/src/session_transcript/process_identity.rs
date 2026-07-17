#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ProcessLiveness {
    Alive,
    Dead,
    Unknown,
}

pub(super) fn start_token(process_id: u32) -> Option<String> {
    platform::observe(process_id).token
}

pub(super) fn liveness(process_id: u32, expected_token: Option<&str>) -> ProcessLiveness {
    let observation = platform::observe(process_id);
    if observation.liveness != ProcessLiveness::Alive {
        return observation.liveness;
    }
    match (expected_token, observation.token.as_deref()) {
        (Some(expected), Some(actual)) if expected != actual => ProcessLiveness::Dead,
        (Some(_), None) => ProcessLiveness::Unknown,
        _ => ProcessLiveness::Alive,
    }
}

struct ProcessObservation {
    liveness: ProcessLiveness,
    token: Option<String>,
}

impl ProcessObservation {
    fn alive(token: Option<String>) -> Self {
        Self {
            liveness: ProcessLiveness::Alive,
            token,
        }
    }

    fn dead() -> Self {
        Self {
            liveness: ProcessLiveness::Dead,
            token: None,
        }
    }

    fn unknown() -> Self {
        Self {
            liveness: ProcessLiveness::Unknown,
            token: None,
        }
    }
}

mod platform {
    use super::ProcessObservation;

    #[cfg(target_os = "linux")]
    pub(super) fn observe(process_id: u32) -> ProcessObservation {
        let path = std::path::Path::new("/proc")
            .join(process_id.to_string())
            .join("stat");
        let stat = match crate::bounded_file::read_utf8_text(&path, 16 * 1024) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return ProcessObservation::dead()
            }
            Err(_) => return ProcessObservation::unknown(),
        };
        linux_observation(&stat)
    }

    #[cfg(target_os = "linux")]
    fn linux_observation(stat: &str) -> ProcessObservation {
        let Some((state, token)) = parse_linux_stat(stat) else {
            return ProcessObservation::unknown();
        };
        if matches!(state, "Z" | "X" | "x") {
            return ProcessObservation::dead();
        }
        ProcessObservation::alive(Some(token.to_string()))
    }

    #[cfg(target_os = "linux")]
    fn parse_linux_stat(stat: &str) -> Option<(&str, &str)> {
        let fields = stat
            .rsplit_once(") ")?
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        Some((*fields.first()?, *fields.get(19)?))
    }

    #[cfg(target_os = "macos")]
    pub(super) fn observe(process_id: u32) -> ProcessObservation {
        use std::mem::{size_of, MaybeUninit};
        let Ok(pid) = libc::pid_t::try_from(process_id) else {
            return ProcessObservation::dead();
        };
        let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let size = i32::try_from(size_of::<libc::proc_bsdinfo>()).unwrap_or(i32::MAX);
        let read = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if read != size {
            return missing_process();
        }
        macos_observation(unsafe { info.assume_init() })
    }

    #[cfg(target_os = "macos")]
    fn macos_observation(info: libc::proc_bsdinfo) -> ProcessObservation {
        if info.pbi_status == libc::SZOMB {
            return ProcessObservation::dead();
        }
        ProcessObservation::alive(Some(format!(
            "{}:{}",
            info.pbi_start_tvsec, info.pbi_start_tvusec
        )))
    }

    #[cfg(target_os = "macos")]
    fn missing_process() -> ProcessObservation {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            ProcessObservation::dead()
        } else {
            ProcessObservation::unknown()
        }
    }

    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    pub(super) fn observe(process_id: u32) -> ProcessObservation {
        let Ok(pid) = libc::pid_t::try_from(process_id) else {
            return ProcessObservation::dead();
        };
        if unsafe { libc::kill(pid, 0) } == 0 {
            return ProcessObservation::alive(None);
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EPERM) => ProcessObservation::alive(None),
            Some(libc::ESRCH) => ProcessObservation::dead(),
            _ => ProcessObservation::unknown(),
        }
    }

    #[cfg(windows)]
    pub(super) fn observe(process_id: u32) -> ProcessObservation {
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        if handle.is_null() {
            return ProcessObservation::dead();
        }
        let result = windows_observation(handle);
        unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
        result
    }

    #[cfg(windows)]
    fn windows_observation(handle: windows_sys::Win32::Foundation::HANDLE) -> ProcessObservation {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::Threading::GetProcessTimes;
        let mut times = [FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        }; 4];
        if unsafe {
            GetProcessTimes(
                handle,
                &mut times[0],
                &mut times[1],
                &mut times[2],
                &mut times[3],
            )
        } == 0
        {
            return ProcessObservation::alive(None);
        }
        let token = (u64::from(times[0].dwHighDateTime) << 32) | u64::from(times[0].dwLowDateTime);
        ProcessObservation::alive(Some(token.to_string()))
    }

    #[cfg(not(any(unix, windows)))]
    pub(super) fn observe(_process_id: u32) -> ProcessObservation {
        ProcessObservation::unknown()
    }
}
