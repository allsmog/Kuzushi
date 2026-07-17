use super::{ProcessBirthIdentity, ProcessObservation};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, FILETIME, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
};

pub(super) fn observe(process_id: u32) -> ProcessObservation {
    let access = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;
    let handle = unsafe { OpenProcess(access, 0, process_id) };
    if handle.is_null() {
        return if unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
            ProcessObservation::Dead
        } else {
            ProcessObservation::Unknown
        };
    }
    let observation = observe_open_process(handle);
    unsafe { CloseHandle(handle) };
    observation
}

fn observe_open_process(handle: windows_sys::Win32::Foundation::HANDLE) -> ProcessObservation {
    let wait = wait_observation(unsafe { WaitForSingleObject(handle, 0) });
    if wait != ProcessObservation::Alive(None) {
        return wait;
    }
    observe_creation_identity(handle)
}

fn wait_observation(wait_result: u32) -> ProcessObservation {
    match wait_result {
        WAIT_OBJECT_0 => ProcessObservation::Dead,
        WAIT_TIMEOUT => ProcessObservation::Alive(None),
        _ => ProcessObservation::Unknown,
    }
}

fn observe_creation_identity(handle: windows_sys::Win32::Foundation::HANDLE) -> ProcessObservation {
    let (mut creation, mut exit, mut kernel, mut user) = zero_file_times();
    if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return ProcessObservation::Alive(None);
    }
    ProcessObservation::Alive(Some(ProcessBirthIdentity {
        platform: "windows".to_string(),
        boot_id: None,
        start_token: file_time_value(creation).to_string(),
    }))
}

fn zero_file_times() -> (FILETIME, FILETIME, FILETIME, FILETIME) {
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    (zero, zero, zero, zero)
}

fn file_time_value(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::WAIT_FAILED;

    #[test]
    fn wait_result_is_the_liveness_source_of_truth() {
        assert_eq!(wait_observation(WAIT_OBJECT_0), ProcessObservation::Dead);
        assert_eq!(
            wait_observation(WAIT_TIMEOUT),
            ProcessObservation::Alive(None)
        );
        assert_eq!(wait_observation(WAIT_FAILED), ProcessObservation::Unknown);
        assert_eq!(wait_observation(7), ProcessObservation::Unknown);
    }

    #[test]
    fn child_with_exit_code_259_is_dead() {
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/C", "exit", "259"])
            .spawn()
            .unwrap();
        let access = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;
        let handle = unsafe { OpenProcess(access, 0, child.id()) };
        assert!(!handle.is_null());
        child.wait().unwrap();

        assert_eq!(observe_open_process(handle), ProcessObservation::Dead);
        unsafe { CloseHandle(handle) };
    }

    #[test]
    fn running_child_is_alive_with_creation_identity() {
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/C", "ping", "-n", "6", "127.0.0.1", ">", "NUL"])
            .spawn()
            .unwrap();
        let observation = observe(child.id());
        let _ = child.kill();
        let _ = child.wait();

        assert!(matches!(observation, ProcessObservation::Alive(Some(_))));
    }
}
