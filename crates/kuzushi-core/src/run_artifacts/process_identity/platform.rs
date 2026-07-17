use super::{ProcessBirthIdentity, ProcessObservation};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
mod other_unix;
#[cfg(windows)]
mod windows;

pub(super) fn observe(process_id: u32) -> ProcessObservation {
    implementation::observe(process_id)
}

#[cfg(target_os = "linux")]
use linux as implementation;
#[cfg(target_os = "macos")]
use macos as implementation;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
use other_unix as implementation;
#[cfg(windows)]
use windows as implementation;

#[cfg(not(any(unix, windows)))]
mod implementation {
    use super::ProcessObservation;

    pub(super) fn observe(_process_id: u32) -> ProcessObservation {
        ProcessObservation::Unknown
    }
}
