use super::ProcessObservation;

pub(super) fn observe(process_id: u32) -> ProcessObservation {
    let Ok(pid) = libc::pid_t::try_from(process_id) else {
        return ProcessObservation::Dead;
    };
    if pid <= 0 {
        return ProcessObservation::Dead;
    }
    if unsafe { libc::kill(pid, 0) } == 0 {
        return ProcessObservation::Alive(None);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EPERM) => ProcessObservation::Alive(None),
        Some(libc::ESRCH) => ProcessObservation::Dead,
        _ => ProcessObservation::Unknown,
    }
}
