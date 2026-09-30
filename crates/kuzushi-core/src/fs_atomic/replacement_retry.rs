use std::io;
use std::time::Duration;

// MoveFileExW can fail transiently while another replacement has the old
// destination open/delete-pending. Keep the synced source intact and retry the
// atomic operation; never remove the destination to make a rename succeed.
const MAX_RETRIES: usize = 10;

pub(super) fn replace_with_retry(replace: impl FnMut() -> io::Result<()>) -> io::Result<()> {
    retry_replacement(replace, std::thread::sleep)
}

fn retry_replacement(
    mut replace: impl FnMut() -> io::Result<()>,
    mut wait: impl FnMut(Duration),
) -> io::Result<()> {
    for attempt in 0..=MAX_RETRIES {
        let result = replace();
        if !should_retry(&result, attempt) {
            return result;
        }
        wait(Duration::from_millis(1 << attempt.min(7)));
    }
    unreachable!("the last attempt always returns its result")
}

fn should_retry(result: &io::Result<()>, attempt: usize) -> bool {
    if attempt == MAX_RETRIES {
        return false;
    }
    // ERROR_ACCESS_DENIED and ERROR_SHARING_VIOLATION. Persistent permission
    // failures still return their original error after at most 511 ms of waits.
    matches!(
        result.as_ref().err().and_then(io::Error::raw_os_error),
        Some(5 | 32)
    )
}

#[cfg(test)]
#[path = "replacement_retry/tests.rs"]
mod tests;
