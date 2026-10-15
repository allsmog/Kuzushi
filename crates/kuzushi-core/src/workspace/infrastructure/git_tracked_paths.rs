use anyhow::Result;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

use crate::scan::ScanCancellation;

const INDEX_DEADLINE: Duration = Duration::from_secs(30);
const CANCEL_POLL: Duration = Duration::from_millis(25);

#[derive(Clone)]
pub(crate) enum GitIndexEnumeration {
    Tracked {
        paths: Vec<String>,
        fingerprint: String,
    },
    Unavailable,
    Canceled,
}

/// Acquisition uses the shared 64 MiB stdout / 1 MiB stderr bounds and a
/// deadline. Only an absent Git index permits filesystem enumeration.
pub(crate) fn git_tracked_relative_paths(
    root: &Path,
    max_entries: usize,
    should_cancel: &dyn Fn() -> bool,
) -> Result<GitIndexEnumeration> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "--cached"])
        .env("LC_ALL", "C")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null());
    acquire_index(command, max_entries, should_cancel, INDEX_DEADLINE)
}

fn acquire_index(
    mut command: Command,
    max_entries: usize,
    should_cancel: &dyn Fn() -> bool,
    deadline: Duration,
) -> Result<GitIndexEnumeration> {
    let cancellation = ScanCancellation::default();
    request_cancellation(&cancellation, should_cancel);
    let result = std::thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel(1);
        let cancellation = &cancellation;
        scope.spawn(move || {
            let result = crate::bounded_subprocess::output_with_control(
                &mut command,
                "Git inventory enumeration",
                Some(cancellation),
                deadline,
            );
            let _ = sender.send(result);
        });
        wait_for_index(&receiver, cancellation, should_cancel)
    });
    if cancellation.is_cancelled() {
        return Ok(GitIndexEnumeration::Canceled);
    }
    classify_index_result(result, max_entries)
}

fn wait_for_index(
    receiver: &Receiver<Result<Output>>,
    cancellation: &ScanCancellation,
    should_cancel: &dyn Fn() -> bool,
) -> Result<Output> {
    loop {
        request_cancellation(cancellation, should_cancel);
        match receiver.recv_timeout(CANCEL_POLL) {
            Ok(result) => return result,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                anyhow::bail!("Git inventory worker disconnected")
            }
        }
    }
}

fn request_cancellation(cancellation: &ScanCancellation, should_cancel: &dyn Fn() -> bool) {
    if !cancellation.is_cancelled() && should_cancel() {
        cancellation.cancel();
    }
}

fn classify_index_result(
    result: Result<Output>,
    max_entries: usize,
) -> Result<GitIndexEnumeration> {
    match result {
        Ok(output) => parse_index_output(output, max_entries),
        Err(error) if git_is_missing(&error) => Ok(GitIndexEnumeration::Unavailable),
        Err(error) => {
            Err(error
                .context("Git inventory acquisition stopped; filesystem fallback was not used"))
        }
    }
}

fn git_is_missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn parse_index_output(output: Output, max_entries: usize) -> Result<GitIndexEnumeration> {
    if !output.status.success() {
        return classify_git_failure(&output.stderr);
    }
    if output.stdout.is_empty() {
        return Ok(GitIndexEnumeration::Unavailable);
    }
    anyhow::ensure!(
        output.stdout.last() == Some(&0),
        "Git inventory returned an incomplete path list"
    );
    let paths = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|segment| !segment.is_empty())
        .take(max_entries.saturating_add(1))
        .map(|segment| String::from_utf8_lossy(segment).into_owned())
        .collect();
    let mut fingerprint = blake3::Hasher::new();
    fingerprint.update(b"git-inventory-paths-v1\0");
    fingerprint.update(&output.stdout);
    Ok(GitIndexEnumeration::Tracked {
        paths,
        fingerprint: fingerprint.finalize().to_hex().to_string(),
    })
}

fn classify_git_failure(stderr: &[u8]) -> Result<GitIndexEnumeration> {
    let message = String::from_utf8_lossy(stderr);
    if message.starts_with("fatal: not a git repository") {
        return Ok(GitIndexEnumeration::Unavailable);
    }
    anyhow::bail!(
        "Git inventory failed; filesystem fallback was not used: {}",
        message.trim()
    );
}

#[cfg(test)]
mod tests;
