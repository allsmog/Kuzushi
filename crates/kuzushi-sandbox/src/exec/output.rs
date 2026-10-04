use crate::backend::SandboxBackend;

use super::{ExitOutcome, SandboxExecResult, MAX_OUTPUT_BYTES, TRUNCATION_MARKER};

pub(super) fn completed_sandbox_result(
    backend: SandboxBackend,
    duration_ms: u64,
    output: std::process::Output,
) -> SandboxExecResult {
    let (stdout, stdout_truncated) = cap_output(output.stdout);
    let (stderr, stderr_truncated) = cap_output(output.stderr);
    let signal = child_exit_signal(&output.status);
    SandboxExecResult {
        backend,
        outcome: exit_outcome(signal),
        exit_code: output.status.code(),
        signal,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        duration_ms,
    }
}

fn child_exit_signal(status: &std::process::ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

fn exit_outcome(signal: Option<i32>) -> ExitOutcome {
    if signal.is_some() {
        ExitOutcome::Signaled
    } else {
        ExitOutcome::Exited
    }
}

pub(crate) fn cap_output(bytes: Vec<u8>) -> (String, bool) {
    if bytes.len() <= MAX_OUTPUT_BYTES {
        return (String::from_utf8_lossy(&bytes).into_owned(), false);
    }
    let mut head = String::from_utf8_lossy(&bytes[..MAX_OUTPUT_BYTES]).into_owned();
    head.push_str(TRUNCATION_MARKER);
    (head, true)
}
