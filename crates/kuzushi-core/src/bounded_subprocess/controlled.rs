use super::{DEFAULT_STDERR_LIMIT, DEFAULT_STDOUT_LIMIT};
use anyhow::{Context, Result};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

mod io;

use io::ControlledIo;

const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(25);

pub(super) fn controlled_output(
    command: &mut Command,
    label: &str,
    input: Option<Vec<u8>>,
    cancellation: Option<&crate::scan::ScanCancellation>,
    timeout: Duration,
) -> Result<Output> {
    controlled_output_with_stdout(
        command,
        label,
        input,
        None,
        cancellation,
        timeout,
        DEFAULT_STDOUT_LIMIT,
        DEFAULT_STDERR_LIMIT,
    )
}

pub(super) fn controlled_output_with_limits(
    command: &mut Command,
    label: &str,
    stdout_limit: usize,
    stderr_limit: usize,
    timeout: Duration,
) -> Result<Output> {
    controlled_output_with_stdout(
        command,
        label,
        None,
        None,
        None,
        timeout,
        stdout_limit,
        stderr_limit,
    )
}

pub(super) fn controlled_output_to_file(
    command: &mut Command,
    label: &str,
    input: Option<Vec<u8>>,
    stdout: std::fs::File,
    stdout_limit: u64,
    cancellation: Option<&crate::scan::ScanCancellation>,
    timeout: Duration,
) -> Result<Output> {
    controlled_output_with_stdout(
        command,
        label,
        input,
        Some((stdout, stdout_limit)),
        cancellation,
        timeout,
        DEFAULT_STDOUT_LIMIT,
        DEFAULT_STDERR_LIMIT,
    )
}

fn controlled_output_with_stdout(
    command: &mut Command,
    label: &str,
    input: Option<Vec<u8>>,
    stdout: Option<(std::fs::File, u64)>,
    cancellation: Option<&crate::scan::ScanCancellation>,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<Output> {
    anyhow::ensure!(
        !timeout.is_zero(),
        "{label} timeout must be greater than zero"
    );
    anyhow::ensure!(
        !cancellation.is_some_and(crate::scan::ScanCancellation::is_cancelled),
        "{label} was cancelled before it started"
    );
    let deadline = Instant::now()
        .checked_add(timeout)
        .with_context(|| format!("{label} deadline is outside the supported clock range"))?;
    configure_controlled_stdio(command, input.is_some());
    let process_group = crate::scan::configure_scanner_process_group(command)?;
    let mut child = command
        .spawn()
        .with_context(|| format!("Could not start {label}"))?;
    let io =
        match ControlledIo::capture(&mut child, input, label, stdout, stdout_limit, stderr_limit) {
            Ok(io) => io,
            Err(error) => return Err(terminate_unregistered_child(child, process_group, error)),
        };
    let local_cancellation = crate::scan::ScanCancellation::default();
    let cancellation = cancellation.unwrap_or(&local_cancellation);
    let child = match cancellation.register_prepared_child(child, process_group) {
        Ok(child) => child,
        Err(error) => return Err(io.join_cleanup(error)),
    };
    wait_for_controlled_output(child, io, cancellation, deadline, timeout, label)
}

fn configure_controlled_stdio(command: &mut Command, has_input: bool) {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if has_input {
        command.stdin(Stdio::piped());
    }
}

fn terminate_unregistered_child(
    mut child: Child,
    process_group: crate::scan::PreparedProcessGroup,
    error: anyhow::Error,
) -> anyhow::Error {
    let group_owned = process_group.process_group_id().is_some();
    drop(process_group);
    if !group_owned {
        let _ = child.kill();
    }
    match child.wait() {
        Ok(_) => error,
        Err(cleanup) => anyhow::Error::new(cleanup).context(error),
    }
}

fn wait_for_controlled_output(
    child: crate::scan::RegisteredChild,
    io: ControlledIo,
    cancellation: &crate::scan::ScanCancellation,
    deadline: Instant,
    timeout: Duration,
    label: &str,
) -> Result<Output> {
    loop {
        match controlled_wait_step(&child, &io, cancellation, deadline, timeout, label) {
            ControlledWaitStep::Running => thread::sleep(CONTROL_POLL_INTERVAL),
            ControlledWaitStep::Exited(status) => {
                let status_succeeded = status.success();
                let joined = io.join(status, label);
                return resolve_exited_output(
                    joined,
                    status_succeeded,
                    cancellation.is_cancelled(),
                    label,
                );
            }
            ControlledWaitStep::Failed(error) => {
                return Err(terminate_controlled_child(&child, io, error));
            }
        }
    }
}

fn resolve_exited_output<T>(
    joined: Result<T>,
    status_succeeded: bool,
    cancellation_requested: bool,
    label: &str,
) -> Result<T> {
    if status_succeeded || !cancellation_requested {
        return joined;
    }
    let message = format!("{label} was cancelled and killed");
    Err(match joined {
        Ok(_) => anyhow::anyhow!(message),
        Err(error) => error.context(message),
    })
}

enum ControlledWaitStep {
    Running,
    Exited(ExitStatus),
    Failed(anyhow::Error),
}

fn controlled_wait_step(
    child: &crate::scan::RegisteredChild,
    io: &ControlledIo,
    cancellation: &crate::scan::ScanCancellation,
    deadline: Instant,
    timeout: Duration,
    label: &str,
) -> ControlledWaitStep {
    if let Some(error) = controlled_stop_request(io, cancellation, deadline, timeout, label) {
        return ControlledWaitStep::Failed(error);
    }
    match child.try_wait() {
        Ok(Some(status)) => ControlledWaitStep::Exited(status),
        Ok(None) => ControlledWaitStep::Running,
        Err(error) => ControlledWaitStep::Failed(error.context(format!("Could not poll {label}"))),
    }
}

fn controlled_stop_request(
    io: &ControlledIo,
    cancellation: &crate::scan::ScanCancellation,
    deadline: Instant,
    timeout: Duration,
    label: &str,
) -> Option<anyhow::Error> {
    if cancellation.is_cancelled() {
        return Some(anyhow::anyhow!("{label} was cancelled and killed"));
    }
    if Instant::now() >= deadline {
        return Some(anyhow::anyhow!(
            "{label} exceeded its {} ms deadline and was killed",
            timeout.as_nanos().div_ceil(1_000_000)
        ));
    }
    match io.failure() {
        Ok(Some(failure)) => Some(anyhow::anyhow!("{label}: {failure}")),
        Ok(None) => None,
        Err(error) => Some(error),
    }
}

fn terminate_controlled_child(
    child: &crate::scan::RegisteredChild,
    io: ControlledIo,
    error: anyhow::Error,
) -> anyhow::Error {
    let error = match child.kill_and_wait() {
        Ok(()) => error,
        Err(cleanup) => cleanup.context(error),
    };
    io.join_cleanup(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_wins_when_killed_process_exit_wins_poll_race() {
        let error = resolve_exited_output(Ok(()), false, true, "fixture")
            .unwrap_err()
            .to_string();

        assert_eq!(error, "fixture was cancelled and killed");
    }

    #[test]
    fn late_cancellation_does_not_replace_successful_completion() {
        let output = resolve_exited_output(Ok("complete"), true, true, "fixture").unwrap();

        assert_eq!(output, "complete");
    }

    #[test]
    fn cancellation_keeps_join_failure_in_its_error_chain() {
        let error = resolve_exited_output::<()>(
            Err(anyhow::anyhow!("pipe failed")),
            false,
            true,
            "fixture",
        )
        .unwrap_err();
        let chain = format!("{error:#}");

        assert!(
            chain.contains("fixture was cancelled and killed"),
            "{chain}"
        );
        assert!(chain.contains("pipe failed"), "{chain}");
    }
}
