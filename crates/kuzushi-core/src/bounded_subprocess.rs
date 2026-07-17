use anyhow::{Context, Result};
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;

mod controlled;

use controlled::controlled_output;

#[cfg(test)]
use std::time::Instant;

pub(crate) const DEFAULT_STDOUT_LIMIT: usize = 64 * 1024 * 1024;
pub(crate) const DEFAULT_STDERR_LIMIT: usize = 1024 * 1024;

pub(crate) fn output(command: &mut Command, label: &str) -> Result<Output> {
    output_with_limits(command, label, DEFAULT_STDOUT_LIMIT, DEFAULT_STDERR_LIMIT)
}

pub(crate) fn output_with_limits(
    command: &mut Command,
    label: &str,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<Output> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .with_context(|| format!("Could not start {label}"))?;
    let stdout = child
        .stdout
        .take()
        .with_context(|| format!("Could not capture {label} stdout"))?;
    let stderr = child
        .stderr
        .take()
        .with_context(|| format!("Could not capture {label} stderr"))?;
    let stdout = thread::spawn(move || drain_bounded(stdout, stdout_limit, "stdout"));
    let stderr = thread::spawn(move || drain_bounded(stderr, stderr_limit, "stderr"));
    let status = child
        .wait()
        .with_context(|| format!("Could not wait for {label}"))?;
    let stdout = join_reader(stdout, label)?;
    let stderr = join_reader(stderr, label)?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

pub(crate) fn output_with_control(
    command: &mut Command,
    label: &str,
    cancellation: Option<&crate::scan::ScanCancellation>,
    timeout: Duration,
) -> Result<Output> {
    controlled_output(command, label, None, cancellation, timeout)
}

pub(crate) fn output_with_limits_and_control(
    command: &mut Command,
    label: &str,
    stdout_limit: usize,
    stderr_limit: usize,
    timeout: Duration,
) -> Result<Output> {
    controlled::controlled_output_with_limits(command, label, stdout_limit, stderr_limit, timeout)
}

pub(crate) fn output_with_input_and_control(
    command: &mut Command,
    label: &str,
    input: Vec<u8>,
    cancellation: Option<&crate::scan::ScanCancellation>,
    timeout: Duration,
) -> Result<Output> {
    controlled_output(command, label, Some(input), cancellation, timeout)
}

pub(crate) fn output_with_input_to_file_and_control(
    command: &mut Command,
    label: &str,
    input: Vec<u8>,
    stdout: File,
    stdout_limit: u64,
    cancellation: Option<&crate::scan::ScanCancellation>,
    timeout: Duration,
) -> Result<Output> {
    controlled::controlled_output_to_file(
        command,
        label,
        Some(input),
        stdout,
        stdout_limit,
        cancellation,
        timeout,
    )
}

pub(crate) fn timeout_from_input(
    input: &Value,
    keys: &[&str],
    default_ms: u64,
    max_ms: u64,
    label: &str,
) -> Result<Duration> {
    let value = keys.iter().find_map(|key| input.get(*key));
    let milliseconds = match value {
        Some(value) => value
            .as_u64()
            .with_context(|| format!("{label} must be a positive integer in milliseconds"))?,
        None => default_ms,
    };
    anyhow::ensure!(milliseconds > 0, "{label} must be greater than zero");
    anyhow::ensure!(
        milliseconds <= max_ms,
        "{label} must not exceed {max_ms} milliseconds"
    );
    Ok(Duration::from_millis(milliseconds))
}

fn join_reader(reader: thread::JoinHandle<Result<Vec<u8>>>, label: &str) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("{label} output reader panicked"))?
        .map_err(|error| anyhow::anyhow!("Could not capture {label} output: {error}"))
}

pub(crate) fn drain_bounded(mut reader: impl Read, limit: usize, stream: &str) -> Result<Vec<u8>> {
    let mut captured = Vec::with_capacity(limit.min(64 * 1024));
    let mut buffer = [0u8; 16 * 1024];
    let mut exceeded = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(captured.len());
        captured.extend_from_slice(&buffer[..count.min(remaining)]);
        exceeded |= count > remaining;
    }
    anyhow::ensure!(
        !exceeded,
        "subprocess {stream} exceeded the {limit}-byte capture limit"
    );
    Ok(captured)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Seek;

    #[cfg(unix)]
    #[test]
    fn bounded_output_rejects_excess_while_draining_child() {
        let mut command = Command::new("sh");
        command.args(["-c", "printf '123456789'"]);

        let error = output_with_limits(&mut command, "fixture", 4, 4).unwrap_err();
        let error = format!("{error:#}");

        assert!(error.contains("capture limit"));
    }

    #[cfg(unix)]
    #[test]
    fn controlled_output_kills_sleeping_child_at_deadline() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 60"]);
        let started = Instant::now();

        let error = output_with_control(
            &mut command,
            "sleep fixture",
            None,
            Duration::from_millis(40),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("deadline"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn controlled_output_honors_explicit_capture_limits() {
        let mut command = Command::new("sh");
        command.args(["-c", "printf '123456789'"]);

        let error = output_with_limits_and_control(
            &mut command,
            "bounded controlled fixture",
            4,
            4,
            Duration::from_secs(5),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("capture limit"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn controlled_output_kills_sleeping_child_on_cancellation() {
        let cancellation = crate::scan::ScanCancellation::default();
        let cancel_from_thread = cancellation.clone();
        let canceller = thread::spawn(move || {
            thread::sleep(Duration::from_millis(40));
            cancel_from_thread.cancel();
        });
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 60"]);

        let error = output_with_control(
            &mut command,
            "sleep fixture",
            Some(&cancellation),
            Duration::from_secs(30),
        )
        .unwrap_err()
        .to_string();
        canceller.join().unwrap();

        assert!(error.contains("cancelled"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn controlled_output_reaps_pipe_inheriting_descendant_after_leader_exit() {
        let mut command = Command::new("sh");
        command.args(["-c", "(sleep 60) & exit 0"]);
        let started = Instant::now();

        let output = output_with_control(
            &mut command,
            "descendant fixture",
            None,
            Duration::from_millis(250),
        )
        .unwrap();

        assert!(output.status.success());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn timeout_option_rejects_zero_and_excessive_values() {
        let zero = timeout_from_input(
            &serde_json::json!({"timeoutMs": 0}),
            &["timeoutMs"],
            10,
            20,
            "timeoutMs",
        )
        .unwrap_err()
        .to_string();
        let excessive = timeout_from_input(
            &serde_json::json!({"timeoutMs": 21}),
            &["timeoutMs"],
            10,
            20,
            "timeoutMs",
        )
        .unwrap_err()
        .to_string();

        assert!(zero.contains("greater than zero"));
        assert!(excessive.contains("must not exceed"));
    }

    #[test]
    fn controlled_output_can_stream_stdout_to_an_open_file() {
        let mut command = Command::new("sh");
        command.args(["-c", "cat"]);
        let mut output = tempfile::tempfile().unwrap();

        let result = output_with_input_to_file_and_control(
            &mut command,
            "stream fixture",
            b"streamed output".to_vec(),
            output.try_clone().unwrap(),
            1024,
            None,
            Duration::from_secs(5),
        )
        .unwrap();
        output.rewind().unwrap();
        let mut body = String::new();
        output.read_to_string(&mut body).unwrap();

        assert!(result.status.success());
        assert!(result.stdout.is_empty());
        assert_eq!(body, "streamed output");
    }

    #[test]
    fn streamed_stdout_stops_at_the_file_limit() {
        let mut command = Command::new("sh");
        command.args(["-c", "cat"]);
        let output = tempfile::tempfile().unwrap();

        let error = output_with_input_to_file_and_control(
            &mut command,
            "bounded stream fixture",
            b"too much output".to_vec(),
            output.try_clone().unwrap(),
            4,
            None,
            Duration::from_secs(5),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("exceeded"), "{error}");
        assert!(output.metadata().unwrap().len() <= 4);
    }
}
