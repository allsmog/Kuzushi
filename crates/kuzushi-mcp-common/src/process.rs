use anyhow::{Context, Result};
use std::process::ExitStatus;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

mod parent_death_process_group;
pub use parent_death_process_group::ParentDeathProcessGroup;

#[cfg(windows)]
mod windows_job;

pub const DEFAULT_PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_STDOUT_LIMIT: usize = 1024 * 1024;
pub const DEFAULT_STDERR_LIMIT: usize = 256 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct ProcessLimits {
    pub timeout: Duration,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_PROCESS_TIMEOUT,
            stdout_bytes: DEFAULT_STDOUT_LIMIT,
            stderr_bytes: DEFAULT_STDERR_LIMIT,
        }
    }
}

#[derive(Debug)]
pub struct BoundedProcessOutput {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

/// Run a child with a deadline, bounded concurrent pipe drains, and group
/// cleanup. Dropping the returned future also kills the child process group.
pub async fn run_bounded_process(
    command: &mut Command,
    label: &str,
    limits: ProcessLimits,
) -> Result<BoundedProcessOutput> {
    validate_limits(label, limits)?;
    prepare_command(command);
    let mut child = ProcessGuard::spawn(command, label)?;
    let mut captures = Captures::start(child.child_mut(), label, limits)?;
    let deadline = Instant::now() + limits.timeout;
    if let Err(error) = captures.wait_until_complete(deadline, label).await {
        return Err(child.stop(captures, error).await);
    }
    let status = match wait_for_exit(&mut child, deadline, limits.timeout, label).await {
        Ok(status) => status,
        Err(error) => return Err(child.stop(captures, error).await),
    };
    let (stdout, stderr) = captures.finish(label).await?;
    child.disarm();
    Ok(BoundedProcessOutput {
        status,
        stdout: sanitize_terminal_text(&String::from_utf8_lossy(&stdout)),
        stderr: sanitize_terminal_text(&String::from_utf8_lossy(&stderr)),
    })
}

/// Run a child to completion under parent-death supervision without imposing
/// an additional deadline or output limit.
pub async fn run_guarded_output(
    command: &mut Command,
    label: &str,
) -> Result<std::process::Output> {
    command.kill_on_drop(true);
    let mut process_group = ParentDeathProcessGroup::configure(command)?;
    let child = command
        .spawn()
        .with_context(|| format!("could not start {label}"))?;
    process_group.attach_child(&child)?;
    child
        .wait_with_output()
        .await
        .with_context(|| format!("could not wait for {label}"))
}

fn validate_limits(label: &str, limits: ProcessLimits) -> Result<()> {
    anyhow::ensure!(
        !limits.timeout.is_zero(),
        "{label} timeout must be positive"
    );
    anyhow::ensure!(
        limits.stdout_bytes > 0,
        "{label} stdout limit must be positive"
    );
    anyhow::ensure!(
        limits.stderr_bytes > 0,
        "{label} stderr limit must be positive"
    );
    Ok(())
}

fn prepare_command(command: &mut Command) {
    command.kill_on_drop(true);
}

struct ProcessGuard {
    child: Option<Child>,
    process_group: ParentDeathProcessGroup,
}

impl ProcessGuard {
    fn spawn(command: &mut Command, label: &str) -> Result<Self> {
        let mut process_group = ParentDeathProcessGroup::configure(command)?;
        let child = command
            .spawn()
            .with_context(|| format!("could not start {label}"))?;
        process_group.attach_child(&child)?;
        Ok(Self {
            child: Some(child),
            process_group,
        })
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("process guard is armed")
    }

    async fn stop(mut self, captures: Captures, error: anyhow::Error) -> anyhow::Error {
        self.kill_group();
        let cleanup = self.child_mut().wait().await;
        let capture_cleanup = captures.finish("subprocess cleanup").await;
        self.disarm();
        attach_cleanup(error, cleanup, capture_cleanup)
    }

    fn kill_group(&mut self) {
        self.process_group.kill();
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }

    fn disarm(&mut self) {
        self.child = None;
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.child.is_some() {
            self.kill_group();
        }
    }
}

fn attach_cleanup(
    error: anyhow::Error,
    wait: std::io::Result<ExitStatus>,
    capture: Result<(Vec<u8>, Vec<u8>)>,
) -> anyhow::Error {
    let error = match wait {
        Ok(_) => error,
        Err(cleanup) => error.context(cleanup),
    };
    match capture {
        Ok(_) => error,
        Err(cleanup) => cleanup.context(error),
    }
}

enum CaptureEvent {
    Complete,
    Failed(String),
}

struct Captures {
    stdout: JoinHandle<Result<Vec<u8>>>,
    stderr: JoinHandle<Result<Vec<u8>>>,
    events: mpsc::UnboundedReceiver<CaptureEvent>,
}

impl Captures {
    fn start(child: &mut Child, label: &str, limits: ProcessLimits) -> Result<Self> {
        let stdout = child
            .stdout
            .take()
            .with_context(|| format!("{label} stdout was not piped"))?;
        let stderr = child
            .stderr
            .take()
            .with_context(|| format!("{label} stderr was not piped"))?;
        let (sender, events) = mpsc::unbounded_channel();
        Ok(Self {
            stdout: spawn_capture(stdout, limits.stdout_bytes, "stdout", sender.clone()),
            stderr: spawn_capture(stderr, limits.stderr_bytes, "stderr", sender),
            events,
        })
    }

    async fn finish(self, label: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let stdout = join_capture(self.stdout, label, "stdout").await?;
        let stderr = join_capture(self.stderr, label, "stderr").await?;
        Ok((stdout, stderr))
    }

    async fn wait_until_complete(&mut self, deadline: Instant, label: &str) -> Result<()> {
        let mut completed = 0_u8;
        while completed < 2 {
            let event = tokio::time::timeout_at(deadline, self.events.recv())
                .await
                .map_err(|_| deadline_error(label, deadline))?;
            match event {
                Some(CaptureEvent::Complete) => completed += 1,
                Some(CaptureEvent::Failed(message)) => anyhow::bail!("{label}: {message}"),
                None => anyhow::bail!("{label} output capture ended before both streams closed"),
            }
        }
        Ok(())
    }
}

fn spawn_capture<R>(
    reader: R,
    limit: usize,
    stream: &'static str,
    sender: mpsc::UnboundedSender<CaptureEvent>,
) -> JoinHandle<Result<Vec<u8>>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let result = read_bounded(reader, limit, stream).await;
        let event = match &result {
            Ok(_) => CaptureEvent::Complete,
            Err(error) => CaptureEvent::Failed(error.to_string()),
        };
        let _ = sender.send(event);
        result
    })
}

async fn read_bounded(
    reader: impl AsyncRead + Unpin,
    limit: usize,
    stream: &str,
) -> Result<Vec<u8>> {
    let read_limit = limit
        .checked_add(1)
        .context("process output limit overflow")?;
    let mut bytes = Vec::with_capacity(read_limit.min(64 * 1024));
    reader
        .take(read_limit as u64)
        .read_to_end(&mut bytes)
        .await?;
    anyhow::ensure!(
        bytes.len() <= limit,
        "subprocess {stream} exceeded the {limit}-byte capture limit"
    );
    Ok(bytes)
}

async fn join_capture(
    capture: JoinHandle<Result<Vec<u8>>>,
    label: &str,
    stream: &str,
) -> Result<Vec<u8>> {
    capture
        .await
        .with_context(|| format!("{label} {stream} capture task failed"))?
}

async fn wait_for_exit(
    child: &mut ProcessGuard,
    deadline: Instant,
    timeout: Duration,
    label: &str,
) -> Result<ExitStatus> {
    tokio::time::timeout_at(deadline, child.child_mut().wait())
        .await
        .map_err(|_| timeout_error(label, timeout))?
        .context("could not wait for subprocess")
}

fn deadline_error(label: &str, deadline: Instant) -> anyhow::Error {
    let elapsed = Instant::now().saturating_duration_since(deadline);
    anyhow::anyhow!(
        "{label} exceeded its output-drain deadline by {} ms and was killed",
        elapsed.as_millis()
    )
}

fn timeout_error(label: &str, timeout: Duration) -> anyhow::Error {
    anyhow::anyhow!(
        "{label} exceeded its {} ms deadline and was killed",
        timeout.as_millis()
    )
}

/// Escape terminal control characters while preserving ordinary text, tabs,
/// and line feeds.
pub fn sanitize_terminal_text(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for character in input.chars() {
        if character == '\n' || character == '\t' || !character.is_control() {
            output.push(character);
        } else {
            use std::fmt::Write as _;
            let _ = write!(output, "\\u{{{:x}}}", character as u32);
        }
    }
    output
}

#[cfg(test)]
mod tests;
