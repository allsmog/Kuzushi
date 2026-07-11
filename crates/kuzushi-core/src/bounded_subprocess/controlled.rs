use super::{DEFAULT_STDERR_LIMIT, DEFAULT_STDOUT_LIMIT};
use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(25);

pub(super) fn controlled_output(
    command: &mut Command,
    label: &str,
    input: Option<Vec<u8>>,
    cancellation: Option<&crate::scan::ScanCancellation>,
    timeout: Duration,
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
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    crate::scan::configure_scanner_process_group(command);
    let mut child = command
        .spawn()
        .with_context(|| format!("Could not start {label}"))?;
    let process_group_id = crate::scan::child_process_group_id(&child);
    let io = match ControlledIo::capture(&mut child, input, label) {
        Ok(io) => io,
        Err(error) => return Err(terminate_unregistered_child(child, process_group_id, error)),
    };
    let local_cancellation = crate::scan::ScanCancellation::default();
    let cancellation = cancellation.unwrap_or(&local_cancellation);
    let child = match cancellation.register_child(child, process_group_id) {
        Ok(child) => child,
        Err(error) => return Err(io.join_cleanup(error)),
    };
    wait_for_controlled_output(child, io, cancellation, deadline, timeout, label)
}

fn terminate_unregistered_child(
    mut child: Child,
    process_group_id: Option<u32>,
    error: anyhow::Error,
) -> anyhow::Error {
    #[cfg(unix)]
    if let Some(group) = process_group_id {
        unsafe {
            libc::killpg(group as libc::pid_t, libc::SIGKILL);
        }
    } else {
        let _ = child.kill();
    }
    #[cfg(not(unix))]
    {
        let _ = process_group_id;
        let _ = child.kill();
    }
    match child.wait() {
        Ok(_) => error,
        Err(cleanup) => anyhow::Error::new(cleanup).context(error),
    }
}

type ControlledReader = JoinHandle<Result<Vec<u8>>>;
type ControlledWriter = JoinHandle<Result<()>>;
type ControlledFailure = Arc<Mutex<Option<String>>>;

struct ControlledIo {
    stdout: ControlledReader,
    stderr: ControlledReader,
    stdin: Option<ControlledWriter>,
    failure: ControlledFailure,
}

impl ControlledIo {
    fn capture(child: &mut Child, input: Option<Vec<u8>>, label: &str) -> Result<Self> {
        let stdout = child
            .stdout
            .take()
            .with_context(|| format!("Could not capture {label} stdout"))?;
        let stderr = child
            .stderr
            .take()
            .with_context(|| format!("Could not capture {label} stderr"))?;
        let stdin = input
            .map(|input| controlled_stdin(child, label).map(|stdin| (stdin, input)))
            .transpose()?;
        let failure = Arc::new(Mutex::new(None));
        let stdout =
            spawn_controlled_reader(stdout, DEFAULT_STDOUT_LIMIT, "stdout", Arc::clone(&failure));
        let stderr =
            spawn_controlled_reader(stderr, DEFAULT_STDERR_LIMIT, "stderr", Arc::clone(&failure));
        let stdin =
            stdin.map(|(stdin, input)| spawn_controlled_writer(stdin, input, Arc::clone(&failure)));
        Ok(Self {
            stdout,
            stderr,
            stdin,
            failure,
        })
    }

    fn failure(&self) -> Result<Option<String>> {
        self.failure
            .lock()
            .map(|slot| slot.clone())
            .map_err(|_| anyhow::anyhow!("subprocess output failure state was poisoned"))
    }

    fn join(self, status: ExitStatus, label: &str) -> Result<Output> {
        let stdout = join_controlled_reader(self.stdout, label, "stdout");
        let stderr = join_controlled_reader(self.stderr, label, "stderr");
        let stdin = if let Some(stdin) = self.stdin {
            stdin
                .join()
                .map_err(|_| anyhow::anyhow!("{label} stdin writer panicked"))?
        } else {
            Ok(())
        };
        let stdout = stdout?;
        let stderr = stderr?;
        stdin?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    fn join_cleanup(self, error: anyhow::Error) -> anyhow::Error {
        let stdout = join_controlled_reader(self.stdout, "subprocess", "stdout");
        let stderr = join_controlled_reader(self.stderr, "subprocess", "stderr");
        let stdin = self.stdin.map(|writer| {
            writer
                .join()
                .map_err(|_| anyhow::anyhow!("subprocess stdin writer panicked"))?
        });
        [
            stdout.map(|_| ()),
            stderr.map(|_| ()),
            stdin.unwrap_or(Ok(())),
        ]
        .into_iter()
        .filter_map(Result::err)
        .fold(error, |primary, cleanup| cleanup.context(primary))
    }
}

fn controlled_stdin(child: &mut Child, label: &str) -> Result<ChildStdin> {
    child
        .stdin
        .take()
        .with_context(|| format!("Could not capture {label} stdin"))
}

fn spawn_controlled_reader<R: Read + Send + 'static>(
    reader: R,
    limit: usize,
    stream: &'static str,
    failure: ControlledFailure,
) -> ControlledReader {
    thread::spawn(move || match read_controlled_pipe(reader, limit, stream) {
        Ok(bytes) => Ok(bytes),
        Err(error) => {
            record_controlled_failure(&failure, &error);
            Err(error)
        }
    })
}

fn read_controlled_pipe(mut reader: impl Read, limit: usize, stream: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    reader
        .by_ref()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= limit,
        "subprocess {stream} exceeded the {limit}-byte capture limit"
    );
    Ok(bytes)
}

fn spawn_controlled_writer(
    mut stdin: ChildStdin,
    input: Vec<u8>,
    failure: ControlledFailure,
) -> ControlledWriter {
    thread::spawn(move || {
        let result = stdin.write_all(&input).map_err(anyhow::Error::from);
        drop(stdin);
        if let Err(error) = &result {
            record_controlled_failure(&failure, error);
        }
        result
    })
}

fn record_controlled_failure(failure: &ControlledFailure, error: &anyhow::Error) {
    if let Ok(mut slot) = failure.lock() {
        if slot.is_none() {
            *slot = Some(error.to_string());
        }
    }
}

fn join_controlled_reader(reader: ControlledReader, label: &str, stream: &str) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("{label} {stream} reader panicked"))?
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
            ControlledWaitStep::Exited(status) => return io.join(status, label),
            ControlledWaitStep::Failed(error) => {
                return Err(terminate_controlled_child(&child, io, error));
            }
        }
    }
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
            timeout.as_millis()
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
