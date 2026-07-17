use crate::scan::ScanCancellation;
use anyhow::{Context, Result};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug)]
pub(crate) struct ProcessOutput {
    pub(crate) stdout: Vec<u8>,
}

const RECON_STDOUT_LIMIT: usize = 64 * 1024 * 1024;
const RECON_STDERR_LIMIT: usize = 1024 * 1024;

#[derive(Clone, Copy)]
struct CaptureLimits {
    stdout: usize,
    stderr: usize,
}

const DEFAULT_CAPTURE_LIMITS: CaptureLimits = CaptureLimits {
    stdout: RECON_STDOUT_LIMIT,
    stderr: RECON_STDERR_LIMIT,
};

pub(crate) fn run_subprocess(
    tool_name: &str,
    binary: &str,
    args: &[String],
    cwd: Option<&Path>,
    cancel: &ScanCancellation,
    install_hint: &str,
) -> Result<ProcessOutput> {
    run_subprocess_with_limits(
        tool_name,
        binary,
        args,
        cwd,
        cancel,
        install_hint,
        DEFAULT_CAPTURE_LIMITS,
    )
}

fn run_subprocess_with_limits(
    tool_name: &str,
    binary: &str,
    args: &[String],
    cwd: Option<&Path>,
    cancel: &ScanCancellation,
    install_hint: &str,
    limits: CaptureLimits,
) -> Result<ProcessOutput> {
    if cancel.is_cancelled() {
        anyhow::bail!("{tool_name} cancelled");
    }
    let mut command = recon_command(binary, args, cwd);
    let mut child = spawn_subprocess(tool_name, binary, &mut command, install_hint)?;
    let process_group_id = child_process_group_id(&child);
    let (readers, pipe_failure) =
        capture_recon_pipes(tool_name, &mut child, limits.stdout, limits.stderr)?;
    let child = cancel.register_child(child, process_group_id)?;
    let status = wait_for_process(tool_name, &child, cancel, &pipe_failure)?;
    let (stdout, stderr) = join_recon_pipes(tool_name, readers)?;
    validate_subprocess_exit(tool_name, binary, status, stdout, stderr)
}

fn recon_command(binary: &str, args: &[String], cwd: Option<&Path>) -> Command {
    let mut command = Command::new(binary);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    configure_recon_process_group(&mut command);
    command
}

#[cfg(unix)]
fn configure_recon_process_group(command: &mut Command) {
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_recon_process_group(_command: &mut Command) {}

type ReconPipeReader = thread::JoinHandle<Result<Vec<u8>>>;

struct ReconPipeReaders {
    stdout: ReconPipeReader,
    stderr: ReconPipeReader,
}

fn capture_recon_pipes(
    tool_name: &str,
    child: &mut Child,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<(ReconPipeReaders, PipeFailure)> {
    let stdout = child
        .stdout
        .take()
        .with_context(|| format!("Could not capture {tool_name} stdout"))?;
    let stderr = child
        .stderr
        .take()
        .with_context(|| format!("Could not capture {tool_name} stderr"))?;
    let pipe_failure = Arc::new(Mutex::new(None));
    let stdout_reader =
        spawn_pipe_reader(stdout, stdout_limit, "stdout", Arc::clone(&pipe_failure));
    let stderr_reader =
        spawn_pipe_reader(stderr, stderr_limit, "stderr", Arc::clone(&pipe_failure));
    Ok((
        ReconPipeReaders {
            stdout: stdout_reader,
            stderr: stderr_reader,
        },
        pipe_failure,
    ))
}

fn join_recon_pipes(tool_name: &str, readers: ReconPipeReaders) -> Result<(Vec<u8>, Vec<u8>)> {
    let stdout = readers
        .stdout
        .join()
        .map_err(|_| anyhow::anyhow!("{tool_name} stdout reader panicked"))??;
    let stderr = readers
        .stderr
        .join()
        .map_err(|_| anyhow::anyhow!("{tool_name} stderr reader panicked"))??;
    Ok((stdout, stderr))
}

fn spawn_subprocess(
    tool_name: &str,
    binary: &str,
    command: &mut Command,
    install_hint: &str,
) -> Result<Child> {
    command.spawn().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "{tool_name}: could not find subprocess binary {:?}. {install_hint}",
                binary
            )
        } else {
            anyhow::anyhow!("{tool_name}: could not start {:?}: {error}", binary)
        }
    })
}

fn validate_subprocess_exit(
    tool_name: &str,
    binary: &str,
    status: Option<ExitStatus>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
) -> Result<ProcessOutput> {
    let Some(status) = status else {
        anyhow::bail!("{tool_name} cancelled");
    };
    if !status.success() {
        let details = String::from_utf8_lossy(if stderr.is_empty() { &stdout } else { &stderr });
        anyhow::bail!(
            "{tool_name}: subprocess {:?} failed with status {}: {}",
            binary,
            status,
            details.trim()
        );
    }
    Ok(ProcessOutput { stdout })
}

fn wait_for_process(
    tool_name: &str,
    child: &crate::scan::RegisteredChild,
    cancel: &ScanCancellation,
    pipe_failure: &PipeFailure,
) -> Result<Option<ExitStatus>> {
    loop {
        if cancel.is_cancelled() {
            child.kill_and_wait()?;
            return Ok(None);
        }
        fail_process_on_pipe_overflow(child, pipe_failure)?;
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("{tool_name}: could not poll subprocess"))?
        {
            return Ok(Some(status));
        }
        thread::sleep(Duration::from_millis(75));
    }
}

type PipeFailure = Arc<Mutex<Option<String>>>;

fn fail_process_on_pipe_overflow(
    child: &crate::scan::RegisteredChild,
    failure: &PipeFailure,
) -> Result<()> {
    let failure = failure
        .lock()
        .map_err(|_| anyhow::anyhow!("recon subprocess pipe failure state was poisoned"))?
        .clone();
    if let Some(failure) = failure {
        child.kill_and_wait()?;
        anyhow::bail!(failure);
    }
    Ok(())
}

fn child_process_group_id(child: &Child) -> Option<u32> {
    #[cfg(unix)]
    {
        Some(child.id())
    }

    #[cfg(not(unix))]
    {
        let _ = child;
        None
    }
}

fn spawn_pipe_reader<R: Read + Send + 'static>(
    mut pipe: R,
    limit: usize,
    stream: &'static str,
    failure: PipeFailure,
) -> thread::JoinHandle<Result<Vec<u8>>> {
    thread::spawn(move || match read_pipe_bounded(&mut pipe, limit, stream) {
        Ok(bytes) => Ok(bytes),
        Err(error) => {
            if let Ok(mut slot) = failure.lock() {
                *slot = Some(error.to_string());
            }
            Err(error)
        }
    })
}

fn read_pipe_bounded(reader: &mut impl Read, limit: usize, stream: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("Could not read recon subprocess {stream}"))?;
    anyhow::ensure!(
        bytes.len() <= limit,
        "recon subprocess {stream} exceeded the {limit}-byte capture limit"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_pipe_rejects_output_above_limit() {
        let mut output = std::io::Cursor::new(vec![b'x'; 17]);
        let error = read_pipe_bounded(&mut output, 16, "stdout")
            .unwrap_err()
            .to_string();
        assert!(error.contains("capture limit"), "{error}");
    }

    #[test]
    fn output_overflow_kills_the_registered_process_tree() {
        let cancel = ScanCancellation::default();
        let args = vec![
            "-e".to_string(),
            "for (;;) require('node:fs').writeSync(1, '1234567890')".to_string(),
        ];

        let error = run_subprocess_with_limits(
            "recon:test",
            "node",
            &args,
            None,
            &cancel,
            "fixture",
            CaptureLimits {
                stdout: 16,
                stderr: 16,
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("capture limit"), "{error}");
    }
}
