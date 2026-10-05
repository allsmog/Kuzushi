use crate::backend::SandboxBackend;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};
use tokio::time::timeout;

use super::argv::build_argv;
use super::output::completed_sandbox_result;
use super::streams::{deliver_stdin, read_bounded};
use super::supervision::ProcessGroup;
use super::{ExitOutcome, SandboxError, SandboxExecOptions, SandboxExecResult, MAX_OUTPUT_BYTES};

pub async fn sandbox_exec(
    backend: SandboxBackend,
    opts: SandboxExecOptions,
) -> Result<SandboxExecResult, SandboxError> {
    validate_options(backend, &opts)?;
    let mut command = sandbox_command(backend, &opts)?;
    let mut group = ProcessGroup::configure(&mut command)?;
    let started = Instant::now();
    let mut child = command.spawn().map_err(SandboxError::Spawn)?;
    group.attach(&child)?;
    let result = supervise(&mut child, &group, backend, &opts, started).await;
    group.terminate();
    // Also reap after an IO/input error. No detached IO tasks survive this call.
    reap(&mut child).await?;
    result
}

fn validate_options(
    backend: SandboxBackend,
    opts: &SandboxExecOptions,
) -> Result<(), SandboxError> {
    if opts.cmd.first().is_none_or(|s| s.is_empty()) {
        return Err(SandboxError::InvalidOptions("empty executable".into()));
    }
    if opts
        .stdin
        .as_ref()
        .is_some_and(|s| s.len() > MAX_OUTPUT_BYTES)
    {
        return Err(SandboxError::InvalidOptions("stdin exceeds 1 MiB".into()));
    }
    if backend.is_isolating() && crate::backend::which(backend.binary_name()).is_none() {
        return Err(SandboxError::BackendUnavailable(backend));
    }
    Ok(())
}

fn sandbox_command(
    backend: SandboxBackend,
    opts: &SandboxExecOptions,
) -> Result<Command, SandboxError> {
    let argv = build_argv(backend, opts);
    let executable = command_executable(backend, &argv[0], opts)?;
    let mut command = Command::new(executable);
    command.args(&argv[1..]);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("LANG", "C.UTF-8");
    if backend == SandboxBackend::Plain {
        command.envs(&opts.env);
        if let Some(workdir) = &opts.workdir {
            command.current_dir(workdir);
        }
    }
    command.kill_on_drop(true);
    Ok(command)
}

fn command_executable(
    backend: SandboxBackend,
    program: &str,
    opts: &SandboxExecOptions,
) -> Result<PathBuf, SandboxError> {
    if backend == SandboxBackend::Plain && opts.env.contains_key("PATH") {
        return Ok(PathBuf::from(program));
    }
    let host_workdir = (backend == SandboxBackend::Plain)
        .then_some(opts.workdir.as_deref())
        .flatten();
    host_executable(program, host_workdir)
}

fn host_executable(program: &str, workdir: Option<&Path>) -> Result<PathBuf, SandboxError> {
    let requested = Path::new(program);
    let candidate = if requested.components().count() > 1 {
        workdir.map_or_else(|| requested.to_path_buf(), |dir| dir.join(requested))
    } else {
        crate::backend::which(program).ok_or_else(|| {
            SandboxError::Spawn(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("executable is not on PATH: {program}"),
            ))
        })?
    };
    // Keep aliases such as the cargo -> rustup proxy: argv[0] selects its role.
    std::path::absolute(candidate).map_err(SandboxError::Spawn)
}

async fn supervise(
    child: &mut Child,
    group: &ProcessGroup,
    backend: SandboxBackend,
    opts: &SandboxExecOptions,
    started: Instant,
) -> Result<SandboxExecResult, SandboxError> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let pipes = (
        child.stdin.take(),
        child.stdout.take().unwrap(),
        child.stderr.take().unwrap(),
    );
    let work = async {
        tokio::try_join!(
            child.wait(),
            read_bounded(pipes.1, &mut stdout),
            read_bounded(pipes.2, &mut stderr),
            deliver_stdin(opts.stdin.as_deref(), pipes.0)
        )
    };
    let completion = timeout(Duration::from_millis(opts.timeout_ms), work).await;
    let outcome = execution_outcome(&completion, &stdout, &stderr)?;
    group.terminate();
    let status = reap(child).await?;
    let output = Output {
        status,
        stdout,
        stderr,
    };
    Ok(terminal_result(
        backend,
        started,
        output,
        outcome,
        opts.timeout_ms,
    ))
}

fn terminal_result(
    backend: SandboxBackend,
    started: Instant,
    output: Output,
    outcome: Option<ExitOutcome>,
    timeout_ms: u64,
) -> SandboxExecResult {
    let mut result =
        completed_sandbox_result(backend, started.elapsed().as_millis() as u64, output);
    if let Some(outcome) = outcome {
        result.outcome = outcome;
    }
    if result.outcome == ExitOutcome::TimedOut {
        result.stderr.push_str(&format!(
            "\n[kuzushi-sandbox] timeout after {timeout_ms} ms"
        ));
    }
    result
}

async fn reap(child: &mut Child) -> Result<std::process::ExitStatus, SandboxError> {
    child.start_kill()?;
    timeout(Duration::from_secs(5), child.wait())
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "sandbox cleanup exceeded five seconds",
            )
        })?
        .map_err(SandboxError::Io)
}

type Completion =
    Result<std::io::Result<(std::process::ExitStatus, (), (), ())>, tokio::time::error::Elapsed>;

fn execution_outcome(
    completion: &Completion,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<Option<ExitOutcome>, SandboxError> {
    if stdout.len() > MAX_OUTPUT_BYTES || stderr.len() > MAX_OUTPUT_BYTES {
        return Ok(Some(ExitOutcome::OutputLimitExceeded));
    }
    match completion {
        Err(_) => Ok(Some(ExitOutcome::TimedOut)),
        Ok(Ok(_)) => Ok(None),
        Ok(Err(error)) => Err(SandboxError::Io(std::io::Error::new(
            error.kind(),
            error.to_string(),
        ))),
    }
}
