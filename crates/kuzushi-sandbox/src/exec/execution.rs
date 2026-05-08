use crate::backend::SandboxBackend;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::timeout;

use super::argv::build_argv;
use super::output::sandbox_result_from_child_output;
use super::{SandboxError, SandboxExecOptions, SandboxExecResult};

pub async fn sandbox_exec(
    backend: SandboxBackend,
    opts: SandboxExecOptions,
) -> Result<SandboxExecResult, SandboxError> {
    if backend.is_isolating() && crate::backend::which(backend.binary_name()).is_none() {
        return Err(SandboxError::BackendUnavailable(backend));
    }

    let argv = build_argv(backend, &opts);
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    configure_plain_backend_process(backend, &opts, &mut command);

    let started = Instant::now();
    let mut child = command.spawn().map_err(SandboxError::Spawn)?;
    pipe_stdin_to_child(opts.stdin.as_deref(), child.stdin.take());

    let result = timeout(
        Duration::from_millis(opts.timeout_ms),
        child.wait_with_output(),
    )
    .await;
    let duration_ms = started.elapsed().as_millis() as u64;

    sandbox_result_from_child_output(backend, opts.timeout_ms, duration_ms, result)
}

fn configure_plain_backend_process(
    backend: SandboxBackend,
    opts: &SandboxExecOptions,
    command: &mut Command,
) {
    if backend != SandboxBackend::Plain {
        return;
    }
    if let Some(wd) = &opts.workdir {
        command.current_dir(wd);
    }
    if opts.env.is_empty() {
        return;
    }
    command.env_clear();
    for (k, v) in &opts.env {
        command.env(k, v);
    }
}

fn pipe_stdin_to_child(stdin: Option<&str>, child_stdin: Option<tokio::process::ChildStdin>) {
    let (Some(input), Some(mut stdin)) = (stdin, child_stdin) else {
        return;
    };
    let bytes = input.as_bytes().to_vec();
    tokio::spawn(async move {
        let _ = stdin.write_all(&bytes).await;
        let _ = stdin.shutdown().await;
    });
}
