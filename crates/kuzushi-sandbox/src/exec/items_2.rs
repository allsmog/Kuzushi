use super::prelude::*;
use super::*;

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

    // For Plain backend, plumb env + workdir directly. For isolating
    // backends, the wrapper already handles them via flags.
    if backend == SandboxBackend::Plain {
        if let Some(wd) = &opts.workdir {
            command.current_dir(wd);
        }
        // Only clear the env when the caller explicitly supplied
        // overrides. Clearing unconditionally strips PATH and breaks
        // compiler/linker invocations (e.g. clang failing to find `ld`).
        if !opts.env.is_empty() {
            command.env_clear();
            for (k, v) in &opts.env {
                command.env(k, v);
            }
        }
    }

    let started = Instant::now();
    let mut child = command.spawn().map_err(SandboxError::Spawn)?;

    if let (Some(stdin), Some(input)) = (child.stdin.take(), opts.stdin.as_ref()) {
        let bytes = input.as_bytes().to_vec();
        let mut stdin = stdin;
        tokio::spawn(async move {
            let _ = stdin.write_all(&bytes).await;
            let _ = stdin.shutdown().await;
        });
    }

    let wait_dur = Duration::from_millis(opts.timeout_ms);
    let result = timeout(wait_dur, child.wait_with_output()).await;

    let duration_ms = started.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(output)) => {
            let (stdout, stdout_truncated) = cap_output(output.stdout);
            let (stderr, stderr_truncated) = cap_output(output.stderr);
            let exit_code = output.status.code();
            #[cfg(unix)]
            let signal = {
                use std::os::unix::process::ExitStatusExt;
                output.status.signal()
            };
            #[cfg(not(unix))]
            let signal: Option<i32> = None;
            let outcome = if signal.is_some() {
                ExitOutcome::Signaled
            } else {
                ExitOutcome::Exited
            };
            Ok(SandboxExecResult {
                backend,
                outcome,
                exit_code,
                signal,
                stdout,
                stderr,
                stdout_truncated,
                stderr_truncated,
                duration_ms,
            })
        }
        Ok(Err(io_err)) => Err(SandboxError::Io(io_err)),
        Err(_elapsed) => {
            // Best-effort kill; child handle was already moved into
            // `wait_with_output`, so we can't kill via the handle. The
            // OS will reap it once we drop our pipe ends. Report the
            // timeout outcome explicitly.
            Ok(SandboxExecResult {
                backend,
                outcome: ExitOutcome::TimedOut,
                exit_code: None,
                signal: None,
                stdout: String::new(),
                stderr: format!("[kuzushi-sandbox] timeout after {} ms", opts.timeout_ms),
                stdout_truncated: false,
                stderr_truncated: false,
                duration_ms,
            })
        }
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

pub fn build_argv(backend: SandboxBackend, opts: &SandboxExecOptions) -> Vec<String> {
    match backend {
        SandboxBackend::Plain => opts.cmd.clone(),
        SandboxBackend::Bwrap => build_bwrap_argv(opts),
        SandboxBackend::Podman => build_podman_argv(opts),
    }
}
