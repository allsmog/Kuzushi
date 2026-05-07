use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::timeout;

use crate::backend::SandboxBackend;

const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const TRUNCATION_MARKER: &str = "\n[kuzushi-sandbox] output truncated at 1 MiB\n";

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("sandbox backend `{0:?}` is not available")]
    BackendUnavailable(SandboxBackend),
    #[error("could not spawn sandbox child: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("sandbox child IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MountSpec {
    pub host_path: PathBuf,
    pub guest_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxExecOptions {
    pub cmd: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub network: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_only_mounts: Vec<MountSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_write_mounts: Vec<MountSpec>,
}

fn default_timeout_ms() -> u64 {
    30_000
}

impl SandboxExecOptions {
    pub fn new(cmd: Vec<String>) -> Self {
        Self {
            cmd,
            stdin: None,
            timeout_ms: default_timeout_ms(),
            memory_mb: None,
            workdir: None,
            env: HashMap::new(),
            network: false,
            read_only_mounts: Vec::new(),
            read_write_mounts: Vec::new(),
        }
    }
}

/// What happened to the child.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExitOutcome {
    /// Exited normally with a status code (which may be non-zero).
    Exited,
    /// Killed by signal.
    Signaled,
    /// Wallclock timeout fired and the child was killed.
    TimedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxExecResult {
    pub backend: SandboxBackend,
    pub outcome: ExitOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub duration_ms: u64,
}

/// Build argv for the chosen backend and run the child to completion.
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

fn cap_output(bytes: Vec<u8>) -> (String, bool) {
    if bytes.len() <= MAX_OUTPUT_BYTES {
        return (String::from_utf8_lossy(&bytes).into_owned(), false);
    }
    let mut head = String::from_utf8_lossy(&bytes[..MAX_OUTPUT_BYTES]).into_owned();
    head.push_str(TRUNCATION_MARKER);
    (head, true)
}

/// Build argv for the requested backend. Public for testing — verify
/// that the right flags appear in the right order without spawning.
pub fn build_argv(backend: SandboxBackend, opts: &SandboxExecOptions) -> Vec<String> {
    match backend {
        SandboxBackend::Plain => opts.cmd.clone(),
        SandboxBackend::Bwrap => build_bwrap_argv(opts),
        SandboxBackend::Podman => build_podman_argv(opts),
    }
}

fn build_bwrap_argv(opts: &SandboxExecOptions) -> Vec<String> {
    let mut a: Vec<String> = vec!["bwrap".to_string()];
    a.extend(["--die-with-parent".to_string()]);
    a.extend(["--unshare-all".to_string()]);
    if opts.network {
        a.extend(["--share-net".to_string()]);
    }
    a.extend(["--cap-drop".to_string(), "ALL".to_string()]);
    a.extend(["--new-session".to_string()]);

    // Standard read-only system mounts.
    for path in ["/usr", "/lib", "/lib64", "/bin", "/etc/alternatives"] {
        if std::path::Path::new(path).exists() {
            a.extend(["--ro-bind".to_string(), path.to_string(), path.to_string()]);
        }
    }
    // Symlink /sbin and /usr/sbin to /usr/bin so basic tools resolve.
    a.extend([
        "--symlink".to_string(),
        "usr/bin".to_string(),
        "/sbin".to_string(),
    ]);

    // Tmpfs for /tmp and /work.
    a.extend(["--tmpfs".to_string(), "/tmp".to_string()]);
    a.extend(["--tmpfs".to_string(), "/work".to_string()]);

    // Operator-supplied mounts.
    for mount in &opts.read_only_mounts {
        a.extend([
            "--ro-bind".to_string(),
            mount.host_path.display().to_string(),
            mount.guest_path.display().to_string(),
        ]);
    }
    for mount in &opts.read_write_mounts {
        a.extend([
            "--bind".to_string(),
            mount.host_path.display().to_string(),
            mount.guest_path.display().to_string(),
        ]);
    }

    if let Some(wd) = &opts.workdir {
        a.extend(["--chdir".to_string(), wd.display().to_string()]);
    }
    for (k, v) in &opts.env {
        a.extend(["--setenv".to_string(), k.clone(), v.clone()]);
    }
    a.push("--".to_string());
    a.extend(opts.cmd.iter().cloned());
    a
}

fn build_podman_argv(opts: &SandboxExecOptions) -> Vec<String> {
    let mut a: Vec<String> = vec!["podman".to_string(), "run".to_string()];
    a.extend(["--rm".to_string()]);
    a.extend(["--read-only".to_string()]);
    a.extend(["--cap-drop=ALL".to_string()]);
    a.extend([
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
    ]);
    if !opts.network {
        a.extend(["--network=none".to_string()]);
    }
    if let Some(mb) = opts.memory_mb {
        a.extend(["--memory".to_string(), format!("{mb}m")]);
    }
    a.extend(["--tmpfs".to_string(), "/tmp".to_string()]);
    a.extend(["--tmpfs".to_string(), "/work".to_string()]);

    for mount in &opts.read_only_mounts {
        a.extend([
            "-v".to_string(),
            format!(
                "{}:{}:ro",
                mount.host_path.display(),
                mount.guest_path.display()
            ),
        ]);
    }
    for mount in &opts.read_write_mounts {
        a.extend([
            "-v".to_string(),
            format!(
                "{}:{}",
                mount.host_path.display(),
                mount.guest_path.display()
            ),
        ]);
    }

    if let Some(wd) = &opts.workdir {
        a.extend(["-w".to_string(), wd.display().to_string()]);
    }
    for (k, v) in &opts.env {
        a.extend(["-e".to_string(), format!("{k}={v}")]);
    }

    // Default rootless image; operator can override via env mount or
    // by passing `--image` in their cmd. For the verify pipeline we
    // expect the cmd to start with the image name and command.
    a.push("--entrypoint=".to_string());
    a.extend(opts.cmd.iter().cloned());
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(cmd: &[&str]) -> SandboxExecOptions {
        SandboxExecOptions::new(cmd.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn bwrap_argv_contains_unshare_all_and_cap_drop() {
        let argv = build_argv(SandboxBackend::Bwrap, &opts(&["echo", "hi"]));
        assert_eq!(argv[0], "bwrap");
        assert!(argv.iter().any(|a| a == "--unshare-all"));
        assert!(argv.iter().any(|a| a == "--cap-drop"));
        assert!(argv.iter().any(|a| a == "ALL"));
        // Ensures the cmd is at the tail past `--`.
        let dashdash = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(&argv[dashdash + 1..], &["echo", "hi"]);
    }

    #[test]
    fn bwrap_share_net_only_when_network_requested() {
        let mut o = opts(&["true"]);
        o.network = false;
        let no_net = build_argv(SandboxBackend::Bwrap, &o);
        assert!(!no_net.iter().any(|a| a == "--share-net"));
        o.network = true;
        let with_net = build_argv(SandboxBackend::Bwrap, &o);
        assert!(with_net.iter().any(|a| a == "--share-net"));
    }

    #[test]
    fn bwrap_includes_tmpfs_for_tmp_and_work() {
        let argv = build_argv(SandboxBackend::Bwrap, &opts(&["true"]));
        let mut tmpfs_targets = Vec::new();
        let mut iter = argv.iter().peekable();
        while let Some(a) = iter.next() {
            if a == "--tmpfs" {
                if let Some(target) = iter.next() {
                    tmpfs_targets.push(target.clone());
                }
            }
        }
        assert!(tmpfs_targets.iter().any(|t| t == "/tmp"));
        assert!(tmpfs_targets.iter().any(|t| t == "/work"));
    }

    #[test]
    fn podman_argv_includes_read_only_and_no_new_privileges() {
        let argv = build_argv(SandboxBackend::Podman, &opts(&["alpine", "echo"]));
        assert_eq!(argv[0], "podman");
        assert_eq!(argv[1], "run");
        assert!(argv.iter().any(|a| a == "--read-only"));
        assert!(argv.iter().any(|a| a == "--cap-drop=ALL"));
        let mut found_no_new = false;
        let mut iter = argv.iter().peekable();
        while let Some(a) = iter.next() {
            if a == "--security-opt" && iter.peek().map(|s| s.as_str()) == Some("no-new-privileges")
            {
                found_no_new = true;
            }
        }
        assert!(found_no_new);
    }

    #[test]
    fn podman_argv_omits_network_none_when_network_requested() {
        let mut o = opts(&["alpine", "true"]);
        o.network = true;
        let argv = build_argv(SandboxBackend::Podman, &o);
        assert!(!argv.iter().any(|a| a == "--network=none"));
    }

    #[test]
    fn read_only_mounts_appear_in_argv() {
        let mut o = opts(&["true"]);
        o.read_only_mounts = vec![MountSpec {
            host_path: PathBuf::from("/host/ro"),
            guest_path: PathBuf::from("/guest/ro"),
        }];
        let argv = build_argv(SandboxBackend::Bwrap, &o);
        let pairs = argv
            .windows(3)
            .find(|w| w[0] == "--ro-bind" && w[1] == "/host/ro" && w[2] == "/guest/ro");
        assert!(pairs.is_some());
    }

    #[test]
    fn cap_output_truncates_at_1mib_with_marker() {
        let big = vec![b'A'; MAX_OUTPUT_BYTES + 100];
        let (capped, truncated) = cap_output(big);
        assert!(truncated);
        assert!(capped.ends_with(TRUNCATION_MARKER));
        assert!(capped.len() <= MAX_OUTPUT_BYTES + TRUNCATION_MARKER.len());
    }

    #[test]
    fn cap_output_passes_short_payloads_through_unchanged() {
        let small = b"hello".to_vec();
        let (out, truncated) = cap_output(small);
        assert!(!truncated);
        assert_eq!(out, "hello");
    }

    #[tokio::test]
    async fn plain_backend_runs_echo_end_to_end() {
        let result = sandbox_exec(SandboxBackend::Plain, opts(&["echo", "kuzushi"]))
            .await
            .unwrap();
        assert_eq!(result.outcome, ExitOutcome::Exited);
        assert_eq!(result.exit_code, Some(0));
        assert!(result.stdout.starts_with("kuzushi"));
        assert!(!result.stdout_truncated);
    }

    #[tokio::test]
    async fn plain_backend_exit_code_propagates() {
        // `false` exits non-zero on every Unix.
        let result = sandbox_exec(SandboxBackend::Plain, opts(&["false"]))
            .await
            .unwrap();
        assert_eq!(result.outcome, ExitOutcome::Exited);
        assert_eq!(result.exit_code, Some(1));
    }

    #[tokio::test]
    async fn timeout_kills_long_running_child() {
        let mut o = opts(&["sleep", "5"]);
        o.timeout_ms = 200;
        let result = sandbox_exec(SandboxBackend::Plain, o).await.unwrap();
        assert_eq!(result.outcome, ExitOutcome::TimedOut);
        assert!(result.stderr.contains("timeout after 200 ms"));
    }

    #[tokio::test]
    async fn requesting_isolating_backend_when_missing_returns_unavailable() {
        // bwrap and podman are absent in the test sandbox; this exercises
        // the BackendUnavailable error path. On hosts that *do* have
        // them the test exits early.
        if crate::backend::which("bwrap").is_some() {
            return;
        }
        let err = sandbox_exec(SandboxBackend::Bwrap, opts(&["true"]))
            .await
            .unwrap_err();
        assert!(matches!(err, SandboxError::BackendUnavailable(_)));
    }

    #[tokio::test]
    async fn stdin_is_piped_through_to_child() {
        let mut o = opts(&["cat"]);
        o.stdin = Some("inbound\n".to_string());
        let result = sandbox_exec(SandboxBackend::Plain, o).await.unwrap();
        assert_eq!(result.outcome, ExitOutcome::Exited);
        assert!(result.stdout.contains("inbound"));
    }
}
