use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::bridge_payloads::{
    BridgeRequest, BridgeResponse, NextStepBridgeRequest, NextStepBridgeResponse,
};

const LEGACY_ERROR_PATTERNS: &[(&[&str], &str)] = &[
    (&["timed out", "timeout"], "timeout"),
    (&["cancelled", "canceled"], "cancelled"),
    (&["fetch failed", "econnreset"], "transport"),
];

pub(crate) fn run_next_step_bridge(
    command: &[String],
    request: &NextStepBridgeRequest,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
) -> Result<NextStepBridgeResponse> {
    run_json_bridge(command, request, "next-step bridge", &[], cancellation)
}

pub(crate) fn run_next_step_preflight_bridge(
    command: &[String],
    request: &NextStepBridgeRequest,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
) -> Result<NextStepBridgeResponse> {
    run_json_bridge(
        command,
        request,
        "next-step preflight bridge",
        &[],
        cancellation,
    )
}

pub(crate) fn run_bridge(
    command: &[String],
    request: &BridgeRequest,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
) -> Result<BridgeResponse> {
    let extra_env = mcp_artifact_env_for_attachments(&request.tool_policy.mcps_attached);
    run_json_bridge(
        command,
        request,
        "LangGraph bridge",
        &extra_env,
        cancellation,
    )
}

/// Build `KUZUSHI_MCP_<NAME>_ARTIFACT=<path>` env pairs from the
/// per-call attachment plan. Constants (treesitter) skip — they don't
/// need an artifact env. Server names with `-` are uppercased and
/// translated to `_` so `entry-points` becomes
/// `KUZUSHI_MCP_ENTRY_POINTS_ARTIFACT`.
fn mcp_artifact_env_for_attachments(
    attachments: &[kuzushi_core::McpAttachment],
) -> Vec<(String, String)> {
    attachments
        .iter()
        .filter(|attachment| !attachment.artifact_path.is_empty())
        .map(|attachment| {
            let env = format!(
                "KUZUSHI_MCP_{}_ARTIFACT",
                attachment.name.to_uppercase().replace('-', "_")
            );
            (env, attachment.artifact_path.clone())
        })
        .collect()
}

pub(crate) fn public_bridge_error(message: &str) -> String {
    let class = legacy_error_class(message);
    if class == "openai_authentication" {
        return "OpenAI OAuth authentication failed; run `kuzushi auth login openai`.".to_string();
    }
    public_failure_message(class, None)
}

pub(crate) fn public_bridge_failure(
    error_class: Option<&str>,
    status: Option<u16>,
    fallback: Option<&str>,
) -> String {
    let class = error_class
        .and_then(allowed_error_class)
        .or_else(|| status.map(error_class_for_status));
    match class {
        Some(class) => public_failure_message(class, status),
        None => public_bridge_error(fallback.unwrap_or_default()),
    }
}

fn public_failure_message(class: &str, status: Option<u16>) -> String {
    let base = match class {
        "authentication" => "Provider authentication failed",
        "cancelled" => "Bridge operation was cancelled",
        "provider_rejected" => "Provider rejected the request",
        "provider_response_invalid" => "Provider returned an invalid response",
        "provider_unavailable" => "Provider is temporarily unavailable",
        "rate_limited" => "Provider rate limited the request",
        "timeout" => "Provider request timed out",
        "transport" => "Provider request failed before a response was received",
        _ => "Bridge operation failed; raw error details were suppressed",
    };
    match status.filter(|status| (100..=599).contains(status)) {
        Some(status) => format!("{base} (HTTP {status})."),
        None => format!("{base}."),
    }
}

fn allowed_error_class(class: &str) -> Option<&str> {
    matches!(
        class,
        "authentication"
            | "bridge_internal"
            | "cancelled"
            | "provider_rejected"
            | "provider_response_invalid"
            | "provider_unavailable"
            | "rate_limited"
            | "timeout"
            | "transport"
    )
    .then_some(class)
}

fn error_class_for_status(status: u16) -> &'static str {
    match status {
        401 | 403 => "authentication",
        408 => "timeout",
        425 | 429 => "rate_limited",
        500..=599 => "provider_unavailable",
        _ => "provider_rejected",
    }
}

fn legacy_error_class(message: &str) -> &'static str {
    let lower = message
        .chars()
        .take(512)
        .collect::<String>()
        .to_ascii_lowercase();
    if lower.contains("openai-codex") || lower.contains("auth login openai") {
        return "openai_authentication";
    }
    if lower.contains("429") || lower.contains("rate limit") {
        return "rate_limited";
    }
    legacy_error_class_non_rate_limited(&lower)
}

fn legacy_error_class_non_rate_limited(lower: &str) -> &'static str {
    let parsed =
        (lower.contains("parse") && lower.contains("json")).then_some("provider_response_invalid");
    parsed
        .or_else(|| {
            LEGACY_ERROR_PATTERNS
                .iter()
                .find(|(needles, _)| needles.iter().any(|needle| lower.contains(needle)))
                .map(|(_, class)| *class)
        })
        .unwrap_or("bridge_internal")
}

fn run_json_bridge<T, R>(
    command: &[String],
    request: &T,
    label: &str,
    extra_env: &[(String, String)],
    cancellation: Option<&kuzushi_core::ScanCancellation>,
) -> Result<R>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let mut cmd = configured_bridge_command(command);
    for (env, value) in extra_env {
        cmd.env(env, value);
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("could not start {label} {}", command[0]))?;

    write_bridge_request(&mut child, request, label)?;
    let output = wait_with_output_deadline(child, label, bridge_timeout(), cancellation)?;
    parse_bridge_output(output, label)
}

/// Hard wall-clock ceiling for one bridge invocation. A wedged Node process
/// (MCP server hang, stdin deadlock, provider stall) previously blocked the
/// caller forever via `wait_with_output()`; every bridge call now surfaces as
/// a timeout error instead. Generous default: a single invocation can span a
/// long agent step with MCP tool calls.
const DEFAULT_BRIDGE_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_BRIDGE_STDOUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_BRIDGE_STDERR_BYTES: usize = 1024 * 1024;

fn bridge_timeout() -> Duration {
    std::env::var("KUZUSHI_BRIDGE_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_BRIDGE_TIMEOUT)
}

/// `wait_with_output` with a deadline: drains stdout/stderr on reader threads
/// (so a full pipe can't deadlock the child), polls for exit, and kills the
/// process when the deadline passes.
fn wait_with_output_deadline(
    child: Child,
    label: &str,
    timeout: Duration,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
) -> Result<Output> {
    wait_with_output_deadline_limits(
        child,
        label,
        timeout,
        cancellation,
        MAX_BRIDGE_STDOUT_BYTES,
        MAX_BRIDGE_STDERR_BYTES,
    )
}

pub(super) fn wait_with_output_deadline_limits(
    mut child: Child,
    label: &str,
    timeout: Duration,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<Output> {
    // Match `wait_with_output` semantics: close the child's stdin so a bridge
    // reading until EOF sees the request end instead of blocking forever.
    drop(child.stdin.take());
    let pipe_failure = Arc::new(Mutex::new(None));
    let stdout = spawn_pipe_reader(
        child.stdout.take(),
        stdout_limit,
        "stdout",
        Arc::clone(&pipe_failure),
    );
    let stderr = spawn_pipe_reader(
        child.stderr.take(),
        stderr_limit,
        "stderr",
        Arc::clone(&pipe_failure),
    );
    let registered = register_bridge_child(child, cancellation)?;
    let status = wait_status_deadline(&registered, label, timeout, cancellation, &pipe_failure)?;
    Ok(Output {
        status,
        stdout: join_pipe_reader(stdout, "stdout")?,
        stderr: join_pipe_reader(stderr, "stderr")?,
    })
}

fn register_bridge_child(
    child: Child,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
) -> Result<kuzushi_core::scan::RegisteredChild> {
    let process_group_id = bridge_process_group_id(&child);
    let local_cancellation;
    let registry = match cancellation {
        Some(cancellation) => cancellation,
        None => {
            local_cancellation = kuzushi_core::ScanCancellation::default();
            &local_cancellation
        }
    };
    registry.register_child(child, process_group_id)
}

type BridgePipeFailure = Arc<Mutex<Option<String>>>;
type BridgePipeReader = Option<std::thread::JoinHandle<Result<Vec<u8>>>>;

fn spawn_pipe_reader<R: Read + Send + 'static>(
    pipe: Option<R>,
    limit: usize,
    stream: &'static str,
    failure: BridgePipeFailure,
) -> BridgePipeReader {
    pipe.map(|mut pipe| {
        std::thread::spawn(move || match read_bounded_pipe(&mut pipe, limit, stream) {
            Ok(bytes) => Ok(bytes),
            Err(error) => {
                if let Ok(mut slot) = failure.lock() {
                    *slot = Some(error.to_string());
                }
                Err(error)
            }
        })
    })
}

pub(super) fn read_bounded_pipe(
    reader: &mut impl Read,
    limit: usize,
    stream: &str,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read LangGraph bridge {stream}"))?;
    anyhow::ensure!(
        bytes.len() <= limit,
        "LangGraph bridge {stream} exceeded the {limit}-byte capture limit"
    );
    Ok(bytes)
}

fn join_pipe_reader(handle: BridgePipeReader, stream: &str) -> Result<Vec<u8>> {
    let Some(handle) = handle else {
        return Ok(Vec::new());
    };
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("LangGraph bridge {stream} reader panicked"))?
}

fn wait_status_deadline(
    child: &kuzushi_core::scan::RegisteredChild,
    label: &str,
    timeout: Duration,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
    pipe_failure: &BridgePipeFailure,
) -> Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        kill_cancelled_bridge(child, label, cancellation)?;
        kill_bridge_on_pipe_failure(child, pipe_failure)?;
        if let Some(status) = poll_bridge_status(child, label)? {
            return Ok(status);
        }
        kill_expired_bridge(child, label, deadline, timeout)?;
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn kill_bridge_on_pipe_failure(
    child: &kuzushi_core::scan::RegisteredChild,
    failure: &BridgePipeFailure,
) -> Result<()> {
    let failure = failure
        .lock()
        .map_err(|_| anyhow::anyhow!("LangGraph bridge pipe failure state was poisoned"))?
        .clone();
    if let Some(failure) = failure {
        kill_child(child);
        anyhow::bail!(failure);
    }
    Ok(())
}

fn poll_bridge_status(
    child: &kuzushi_core::scan::RegisteredChild,
    label: &str,
) -> Result<Option<ExitStatus>> {
    child
        .try_wait()
        .with_context(|| format!("could not poll {label} process"))
}

fn kill_cancelled_bridge(
    child: &kuzushi_core::scan::RegisteredChild,
    label: &str,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
) -> Result<()> {
    if cancellation.is_some_and(kuzushi_core::ScanCancellation::is_cancelled) {
        kill_child(child);
        anyhow::bail!("{label} cancelled and was killed");
    }
    Ok(())
}

fn kill_expired_bridge(
    child: &kuzushi_core::scan::RegisteredChild,
    label: &str,
    deadline: Instant,
    timeout: Duration,
) -> Result<()> {
    if Instant::now() < deadline {
        return Ok(());
    }
    kill_child(child);
    anyhow::bail!(
        "{label} timed out after {}s and was killed; raise KUZUSHI_BRIDGE_TIMEOUT_MS \
         only if the call is legitimately long-running",
        timeout.as_secs()
    );
}

fn kill_child(child: &kuzushi_core::scan::RegisteredChild) {
    let _ = child.kill_and_wait();
}

fn configured_bridge_command(command: &[String]) -> Command {
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_bridge_process_group(&mut cmd);
    for (env, path) in mcp_binary_env_defaults() {
        cmd.env(env, path);
    }
    cmd
}

#[cfg(unix)]
pub(super) fn configure_bridge_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

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
pub(super) fn configure_bridge_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn bridge_process_group_id(child: &Child) -> Option<u32> {
    Some(child.id())
}

#[cfg(not(unix))]
fn bridge_process_group_id(_child: &Child) -> Option<u32> {
    None
}

fn parse_bridge_output<R: DeserializeOwned>(output: Output, label: &str) -> Result<R> {
    if output.status.success() {
        return parse_successful_bridge_output(&output.stdout, label);
    }
    parse_failed_bridge_output(output, label)
}

fn parse_successful_bridge_output<R: DeserializeOwned>(stdout: &[u8], label: &str) -> Result<R> {
    serde_json::from_slice::<R>(stdout)
        .map_err(|_| anyhow::anyhow!("could not parse {label} JSON response"))
}

fn parse_failed_bridge_output<R: DeserializeOwned>(output: Output, label: &str) -> Result<R> {
    if let Some(response) = parse_error_response(&output.stdout) {
        return Ok(response);
    }
    anyhow::bail!(
        "{label} exited with {}; bridge stdout/stderr details were suppressed",
        output.status
    );
}

fn parse_error_response<R: DeserializeOwned>(stdout: &[u8]) -> Option<R> {
    if stdout.is_empty() {
        return None;
    }
    serde_json::from_slice::<R>(stdout).ok()
}

fn write_bridge_request<T: Serialize>(
    child: &mut std::process::Child,
    request: &T,
    label: &str,
) -> Result<()> {
    let stdin = child
        .stdin
        .as_mut()
        .with_context(|| format!("could not open {label} stdin"))?;
    let body =
        serde_json::to_vec(request).with_context(|| format!("could not encode {label} request"))?;
    match stdin.write_all(&body) {
        Ok(()) => Ok(()),
        // `BrokenPipe` here means the bridge subprocess closed its stdin
        // (or exited entirely) before we finished writing the request.
        // That's a *normal* outcome for bridges that decided to short-
        // circuit — e.g. they emit an error JSON and exit 1 without ever
        // reading stdin, which is exactly what
        // `tests::next_step_bridge_surfaces_error_payload` and
        // `tests::bridge_failure_json_is_returned_as_actionable_error`
        // do. Before this carve-out the EPIPE propagated as a raw
        // `broken pipe` IO error with no label, and the tests's
        // assertions failed under parallel load because the unrelated
        // OS error obscured the actual bridge response. Drop EPIPE
        // here and let `wait_with_output` collect the bridge's already-
        // emitted stdout.
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(err) => Err(err).with_context(|| format!("could not write {label} stdin request body")),
    }
}

pub fn default_langgraph_bridge_command(source_root: &Path) -> Vec<String> {
    if let Some(command) = bridge_command_at(source_root) {
        return command;
    }

    // The caller's cwd (`source_root`) is the natural lookup spot when
    // kuzushi is invoked from inside the Kuzushi repo. When kuzushi is
    // invoked against an external target the cwd is the *target*, not
    // the Kuzushi tree, so fall back to the script that lives next to
    // the kuzushi executable.
    if let Some(exe_bridge) = bridge_next_to_executable() {
        return vec!["node".to_string(), exe_bridge.display().to_string()];
    }

    vec![
        "node".to_string(),
        "scripts/langgraph-bridge.mjs".to_string(),
    ]
}

fn bridge_command_at(source_root: &Path) -> Option<Vec<String>> {
    let bridge = source_root.join("scripts").join("langgraph-bridge.mjs");
    bridge
        .exists()
        .then(|| vec!["node".to_string(), bridge.display().to_string()])
}

fn bridge_next_to_executable() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    bridge_near_executable(&exe)
}

/// When kuzushi is invoked from `target/debug` or an installed layout, its
/// sibling `kuzushi-mcp-*` binaries are not on `PATH`, so the bridge's
/// `spawn("kuzushi-mcp-treesitter", …)` fails with ENOENT and any tool
/// requesting `toolPolicy.mcps=true` (e.g. `taint-iris-next:hunt`) silently
/// degrades to a no-MCP run before the LLM is ever called. Pre-populate the
/// per-binary `KUZUSHI_MCP_*_BIN` overrides with absolute sibling paths
/// when an operator hasn't already set them, so the bridge picks the
/// matching binary by default.
pub(super) fn mcp_binary_env_defaults() -> Vec<(&'static str, PathBuf)> {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(_) => return Vec::new(),
    };
    let Some(dir) = exe.parent() else {
        return Vec::new();
    };
    const CANDIDATES: &[(&str, &str)] = &[
        ("KUZUSHI_MCP_TREESITTER_BIN", "kuzushi-mcp-treesitter"),
        ("KUZUSHI_MCP_JOERN_BIN", "kuzushi-mcp-joern"),
        ("KUZUSHI_MCP_CODEQL_BIN", "kuzushi-mcp-codeql"),
        ("KUZUSHI_MCP_CLANG_BIN", "kuzushi-mcp-clang"),
        ("KUZUSHI_MCP_GTAGS_BIN", "kuzushi-mcp-gtags"),
        ("KUZUSHI_MCP_REVNG_BIN", "kuzushi-mcp-revng"),
        ("KUZUSHI_MCP_CONTEXT_BIN", "kuzushi-mcp-context"),
        ("KUZUSHI_MCP_ENTRY_POINTS_BIN", "kuzushi-mcp-entry-points"),
        ("KUZUSHI_MCP_THREAT_MODEL_BIN", "kuzushi-mcp-threat-model"),
        ("KUZUSHI_MCP_THREAT_INTEL_BIN", "kuzushi-mcp-threat-intel"),
        ("KUZUSHI_MCP_X_RAY_BIN", "kuzushi-mcp-x-ray"),
    ];
    CANDIDATES
        .iter()
        .filter_map(|(env_var, binary_name)| {
            if std::env::var_os(env_var).is_some() {
                return None;
            }
            let candidate = dir.join(binary_name);
            candidate.is_file().then_some((*env_var, candidate))
        })
        .collect()
}

pub(super) fn bridge_near_executable(exe: &Path) -> Option<PathBuf> {
    // Walk up to 6 ancestors so we cover the layouts kuzushi ships in:
    //   target/release/kuzushi          -> ../../scripts/...   (2 hops)
    //   target/debug/kuzushi            -> ../../scripts/...   (2 hops)
    //   native/<plat>-<arch>/kuzushi    -> ../../scripts/...   (2 hops)
    //   bin/kuzushi (npm package)       -> ../scripts/...      (1 hop)
    //   share/kuzushi/bin/kuzushi       -> ../../scripts/...   (2 hops)
    // 6 keeps the search bounded and well clear of `/`.
    let mut dir = exe.parent();
    for _ in 0..6 {
        let Some(parent) = dir else { return None };
        let candidate = parent.join("scripts").join("langgraph-bridge.mjs");
        if candidate.exists() {
            return Some(candidate);
        }
        dir = parent.parent();
    }
    None
}

#[cfg(test)]
mod telemetry_safety_tests {
    use super::*;

    #[derive(Debug, serde::Deserialize)]
    struct ExpectedResponse {
        _ok: bool,
    }

    #[test]
    fn successful_bridge_parse_error_does_not_echo_stdout() {
        let sentinel = br#"{"_ok":"raw-model-response-sentinel"}"#;

        let error = format!(
            "{:#}",
            parse_successful_bridge_output::<ExpectedResponse>(sentinel, "bridge").unwrap_err()
        );

        assert!(error.contains("could not parse bridge JSON response"));
        assert!(!error.contains("raw-model-response-sentinel"));
    }
}
