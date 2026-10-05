use super::bridge_observation::{BridgeObservation, BridgeStream};
use super::ResponseTextObserver;
use anyhow::{Context, Result};
use kuzushi_core::allowance::AllowanceBinding;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::bridge_payloads::{
    BridgeRequest, BridgeResponse, NextStepBridgeRequest, NextStepBridgeResponse,
    ToolPolicyHandshakeBridgeRequest, ToolPolicyHandshakeBridgeResponse,
};

const LEGACY_ERROR_PATTERNS: &[(&[&str], &str)] = &[
    (
        &[
            "missing credentials",
            "missing api key",
            "api key not found",
        ],
        "authentication",
    ),
    (&["timed out", "timeout"], "timeout"),
    (&["cancelled", "canceled"], "cancelled"),
    (&["fetch failed", "econnreset"], "transport"),
];

#[cfg(test)]
pub(crate) fn run_next_step_bridge_observed(
    command: &[String],
    request: &NextStepBridgeRequest,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
    observer: Option<&ResponseTextObserver>,
) -> Result<NextStepBridgeResponse> {
    run_next_step_bridge_admitted(command, request, cancellation, observer, None)
}

pub(crate) fn run_next_step_bridge_admitted(
    command: &[String],
    request: &NextStepBridgeRequest,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
    observer: Option<&ResponseTextObserver>,
    allowance: Option<&AllowanceBinding>,
) -> Result<NextStepBridgeResponse> {
    run_json_bridge(
        command,
        request,
        "next-step bridge",
        &[],
        cancellation,
        BridgeObservation::new(observer, allowance),
    )
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
        BridgeObservation::default(),
    )
}

pub(crate) fn run_bridge_admitted(
    command: &[String],
    request: &BridgeRequest,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
    observer: Option<&ResponseTextObserver>,
    allowance: Option<&AllowanceBinding>,
) -> Result<BridgeResponse> {
    let extra_env = mcp_artifact_env_for_attachments(&request.tool_policy.mcps_attached);
    run_json_bridge(
        command,
        request,
        "LangGraph bridge",
        &extra_env,
        cancellation,
        BridgeObservation::new(observer, allowance),
    )
}

pub(crate) fn run_tool_policy_handshake_bridge(
    command: &[String],
    request: &ToolPolicyHandshakeBridgeRequest,
) -> Result<ToolPolicyHandshakeBridgeResponse> {
    run_json_bridge(
        command,
        request,
        "tool-policy handshake bridge",
        &[],
        None,
        BridgeObservation::default(),
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

#[cfg(test)]
pub(crate) fn public_bridge_error(message: &str) -> String {
    if legacy_error_class(message) == "openai_authentication" {
        return "OpenAI OAuth authentication failed; run `kuzushi auth login openai`.".to_string();
    }
    bridge_failure_metadata(None, None, Some(message), None).public_message()
}

#[cfg(test)]
pub(crate) fn public_bridge_failure_with_detail(
    error_class: Option<&str>,
    status: Option<u16>,
    fallback: Option<&str>,
    detail: Option<&str>,
) -> String {
    bridge_failure_metadata(error_class, status, fallback, detail).public_message()
}

pub(crate) fn bridge_failure_metadata(
    error_class: Option<&str>,
    status: Option<u16>,
    fallback: Option<&str>,
    detail: Option<&str>,
) -> kuzushi_core::runtime::RuntimeFailureMetadata {
    let fallback = fallback.unwrap_or_default();
    let class = error_class
        .and_then(runtime_failure_class)
        .or_else(|| status.map(runtime_failure_class_for_status))
        .unwrap_or_else(|| legacy_runtime_failure_class(fallback));
    let detail = detail.or_else(|| legacy_safe_failure_detail(fallback));
    kuzushi_core::runtime::RuntimeFailureMetadata::new(class, status, detail)
}

fn legacy_safe_failure_detail(message: &str) -> Option<&'static str> {
    (legacy_error_class(message) == "openai_authentication")
        .then_some("OpenAI OAuth authentication failed; run `kuzushi auth login openai`.")
}

pub(crate) fn bridge_runtime_failure(
    error_class: Option<&str>,
    status: Option<u16>,
    fallback: Option<&str>,
    detail: Option<&str>,
) -> anyhow::Error {
    anyhow::Error::new(kuzushi_core::runtime::RuntimeFailure::new(
        bridge_failure_metadata(error_class, status, fallback, detail),
    ))
}

fn runtime_failure_class(class: &str) -> Option<kuzushi_core::runtime::RuntimeFailureClass> {
    use kuzushi_core::runtime::RuntimeFailureClass as Class;
    const CLASSES: [(&str, Class); 13] = [
        ("allowance_refused", Class::AllowanceRefused),
        ("authentication", Class::Authentication),
        ("bridge_internal", Class::BridgeInternal),
        ("cancelled", Class::Cancelled),
        ("mcp_timeout", Class::McpTimeout),
        ("mcp_unavailable", Class::McpUnavailable),
        ("provider_rejected", Class::ProviderRejected),
        ("provider_response_invalid", Class::ProviderResponseInvalid),
        ("provider_unavailable", Class::ProviderUnavailable),
        ("rate_limited", Class::RateLimited),
        ("sdk_client_validation", Class::SdkClientValidation),
        ("timeout", Class::Timeout),
        ("transport", Class::Transport),
    ];
    CLASSES
        .iter()
        .find_map(|(name, value)| (*name == class).then_some(*value))
}

fn runtime_failure_class_for_status(status: u16) -> kuzushi_core::runtime::RuntimeFailureClass {
    use kuzushi_core::runtime::RuntimeFailureClass as Class;
    match status {
        401 | 403 => Class::Authentication,
        408 => Class::Timeout,
        425 | 429 => Class::RateLimited,
        500..=599 => Class::ProviderUnavailable,
        _ => Class::ProviderRejected,
    }
}

fn legacy_runtime_failure_class(message: &str) -> kuzushi_core::runtime::RuntimeFailureClass {
    use kuzushi_core::runtime::RuntimeFailureClass as Class;
    let class = legacy_error_class(message);
    if class == "openai_authentication" {
        Class::Authentication
    } else {
        runtime_failure_class(class).unwrap_or(Class::BridgeInternal)
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

/// Spawn the bridge, hand it the request, and collect its process output.
/// The only side-effecting step; both runners below interpret the result.
fn bridge_output<T: Serialize>(
    command: &[String],
    request: &T,
    label: &str,
    extra_env: &[(String, String)],
    cancellation: Option<&kuzushi_core::ScanCancellation>,
    observation: BridgeObservation,
) -> Result<Output> {
    let request = observed_request(request, &observation)?;
    let (mut cmd, process_group) = configured_bridge_command(command)?;
    for (env, value) in extra_env {
        cmd.env(env, value);
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("could not start {label} {}", command[0]))?;

    write_bridge_request(&mut child, &request, label)?;
    wait_with_output_deadline(
        child,
        process_group,
        label,
        Some(bridge_timeout()?),
        cancellation,
        observation,
    )
}

fn observed_request<T: Serialize>(
    request: &T,
    observation: &BridgeObservation,
) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(request).context("could not encode LangGraph request")?;
    observation.prepare_request(&mut value)?;
    Ok(value)
}

fn run_json_bridge<T, R>(
    command: &[String],
    request: &T,
    label: &str,
    extra_env: &[(String, String)],
    cancellation: Option<&kuzushi_core::ScanCancellation>,
    observation: BridgeObservation,
) -> Result<R>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let output = bridge_output(
        command,
        request,
        label,
        extra_env,
        cancellation,
        observation,
    )?;
    parse_bridge_output(output, label)
}

/// Strict variant: a nonzero exit is a failure even when the bridge also
/// printed a well-formed response document. Diagnostic callers such as
/// `auth ping` must not report success for a process that died.
pub(crate) fn run_strict_json_bridge<T, R>(
    command: &[String],
    request: &T,
    label: &str,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
) -> Result<R>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let output = bridge_output(
        command,
        request,
        label,
        &[],
        cancellation,
        BridgeObservation::default(),
    )?;
    forward_bridge_diagnostics(&output.stderr);
    anyhow::ensure!(
        output.status.success(),
        "{label} exited with {}",
        output.status
    );
    parse_successful_bridge_output(&output.stdout, label)
}

const MAX_BRIDGE_STDOUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_BRIDGE_STDERR_BYTES: usize = 1024 * 1024;
const MAX_BRIDGE_DIAGNOSTIC_LINE_BYTES: usize = 4096;
const MAX_BRIDGE_DIAGNOSTIC_LINES: usize = 64;
const BRIDGE_DIAGNOSTIC_PREFIX: &str = "[kuzushi-bridge] ";

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BridgeDiagnosticMetadata {
    ts: u64,
    kind: BridgeDiagnosticKind,
    model_provider: BridgeDiagnosticProvider,
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking_level: Option<BridgeDiagnosticThinkingLevel>,
    tool_count: u64,
    prompt_len: u64,
    message_count: u64,
    system_prompt_len: u64,
    response_len: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop_class: Option<BridgeDiagnosticStopClass>,
    response_tool_count: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum BridgeDiagnosticKind {
    Query,
    NextStep,
}

#[derive(Debug, Deserialize, Serialize)]
enum BridgeDiagnosticProvider {
    #[serde(rename = "anthropic")]
    Anthropic,
    #[serde(rename = "openai")]
    OpenAi,
    #[serde(rename = "openai-codex")]
    OpenAiCodex,
    #[serde(rename = "other")]
    Other,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum BridgeDiagnosticThinkingLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum BridgeDiagnosticStopClass {
    Length,
    Tool,
    Complete,
    Filtered,
    Other,
}

const DEFAULT_BRIDGE_TIMEOUT_MS: u64 = 10 * 60 * 1_000;

fn bridge_timeout() -> Result<Duration> {
    match std::env::var("KUZUSHI_BRIDGE_TIMEOUT_MS") {
        Ok(raw) => bridge_timeout_from_env_value(Some(&raw)),
        Err(std::env::VarError::NotPresent) => bridge_timeout_from_env_value(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("KUZUSHI_BRIDGE_TIMEOUT_MS is not valid Unicode")
        }
    }
}

pub(super) fn bridge_timeout_from_env_value(raw: Option<&str>) -> Result<Duration> {
    let Some(raw) = raw else {
        return Ok(Duration::from_millis(DEFAULT_BRIDGE_TIMEOUT_MS));
    };
    let millis = raw
        .trim()
        .parse::<u64>()
        .context("KUZUSHI_BRIDGE_TIMEOUT_MS must be a positive integer")?;
    anyhow::ensure!(millis > 0, "KUZUSHI_BRIDGE_TIMEOUT_MS must be positive");
    Ok(Duration::from_millis(millis))
}

/// `wait_with_output` with an optional deadline: drains stdout/stderr on
/// reader threads (so a full pipe can't deadlock the child), polls for exit
/// and cancellation, and kills the process if a configured deadline passes.
fn wait_with_output_deadline(
    child: Child,
    process_group: kuzushi_core::scan::PreparedProcessGroup,
    label: &str,
    timeout: Option<Duration>,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
    observation: BridgeObservation,
) -> Result<Output> {
    wait_with_output_deadline_observed(
        child,
        process_group,
        label,
        timeout,
        cancellation,
        MAX_BRIDGE_STDOUT_BYTES,
        MAX_BRIDGE_STDERR_BYTES,
        observation,
    )
}

fn wait_with_output_deadline_observed(
    mut child: Child,
    process_group: kuzushi_core::scan::PreparedProcessGroup,
    label: &str,
    timeout: Option<Duration>,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
    stdout_limit: usize,
    stderr_limit: usize,
    observation: BridgeObservation,
) -> Result<Output> {
    // Legacy requests terminate at EOF. Admitted requests keep stdin solely
    // for replies to provider-call reservations on the framed stdout channel.
    let admission = observation.admission(child.stdin.take(), cancellation)?;
    let handshake = admission.as_ref().map(|admission| admission.handshake());
    let pipe_failure = Arc::new(Mutex::new(None));
    let stdout = spawn_pipe_reader(
        child.stdout.take(),
        stdout_limit,
        "stdout",
        Arc::clone(&pipe_failure),
        Some(BridgeStream {
            text: observation.text,
            admission,
        }),
    );
    let stderr = spawn_pipe_reader(
        child.stderr.take(),
        stderr_limit,
        "stderr",
        Arc::clone(&pipe_failure),
        None,
    );
    let registered = register_bridge_child(child, process_group, cancellation)?;
    let status = wait_status_deadline(
        &registered,
        label,
        timeout,
        cancellation,
        &pipe_failure,
        handshake.as_ref(),
    )?;
    Ok(Output {
        status,
        stdout: join_pipe_reader(stdout, "stdout")?,
        stderr: join_pipe_reader(stderr, "stderr")?,
    })
}

fn register_bridge_child(
    child: Child,
    process_group: kuzushi_core::scan::PreparedProcessGroup,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
) -> Result<kuzushi_core::scan::RegisteredChild> {
    let local_cancellation;
    let registry = match cancellation {
        Some(cancellation) => cancellation,
        None => {
            local_cancellation = kuzushi_core::ScanCancellation::default();
            &local_cancellation
        }
    };
    registry.register_prepared_child(child, process_group)
}

type BridgePipeFailure = Arc<Mutex<Option<anyhow::Error>>>;
type BridgePipeReader = Option<std::thread::JoinHandle<Result<Vec<u8>>>>;

fn spawn_pipe_reader<R: Read + Send + 'static>(
    pipe: Option<R>,
    limit: usize,
    stream: &'static str,
    failure: BridgePipeFailure,
    observation: Option<BridgeStream>,
) -> BridgePipeReader {
    pipe.map(|mut pipe| {
        std::thread::spawn(move || {
            match read_observed_pipe(&mut pipe, limit, stream, observation) {
                Ok(bytes) => Ok(bytes),
                Err(error) => {
                    if let Ok(mut slot) = failure.lock() {
                        *slot = Some(pipe_failure_error(&error));
                    }
                    Err(error)
                }
            }
        })
    })
}

fn pipe_failure_error(error: &anyhow::Error) -> anyhow::Error {
    match kuzushi_core::runtime::runtime_failure_metadata(error) {
        Some(metadata) => kuzushi_core::RuntimeFailure::new(metadata).into(),
        None => anyhow::anyhow!(error.to_string()),
    }
}

fn read_observed_pipe(
    reader: &mut impl Read,
    limit: usize,
    stream: &str,
    observation: Option<BridgeStream>,
) -> Result<Vec<u8>> {
    match observation {
        Some(observation) => super::response_frames::read_response_frames_admitted(
            reader,
            limit,
            observation.text.as_ref(),
            observation.admission,
        ),
        None => read_bounded_pipe(reader, limit, stream),
    }
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
    timeout: Option<Duration>,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
    pipe_failure: &BridgePipeFailure,
    handshake: Option<&super::provider_admission::AdmissionHandshake>,
) -> Result<ExitStatus> {
    let deadline = timeout.map(|timeout| (Instant::now() + timeout, timeout));
    loop {
        kill_cancelled_bridge(child, label, cancellation)?;
        kill_bridge_on_pipe_failure(child, pipe_failure)?;
        check_admission_handshake(child, handshake)?;
        kill_expired_bridge(child, label, deadline)?;
        if let Some(status) = poll_bridge_status(child, label)? {
            return Ok(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn check_admission_handshake(
    child: &kuzushi_core::scan::RegisteredChild,
    handshake: Option<&super::provider_admission::AdmissionHandshake>,
) -> Result<()> {
    let Some(handshake) = handshake else {
        return Ok(());
    };
    if let Err(error) = handshake.check() {
        kill_child(child);
        return Err(error);
    }
    Ok(())
}

fn kill_bridge_on_pipe_failure(
    child: &kuzushi_core::scan::RegisteredChild,
    failure: &BridgePipeFailure,
) -> Result<()> {
    let failure = failure
        .lock()
        .map_err(|_| anyhow::anyhow!("LangGraph bridge pipe failure state was poisoned"))?
        .take();
    if let Some(failure) = failure {
        kill_child(child);
        return Err(failure);
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
    deadline: Option<(Instant, Duration)>,
) -> Result<()> {
    let Some((deadline, timeout)) = deadline else {
        return Ok(());
    };
    if Instant::now() < deadline {
        return Ok(());
    }
    kill_child(child);
    anyhow::bail!(
        "{label} exceeded the KUZUSHI_BRIDGE_TIMEOUT_MS ceiling ({}s) and was killed",
        timeout.as_secs()
    );
}

fn kill_child(child: &kuzushi_core::scan::RegisteredChild) {
    let _ = child.kill_and_wait();
}

fn configured_bridge_command(
    command: &[String],
) -> Result<(Command, kuzushi_core::scan::PreparedProcessGroup)> {
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let process_group = configure_bridge_process_group(&mut cmd)?;
    for (env, path) in mcp_binary_env_defaults() {
        cmd.env(env, path);
    }
    Ok((cmd, process_group))
}

pub(super) fn configure_bridge_process_group(
    command: &mut Command,
) -> Result<kuzushi_core::scan::PreparedProcessGroup> {
    kuzushi_core::scan::PreparedProcessGroup::configure(command)
        .context("prepare LangGraph bridge parent-death process group")
}

fn parse_bridge_output<R: DeserializeOwned>(output: Output, label: &str) -> Result<R> {
    forward_bridge_diagnostics(&output.stderr);
    if output.status.success() {
        return parse_successful_bridge_output(&output.stdout, label);
    }
    parse_failed_bridge_output(output, label)
}

fn forward_bridge_diagnostics(captured_stderr: &[u8]) {
    let stderr = std::io::stderr();
    let mut destination = stderr.lock();
    write_bridge_diagnostics(captured_stderr, &mut destination);
}

pub(super) fn write_bridge_diagnostics(captured_stderr: &[u8], destination: &mut dyn Write) {
    let metadata = captured_stderr
        .split(|byte| *byte == b'\n')
        .filter_map(parse_bridge_diagnostic_line)
        .take(MAX_BRIDGE_DIAGNOSTIC_LINES);
    for metadata in metadata {
        if let Ok(serialized) = serde_json::to_string(&metadata) {
            let _ = writeln!(destination, "{BRIDGE_DIAGNOSTIC_PREFIX}{serialized}");
        }
    }
}

fn parse_bridge_diagnostic_line(line: &[u8]) -> Option<BridgeDiagnosticMetadata> {
    if line.len() > MAX_BRIDGE_DIAGNOSTIC_LINE_BYTES {
        return None;
    }
    let line = std::str::from_utf8(line).ok()?;
    let payload = line.strip_prefix(BRIDGE_DIAGNOSTIC_PREFIX)?;
    serde_json::from_str(payload).ok()
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
    let mut body =
        serde_json::to_vec(request).with_context(|| format!("could not encode {label} request"))?;
    body.push(b'\n');
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
        ("KUZUSHI_MCP_CPG_BIN", "kuzushi-mcp-cpg"),
        ("KUZUSHI_MCP_CODEQL_BIN", "kuzushi-mcp-codeql"),
        ("KUZUSHI_MCP_CLANG_BIN", "kuzushi-mcp-clang"),
        ("KUZUSHI_MCP_GTAGS_BIN", "kuzushi-mcp-gtags"),
        ("KUZUSHI_MCP_REVNG_BIN", "kuzushi-mcp-revng"),
        ("KUZUSHI_MCP_CONTEXT_BIN", "kuzushi-mcp-context"),
        ("KUZUSHI_MCP_ENTRY_POINTS_BIN", "kuzushi-mcp-entry-points"),
        ("KUZUSHI_MCP_FINDINGS_BIN", "kuzushi-mcp-findings"),
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

#[cfg(test)]
pub(super) fn wait_with_output_deadline_limits(
    child: Child,
    process_group: kuzushi_core::scan::PreparedProcessGroup,
    label: &str,
    timeout: Option<Duration>,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<Output> {
    wait_with_output_deadline_observed(
        child,
        process_group,
        label,
        timeout,
        cancellation,
        stdout_limit,
        stderr_limit,
        BridgeObservation::default(),
    )
}
