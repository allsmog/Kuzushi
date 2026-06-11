use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use super::bridge_payloads::{
    BridgeRequest, BridgeResponse, NextStepBridgeRequest, NextStepBridgeResponse,
};

pub(crate) fn run_next_step_bridge(
    command: &[String],
    request: &NextStepBridgeRequest,
) -> Result<NextStepBridgeResponse> {
    run_json_bridge(command, request, "next-step bridge", &[])
}

pub(crate) fn run_next_step_preflight_bridge(
    command: &[String],
    request: &NextStepBridgeRequest,
) -> Result<NextStepBridgeResponse> {
    run_json_bridge(command, request, "next-step preflight bridge", &[])
}

pub(crate) fn run_bridge(command: &[String], request: &BridgeRequest) -> Result<BridgeResponse> {
    let extra_env = mcp_artifact_env_for_attachments(&request.tool_policy.mcps_attached);
    run_json_bridge(command, request, "LangGraph bridge", &extra_env)
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
    message
        .replace("auth login openai-codex", "auth login openai")
        .replace("openai-codex", "OpenAI OAuth")
}

fn run_json_bridge<T, R>(
    command: &[String],
    request: &T,
    label: &str,
    extra_env: &[(String, String)],
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
    let output = wait_with_output_deadline(child, label, bridge_timeout())?;
    parse_bridge_output(output, label)
}

/// Hard wall-clock ceiling for one bridge invocation. A wedged Node process
/// (MCP server hang, stdin deadlock, provider stall) previously blocked the
/// caller forever via `wait_with_output()`; every bridge call now surfaces as
/// a timeout error instead. Generous default: a single invocation can span a
/// long agent step with MCP tool calls.
const DEFAULT_BRIDGE_TIMEOUT: Duration = Duration::from_secs(600);

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
fn wait_with_output_deadline(mut child: Child, label: &str, timeout: Duration) -> Result<Output> {
    // Match `wait_with_output` semantics: close the child's stdin so a bridge
    // reading until EOF sees the request end instead of blocking forever.
    drop(child.stdin.take());
    let stdout = spawn_pipe_reader(child.stdout.take());
    let stderr = spawn_pipe_reader(child.stderr.take());
    let status = wait_status_deadline(&mut child, label, timeout)?;
    Ok(Output {
        status,
        stdout: join_pipe_reader(stdout),
        stderr: join_pipe_reader(stderr),
    })
}

fn spawn_pipe_reader<R: Read + Send + 'static>(
    pipe: Option<R>,
) -> Option<std::thread::JoinHandle<Vec<u8>>> {
    pipe.map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buffer = Vec::new();
            let _ = pipe.read_to_end(&mut buffer);
            buffer
        })
    })
}

fn join_pipe_reader(handle: Option<std::thread::JoinHandle<Vec<u8>>>) -> Vec<u8> {
    handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default()
}

fn wait_status_deadline(child: &mut Child, label: &str, timeout: Duration) -> Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("could not poll {label} process"))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!(
                "{label} timed out after {}s and was killed; raise KUZUSHI_BRIDGE_TIMEOUT_MS \
                 only if the call is legitimately long-running",
                timeout.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn configured_bridge_command(command: &[String]) -> Command {
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (env, path) in mcp_binary_env_defaults() {
        cmd.env(env, path);
    }
    cmd
}

fn parse_bridge_output<R: DeserializeOwned>(output: Output, label: &str) -> Result<R> {
    if output.status.success() {
        return parse_successful_bridge_output(&output.stdout, label);
    }
    parse_failed_bridge_output(output, label)
}

fn parse_successful_bridge_output<R: DeserializeOwned>(stdout: &[u8], label: &str) -> Result<R> {
    serde_json::from_slice::<R>(stdout).with_context(|| {
        format!(
            "could not parse {label} JSON: {}",
            public_bridge_bytes(stdout)
        )
    })
}

fn parse_failed_bridge_output<R: DeserializeOwned>(output: Output, label: &str) -> Result<R> {
    if let Some(response) = parse_error_response(&output.stdout) {
        return Ok(response);
    }
    anyhow::bail!(
        "{label} exited with {}: {}",
        output.status,
        bridge_error_detail(&output.stdout, &output.stderr)
    );
}

fn parse_error_response<R: DeserializeOwned>(stdout: &[u8]) -> Option<R> {
    if stdout.is_empty() {
        return None;
    }
    serde_json::from_slice::<R>(stdout).ok()
}

fn bridge_error_detail(stdout: &[u8], stderr: &[u8]) -> String {
    if stderr.is_empty() {
        return public_bridge_bytes(stdout);
    }
    public_bridge_bytes(stderr)
}

fn public_bridge_bytes(bytes: &[u8]) -> String {
    let raw = String::from_utf8_lossy(bytes);
    public_bridge_error(raw.as_ref())
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
