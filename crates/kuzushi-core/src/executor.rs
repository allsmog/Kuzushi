//! Executor abstraction (scaffold)
//!
//! Inspired by deepsec's `ExecutorProvider` (the 5th plugin slot in their
//! plugin model). The goal is to give scan/triage workers a place to fan
//! out across containers, microVMs, or AWS Batch backends without touching
//! the orchestrator. Today only the in-process [`LocalExecutor`] exists;
//! Docker/Sandbox/Batch backends are TODO.
//!
//! This module is **scaffold only**: the trait and two impls (no-op and
//! local) are exported, but no caller in the workspace wires an
//! [`Executor`] through `ToolExecutionContext` yet. That happens when the
//! first remote backend lands and the call sites that benefit (triage
//! batcher, sast pipeline) opt in.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutorRequest {
    pub run_id: String,
    pub command: Vec<String>,
    pub working_dir: PathBuf,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExecutorStatus {
    /// Run is queued or in progress.
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    /// Backend doesn't track this run id (most common: a no-op executor).
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutorResult {
    pub run_id: String,
    pub status: ExecutorStatus,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<SystemTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<SystemTime>,
}

/// Minimum surface for fan-out execution. `launch` returns a run id the
/// caller can later `collect` and `status` against. Trait is `Send + Sync`
/// so backends can be `Arc`-shared between scan workers.
pub trait Executor: Send + Sync {
    fn launch(&self, request: ExecutorRequest) -> Result<String>;
    fn collect(&self, run_id: &str) -> Result<ExecutorResult>;
    fn status(&self, run_id: &str) -> Result<ExecutorStatus>;
    fn name(&self) -> &str;
}

/// In-process executor — runs commands synchronously in `launch` and stores
/// the result so `collect` is a HashMap lookup. Intended for tests, the
/// default fallback when no remote backend is configured, and any caller
/// that wants a `dyn Executor` for type uniformity.
pub struct LocalExecutor {
    results: Mutex<HashMap<String, ExecutorResult>>,
}

impl Default for LocalExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalExecutor {
    pub fn new() -> Self {
        Self {
            results: Mutex::new(HashMap::new()),
        }
    }
}

impl Executor for LocalExecutor {
    fn launch(&self, request: ExecutorRequest) -> Result<String> {
        let run_id = request.run_id.clone();
        let started_at = SystemTime::now();

        let mut command = std::process::Command::new(
            request
                .command
                .first()
                .context("LocalExecutor requires a non-empty command")?,
        );
        if request.command.len() > 1 {
            command.args(&request.command[1..]);
        }
        command.current_dir(&request.working_dir);
        for (key, value) in &request.env {
            command.env(key, value);
        }
        if request.stdin.is_some() {
            command.stdin(std::process::Stdio::piped());
        }
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());

        let mut child = command
            .spawn()
            .with_context(|| format!("Could not start {:?}", request.command))?;
        if let (Some(stdin_text), Some(mut stdin)) = (&request.stdin, child.stdin.take()) {
            use std::io::Write;
            stdin
                .write_all(stdin_text.as_bytes())
                .context("Could not write executor stdin")?;
        }
        let output = child
            .wait_with_output()
            .context("Could not wait on executor child")?;
        let completed_at = SystemTime::now();

        let result = ExecutorResult {
            run_id: run_id.clone(),
            status: if output.status.success() {
                ExecutorStatus::Succeeded
            } else {
                ExecutorStatus::Failed
            },
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code(),
            started_at: Some(started_at),
            completed_at: Some(completed_at),
        };
        self.results
            .lock()
            .expect("LocalExecutor results lock poisoned")
            .insert(run_id.clone(), result);
        Ok(run_id)
    }

    fn collect(&self, run_id: &str) -> Result<ExecutorResult> {
        let guard = self
            .results
            .lock()
            .expect("LocalExecutor results lock poisoned");
        guard
            .get(run_id)
            .cloned()
            .with_context(|| format!("LocalExecutor has no record of run id {run_id}"))
    }

    fn status(&self, run_id: &str) -> Result<ExecutorStatus> {
        let guard = self
            .results
            .lock()
            .expect("LocalExecutor results lock poisoned");
        Ok(guard
            .get(run_id)
            .map(|result| result.status)
            .unwrap_or(ExecutorStatus::Unknown))
    }

    fn name(&self) -> &str {
        "local"
    }
}

/// Container-backed executor that wraps each `launch` in
/// `docker run --rm -v <working_dir>:/workspace -w /workspace <image> <cmd>`.
/// Captures stdout/stderr/exit code into the results map. Useful when an
/// operator wants triage / scan to fan out across containers without
/// installing scanner binaries on the host.
///
/// Today the implementation is "one container per launch"; pooling and
/// long-lived sidecars are a follow-up.
pub struct DockerExecutor {
    image: String,
    docker_binary: String,
    extra_run_args: Vec<String>,
    results: Mutex<HashMap<String, ExecutorResult>>,
}

impl DockerExecutor {
    /// Create a Docker executor for the given image. Defaults the docker
    /// binary to `docker`; override with [`with_binary`] for podman / a
    /// non-PATH location.
    pub fn new(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            docker_binary: "docker".to_string(),
            extra_run_args: Vec::new(),
            results: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_binary(mut self, binary: impl Into<String>) -> Self {
        self.docker_binary = binary.into();
        self
    }

    /// Append flags to every `docker run` invocation (e.g. `--user 1000:1000`,
    /// `--cap-drop ALL`, `--read-only`). These come *after* the volume mount
    /// and `-w` flag and *before* the image name.
    pub fn with_run_args(
        mut self,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.extra_run_args
            .extend(args.into_iter().map(Into::into));
        self
    }
}

impl Executor for DockerExecutor {
    fn launch(&self, request: ExecutorRequest) -> Result<String> {
        let run_id = request.run_id.clone();
        let started_at = SystemTime::now();

        let workdir = request
            .working_dir
            .canonicalize()
            .with_context(|| {
                format!(
                    "DockerExecutor could not resolve {}",
                    request.working_dir.display()
                )
            })?;

        let mut command = std::process::Command::new(&self.docker_binary);
        command.arg("run");
        command.arg("--rm");
        command.arg("-v");
        command.arg(format!("{}:/workspace", workdir.display()));
        command.arg("-w");
        command.arg("/workspace");
        for (key, value) in &request.env {
            command.arg("-e");
            command.arg(format!("{key}={value}"));
        }
        for extra in &self.extra_run_args {
            command.arg(extra);
        }
        if request.stdin.is_some() {
            command.arg("-i");
        }
        command.arg(&self.image);
        let inner = request
            .command
            .first()
            .context("DockerExecutor requires a non-empty command")?;
        command.arg(inner);
        if request.command.len() > 1 {
            for arg in &request.command[1..] {
                command.arg(arg);
            }
        }

        if request.stdin.is_some() {
            command.stdin(std::process::Stdio::piped());
        }
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());

        let mut child = command.spawn().with_context(|| {
            format!(
                "DockerExecutor could not spawn {}: is docker installed?",
                self.docker_binary
            )
        })?;
        if let (Some(stdin_text), Some(mut stdin)) = (&request.stdin, child.stdin.take()) {
            use std::io::Write;
            stdin
                .write_all(stdin_text.as_bytes())
                .context("Could not write docker container stdin")?;
        }
        let output = child
            .wait_with_output()
            .context("Could not wait on docker child")?;
        let completed_at = SystemTime::now();

        let result = ExecutorResult {
            run_id: run_id.clone(),
            status: if output.status.success() {
                ExecutorStatus::Succeeded
            } else {
                ExecutorStatus::Failed
            },
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code(),
            started_at: Some(started_at),
            completed_at: Some(completed_at),
        };
        self.results
            .lock()
            .expect("DockerExecutor results lock poisoned")
            .insert(run_id.clone(), result);
        Ok(run_id)
    }

    fn collect(&self, run_id: &str) -> Result<ExecutorResult> {
        let guard = self
            .results
            .lock()
            .expect("DockerExecutor results lock poisoned");
        guard
            .get(run_id)
            .cloned()
            .with_context(|| format!("DockerExecutor has no record of run id {run_id}"))
    }

    fn status(&self, run_id: &str) -> Result<ExecutorStatus> {
        let guard = self
            .results
            .lock()
            .expect("DockerExecutor results lock poisoned");
        Ok(guard
            .get(run_id)
            .map(|result| result.status)
            .unwrap_or(ExecutorStatus::Unknown))
    }

    fn name(&self) -> &str {
        "docker"
    }
}

/// Remote-execution executor (HTTP-based, blocking via `ureq`).
///
/// Wraps a generic request/response surface for a remote backend
/// (Vercel Sandbox, AWS Batch, Kubernetes Jobs). The protocol is
/// intentionally simple so a thin shim in front of any backend works:
///
///   POST  <endpoint>/runs           { clientId, runId, command, ... }
///   GET   <endpoint>/runs/<id>      -> { status, stdout, stderr, exitCode, ... }
///   GET   <endpoint>/runs/<id>/status -> { status }
///
/// Authentication: when `api_key` is set, every request carries
/// `Authorization: Bearer <key>`. The `clientId/runId` pair is the
/// idempotency key so concurrent kuzushi processes against the same
/// backend don't collide.
pub struct SandboxExecutor {
    endpoint: String,
    api_key: Option<String>,
    /// Per-instance prefix prepended to every run id so concurrent
    /// kuzushi processes against the same remote backend don't collide.
    client_id: String,
    /// Per-call HTTP timeout. Defaults to 60s; override for long scans.
    timeout: std::time::Duration,
    results: Mutex<HashMap<String, ExecutorResult>>,
}

impl SandboxExecutor {
    /// Construct a SandboxExecutor pointed at `endpoint` (e.g.
    /// `https://sandbox.example.com/v1`). Trailing slash is normalised.
    pub fn new(endpoint: impl Into<String>) -> Self {
        let mut endpoint: String = endpoint.into();
        while endpoint.ends_with('/') {
            endpoint.pop();
        }
        Self {
            endpoint,
            api_key: None,
            client_id: format!("kuzushi-{}", std::process::id()),
            timeout: std::time::Duration::from_secs(60),
            results: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = client_id.into();
        self
    }

    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Public for callers / tests that want to inspect the constructed
    /// JSON body without firing a real request.
    pub fn build_request_body(&self, request: &ExecutorRequest) -> Result<String> {
        let payload = serde_json::json!({
            "clientId": self.client_id,
            "runId": request.run_id,
            "command": request.command,
            "workingDir": request.working_dir.display().to_string(),
            "env": request.env,
            "stdin": request.stdin,
        });
        serde_json::to_string(&payload).context("could not encode SandboxExecutor payload")
    }

    fn agent(&self) -> ureq::Agent {
        ureq::AgentBuilder::new()
            .timeout(self.timeout)
            .build()
    }

    fn authed_post(&self, url: &str, body: &str) -> Result<String> {
        let agent = self.agent();
        let mut req = agent.post(url).set("Content-Type", "application/json");
        if let Some(key) = &self.api_key {
            req = req.set("Authorization", &format!("Bearer {key}"));
        }
        let response = req
            .send_string(body)
            .map_err(|error| anyhow::anyhow!("sandbox POST {url} failed: {error}"))?;
        response
            .into_string()
            .with_context(|| format!("sandbox POST {url} response body"))
    }

    fn authed_get(&self, url: &str) -> Result<String> {
        let agent = self.agent();
        let mut req = agent.get(url);
        if let Some(key) = &self.api_key {
            req = req.set("Authorization", &format!("Bearer {key}"));
        }
        let response = req
            .call()
            .map_err(|error| anyhow::anyhow!("sandbox GET {url} failed: {error}"))?;
        response
            .into_string()
            .with_context(|| format!("sandbox GET {url} response body"))
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SandboxLaunchResponse {
    #[serde(default)]
    run_id: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SandboxResultResponse {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    stdout: Option<String>,
    #[serde(default)]
    stderr: Option<String>,
    #[serde(default)]
    exit_code: Option<i32>,
}

fn parse_sandbox_status(raw: Option<&str>) -> ExecutorStatus {
    match raw.map(str::to_ascii_lowercase).as_deref() {
        Some("pending") => ExecutorStatus::Pending,
        Some("running") => ExecutorStatus::Running,
        Some("succeeded") | Some("complete") | Some("completed") => ExecutorStatus::Succeeded,
        Some("failed") | Some("error") => ExecutorStatus::Failed,
        Some("cancelled") | Some("canceled") => ExecutorStatus::Cancelled,
        _ => ExecutorStatus::Unknown,
    }
}

impl Executor for SandboxExecutor {
    fn launch(&self, request: ExecutorRequest) -> Result<String> {
        let body = self.build_request_body(&request)?;
        let url = format!("{}/runs", self.endpoint);
        let raw = self.authed_post(&url, &body)?;
        let response: SandboxLaunchResponse = serde_json::from_str(&raw).with_context(|| {
            format!("sandbox launch returned non-JSON or unexpected shape: {raw:.300}")
        })?;
        // Trust the operator-supplied run_id when the server echoes it
        // back (most idempotent backends do); otherwise prefer the
        // server's id so two callers with identical run_ids don't
        // overwrite each other's slot in `self.results`.
        let id = response.run_id.unwrap_or_else(|| request.run_id.clone());
        Ok(id)
    }

    fn collect(&self, run_id: &str) -> Result<ExecutorResult> {
        let url = format!("{}/runs/{run_id}", self.endpoint);
        let raw = self.authed_get(&url)?;
        let response: SandboxResultResponse = serde_json::from_str(&raw).with_context(|| {
            format!("sandbox collect returned non-JSON or unexpected shape: {raw:.300}")
        })?;
        let result = ExecutorResult {
            run_id: run_id.to_string(),
            status: parse_sandbox_status(response.status.as_deref()),
            stdout: response.stdout.unwrap_or_default(),
            stderr: response.stderr.unwrap_or_default(),
            exit_code: response.exit_code,
            started_at: None,
            completed_at: None,
        };
        // Cache the result so a follow-up `status(...)` call can answer
        // without a second round-trip.
        self.results
            .lock()
            .expect("SandboxExecutor results lock poisoned")
            .insert(run_id.to_string(), result.clone());
        Ok(result)
    }

    fn status(&self, run_id: &str) -> Result<ExecutorStatus> {
        // Prefer the cached result if `collect` has already fetched.
        if let Some(cached) = self
            .results
            .lock()
            .expect("SandboxExecutor results lock poisoned")
            .get(run_id)
        {
            return Ok(cached.status);
        }
        let url = format!("{}/runs/{run_id}/status", self.endpoint);
        let raw = match self.authed_get(&url) {
            Ok(value) => value,
            Err(_) => return Ok(ExecutorStatus::Unknown),
        };
        #[derive(serde::Deserialize)]
        struct StatusResponse {
            #[serde(default)]
            status: Option<String>,
        }
        let response: StatusResponse =
            serde_json::from_str(&raw).unwrap_or(StatusResponse { status: None });
        Ok(parse_sandbox_status(response.status.as_deref()))
    }

    fn name(&self) -> &str {
        "sandbox"
    }
}

/// Stand-in for callers that want a `Box<dyn Executor>` slot but don't
/// have a real backend wired yet. Always returns `Unknown`.
pub struct NoopExecutor;

impl Executor for NoopExecutor {
    fn launch(&self, _request: ExecutorRequest) -> Result<String> {
        anyhow::bail!("no executor backend configured")
    }
    fn collect(&self, _run_id: &str) -> Result<ExecutorResult> {
        anyhow::bail!("no executor backend configured")
    }
    fn status(&self, _run_id: &str) -> Result<ExecutorStatus> {
        Ok(ExecutorStatus::Unknown)
    }
    fn name(&self) -> &str {
        "noop"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_executor_runs_a_command_and_stores_result() {
        let exec = LocalExecutor::new();
        let request = ExecutorRequest {
            run_id: "run-1".to_string(),
            command: vec!["sh".to_string(), "-c".to_string(), "echo hi".to_string()],
            working_dir: PathBuf::from("."),
            env: HashMap::new(),
            stdin: None,
        };
        let id = exec.launch(request).unwrap();
        assert_eq!(id, "run-1");
        let result = exec.collect("run-1").unwrap();
        assert_eq!(result.status, ExecutorStatus::Succeeded);
        assert!(result.stdout.contains("hi"));
        assert_eq!(exec.status("run-1").unwrap(), ExecutorStatus::Succeeded);
    }

    #[test]
    fn local_executor_failed_command_is_recorded() {
        let exec = LocalExecutor::new();
        let request = ExecutorRequest {
            run_id: "run-fail".to_string(),
            command: vec!["sh".to_string(), "-c".to_string(), "exit 7".to_string()],
            working_dir: PathBuf::from("."),
            env: HashMap::new(),
            stdin: None,
        };
        exec.launch(request).unwrap();
        let result = exec.collect("run-fail").unwrap();
        assert_eq!(result.status, ExecutorStatus::Failed);
        assert_eq!(result.exit_code, Some(7));
    }

    #[test]
    fn local_executor_collects_stdin() {
        let exec = LocalExecutor::new();
        let request = ExecutorRequest {
            run_id: "run-stdin".to_string(),
            command: vec!["cat".to_string()],
            working_dir: PathBuf::from("."),
            env: HashMap::new(),
            stdin: Some("payload-via-stdin".to_string()),
        };
        exec.launch(request).unwrap();
        let result = exec.collect("run-stdin").unwrap();
        assert!(result.stdout.contains("payload-via-stdin"));
    }

    #[test]
    fn collect_returns_error_for_unknown_run_id() {
        let exec = LocalExecutor::new();
        assert!(exec.collect("nope").is_err());
    }

    #[test]
    fn docker_executor_constructs_expected_command_arguments() {
        // We can't reliably exec docker in CI, so this test asserts the
        // arg order via name(), with_binary, with_run_args without invoking
        // the binary. End-to-end coverage lives in scan-mode integration
        // when DOCKER_HOST is set.
        let exec = DockerExecutor::new("alpine:3.19")
            .with_binary("docker")
            .with_run_args(["--user", "1000:1000", "--cap-drop", "ALL"]);
        assert_eq!(exec.name(), "docker");
        assert_eq!(exec.image, "alpine:3.19");
        assert_eq!(exec.docker_binary, "docker");
        assert_eq!(
            exec.extra_run_args,
            vec![
                "--user".to_string(),
                "1000:1000".to_string(),
                "--cap-drop".to_string(),
                "ALL".to_string()
            ]
        );
    }

    #[test]
    fn docker_executor_reports_unknown_run_id() {
        let exec = DockerExecutor::new("alpine:3.19");
        assert_eq!(exec.status("nope").unwrap(), ExecutorStatus::Unknown);
    }

    #[test]
    fn sandbox_executor_builds_request_body_with_idempotency_key() {
        let exec = SandboxExecutor::new("https://sandbox.example.com/v1")
            .with_api_key("vck_demo")
            .with_client_id("kuzushi-test");
        let body = exec
            .build_request_body(&ExecutorRequest {
                run_id: "run-99".to_string(),
                command: vec!["ls".to_string()],
                working_dir: PathBuf::from("/work"),
                env: HashMap::from([("KEY".to_string(), "VAL".to_string())]),
                stdin: None,
            })
            .unwrap();
        assert!(body.contains("\"clientId\":\"kuzushi-test\""));
        assert!(body.contains("\"runId\":\"run-99\""));
        assert!(body.contains("\"workingDir\":\"/work\""));
        assert!(body.contains("\"command\":[\"ls\"]"));
        assert!(body.contains("\"KEY\":\"VAL\""));
    }

    #[test]
    fn sandbox_executor_normalises_trailing_slash_in_endpoint() {
        let exec = SandboxExecutor::new("https://sandbox.example.com/v1/");
        assert_eq!(exec.endpoint(), "https://sandbox.example.com/v1");
    }

    #[test]
    fn sandbox_executor_launch_against_unreachable_host_surfaces_a_clear_error() {
        // Loopback to a port that almost-certainly nothing is bound to;
        // ureq will return a connect/connection-refused error which we
        // surface with the URL so operators can read it.
        let exec = SandboxExecutor::new("http://127.0.0.1:1")
            .with_timeout(std::time::Duration::from_millis(150));
        let err = exec
            .launch(ExecutorRequest {
                run_id: "rid".to_string(),
                command: vec!["true".to_string()],
                working_dir: PathBuf::from("."),
                env: HashMap::new(),
                stdin: None,
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("sandbox POST"));
        assert!(err.contains("/runs"));
    }

    #[test]
    fn parse_sandbox_status_recognises_common_strings() {
        assert_eq!(parse_sandbox_status(Some("pending")), ExecutorStatus::Pending);
        assert_eq!(parse_sandbox_status(Some("Running")), ExecutorStatus::Running);
        assert_eq!(
            parse_sandbox_status(Some("SUCCEEDED")),
            ExecutorStatus::Succeeded
        );
        assert_eq!(parse_sandbox_status(Some("complete")), ExecutorStatus::Succeeded);
        assert_eq!(parse_sandbox_status(Some("failed")), ExecutorStatus::Failed);
        assert_eq!(
            parse_sandbox_status(Some("cancelled")),
            ExecutorStatus::Cancelled
        );
        assert_eq!(parse_sandbox_status(None), ExecutorStatus::Unknown);
        assert_eq!(parse_sandbox_status(Some("weird")), ExecutorStatus::Unknown);
    }

    #[test]
    fn noop_executor_reports_unknown() {
        let exec = NoopExecutor;
        assert!(exec.launch(ExecutorRequest {
            run_id: "ignored".to_string(),
            command: vec!["true".to_string()],
            working_dir: PathBuf::from("."),
            env: HashMap::new(),
            stdin: None,
        })
        .is_err());
        assert_eq!(exec.status("anything").unwrap(), ExecutorStatus::Unknown);
        assert_eq!(exec.name(), "noop");
    }
}
