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
