use std::env;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_core::{
    AgentQueryRequest, AgentQueryResponse, AgentRuntime, RuntimeConfig, TriageOutcome,
    TriageRequest, TriageVerdict, V2Config,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct PiAgentCoreRuntime {
    command: Vec<String>,
    api_key_env: String,
    api_key: Option<String>,
    base_url: Option<String>,
    thinking_level: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct BridgeCancellation {
    cancelled: Arc<AtomicBool>,
}

impl BridgeCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

impl PiAgentCoreRuntime {
    pub fn from_config(config: &V2Config, source_root: impl AsRef<Path>) -> Result<Self> {
        Self::from_runtime_config(&config.runtime, source_root)
    }

    pub fn from_runtime_config(
        runtime: &RuntimeConfig,
        source_root: impl AsRef<Path>,
    ) -> Result<Self> {
        let command = runtime
            .agent_bridge_command
            .clone()
            .unwrap_or_else(|| default_bridge_command(source_root.as_ref()));
        if command.is_empty() {
            anyhow::bail!("pi-agent-core bridge command is empty");
        }

        let api_key = env::var(&runtime.api_key_env)
            .ok()
            .filter(|value| !value.trim().is_empty());

        Ok(Self {
            command,
            api_key_env: runtime.api_key_env.clone(),
            api_key,
            base_url: runtime.base_url.clone(),
            thinking_level: env::var("KUZUSHI_THINKING_LEVEL")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
        })
    }

    pub fn command(&self) -> &[String] {
        &self.command
    }

    pub fn with_thinking_level(mut self, thinking_level: Option<String>) -> Self {
        self.thinking_level = thinking_level
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        self
    }

    pub fn query_blocking_with_cancellation(
        &self,
        request: AgentQueryRequest,
        cancellation: &BridgeCancellation,
    ) -> Result<AgentQueryResponse> {
        let bridge_request = self.bridge_request(request);
        let response =
            run_bridge_with_cancellation(&self.command, &bridge_request, Some(cancellation))?;
        response.into_agent_response()
    }

    fn bridge_request(&self, request: AgentQueryRequest) -> BridgeRequest {
        BridgeRequest {
            model: request.model,
            cwd: request.cwd.display().to_string(),
            system_prompt: request.system_prompt,
            prompt: request.prompt,
            api_key_env: self.api_key_env.clone(),
            api_key: self.api_key.clone(),
            base_url: self.base_url.clone(),
            thinking_level: self.thinking_level.clone(),
        }
    }
}

#[async_trait]
impl AgentRuntime for PiAgentCoreRuntime {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        let bridge_request = self.bridge_request(request);
        let response = run_bridge(&self.command, &bridge_request)?;
        response.into_agent_response()
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        let prompt = triage_prompt(&request.finding, request.prompt_template.as_deref())?;
        let response = self.query_blocking(AgentQueryRequest {
            model: request.model,
            cwd: request.cwd,
            system_prompt: TRIAGE_SYSTEM_PROMPT.to_string(),
            prompt,
        })?;

        if let Some(structured) = response.structured {
            if let Ok(outcome) = serde_json::from_value::<TriageOutcome>(structured.clone()) {
                return Ok(clamp_outcome(outcome));
            }
        }

        if !response.text.is_empty() {
            if let Ok(outcome) = serde_json::from_str::<TriageOutcome>(&response.text) {
                return Ok(clamp_outcome(outcome));
            }
            return Ok(TriageOutcome {
                verdict: TriageVerdict::NeedsReview,
                confidence: 0.25,
                rationale: response.text,
            });
        }

        Ok(TriageOutcome {
            verdict: TriageVerdict::NeedsReview,
            confidence: 0.0,
            rationale: "pi-agent-core bridge returned no triage content".to_string(),
        })
    }
}

const TRIAGE_SYSTEM_PROMPT: &str = r#"You are Kuzushi's security triage agent.
Return only JSON matching:
{"verdict":"true_positive|false_positive|needs_review","confidence":0.0-1.0,"rationale":"short evidence-based reason"}."#;

fn triage_prompt(finding: &kuzushi_core::Finding, template: Option<&str>) -> Result<String> {
    let json = serde_json::to_string_pretty(finding).context("Could not serialize finding")?;
    let prefix = template
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(
        "Triage this SAST finding. Be conservative; use needs_review when evidence is incomplete.",
    );
    Ok(format!("{prefix}\n\nFinding JSON:\n{json}"))
}

fn run_bridge(command: &[String], request: &BridgeRequest) -> Result<BridgeResponse> {
    run_bridge_with_cancellation(command, request, None)
}

fn run_bridge_with_cancellation(
    command: &[String],
    request: &BridgeRequest,
    cancellation: Option<&BridgeCancellation>,
) -> Result<BridgeResponse> {
    if cancellation.is_some_and(BridgeCancellation::is_cancelled) {
        anyhow::bail!("pi-agent-core bridge abort requested");
    }

    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Could not start pi-agent-core bridge {}", command[0]))?;

    let stdout = child
        .stdout
        .take()
        .context("Could not open pi-agent-core bridge stdout")?;
    let stderr = child
        .stderr
        .take()
        .context("Could not open pi-agent-core bridge stderr")?;
    let stdout_reader = thread::spawn(move || read_pipe(stdout));
    let stderr_reader = thread::spawn(move || read_pipe(stderr));

    {
        let stdin = child
            .stdin
            .as_mut()
            .context("Could not open pi-agent-core bridge stdin")?;
        let body = serde_json::to_vec(request).context("Could not encode bridge request")?;
        stdin.write_all(&body)?;
    }
    drop(child.stdin.take());

    loop {
        if cancellation.is_some_and(BridgeCancellation::is_cancelled) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            anyhow::bail!("pi-agent-core bridge abort requested");
        }

        if let Some(status) = child
            .try_wait()
            .context("Could not read pi-agent-core bridge status")?
        {
            let stdout = stdout_reader.join().unwrap_or_else(|_| Vec::new());
            let stderr = stderr_reader.join().unwrap_or_else(|_| Vec::new());
            if !status.success() {
                if !stdout.is_empty() {
                    if let Ok(response) = serde_json::from_slice::<BridgeResponse>(&stdout) {
                        return Ok(response);
                    }
                }
                anyhow::bail!(
                    "pi-agent-core bridge exited with {}: {}",
                    status,
                    String::from_utf8_lossy(&stderr)
                );
            }

            return serde_json::from_slice::<BridgeResponse>(&stdout).with_context(|| {
                format!(
                    "Could not parse bridge JSON: {}",
                    String::from_utf8_lossy(&stdout)
                )
            });
        }

        thread::sleep(Duration::from_millis(50));
    }
}

fn read_pipe(mut pipe: impl Read) -> Vec<u8> {
    let mut buffer = Vec::new();
    let _ = pipe.read_to_end(&mut buffer);
    buffer
}

impl BridgeResponse {
    fn into_agent_response(self) -> Result<AgentQueryResponse> {
        if !self.ok {
            anyhow::bail!(
                "pi-agent-core bridge failed: {}",
                self.error.unwrap_or_else(|| "unknown error".to_string())
            );
        }

        Ok(AgentQueryResponse {
            text: self.text.unwrap_or_default(),
            structured: self.structured,
        })
    }
}

fn default_bridge_command(source_root: &Path) -> Vec<String> {
    let source_bridge = source_root.join("scripts").join("pi-agent-core-bridge.mjs");
    if source_bridge.exists() {
        return vec!["node".to_string(), source_bridge.display().to_string()];
    }

    vec![
        "node".to_string(),
        "scripts/pi-agent-core-bridge.mjs".to_string(),
    ]
}

fn clamp_outcome(mut outcome: TriageOutcome) -> TriageOutcome {
    outcome.confidence = outcome.confidence.clamp(0.0, 1.0);
    outcome
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BridgeRequest {
    model: String,
    cwd: String,
    system_prompt: String,
    prompt: String,
    api_key_env: String,
    api_key: Option<String>,
    base_url: Option<String>,
    thinking_level: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BridgeResponse {
    ok: bool,
    text: Option<String>,
    structured: Option<Value>,
    error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{Finding, RuntimeConfig, RuntimeKind, Severity};
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    #[test]
    fn uses_configured_bridge_command() {
        let runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec!["node".to_string(), "bridge.mjs".to_string()]),
        };

        let bridge = PiAgentCoreRuntime::from_runtime_config(&runtime, ".").unwrap();
        assert_eq!(
            bridge.command(),
            &["node".to_string(), "bridge.mjs".to_string()]
        );
    }

    #[test]
    fn bridge_failure_json_is_returned_as_actionable_error() {
        let runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf '%s' '{\"ok\":false,\"error\":\"install @mariozechner/pi-agent-core\"}'; exit 1"
                    .to_string(),
            ]),
        };
        let bridge = PiAgentCoreRuntime::from_runtime_config(&runtime, ".").unwrap();
        let err = bridge
            .triage_finding_blocking(TriageRequest {
                model: "openai:gpt-4.1".to_string(),
                cwd: ".".into(),
                finding: Finding::new_tool(
                    "semgrep",
                    "demo.sql",
                    "src/db.ts",
                    9,
                    Some(9),
                    Severity::High,
                    "SQL injection in search",
                ),
                prompt_template: None,
            })
            .unwrap_err()
            .to_string();

        assert!(err.contains("pi-agent-core bridge failed"));
        assert!(err.contains("install @mariozechner/pi-agent-core"));
    }

    #[cfg(unix)]
    #[test]
    fn cancellable_query_reports_abort_requested_without_waiting_for_bridge_completion() {
        let dir = unique_temp_dir("kuzushi-openai-cancel");
        fs::create_dir_all(&dir).unwrap();
        let bridge = dir.join("sleep-bridge.sh");
        fs::write(
            &bridge,
            "#!/bin/sh\ncat >/dev/null\nsleep 30\nprintf '%s' '{\"ok\":true,\"text\":\"late\"}'\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&bridge).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&bridge, permissions).unwrap();

        let runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec![bridge.display().to_string()]),
        };
        let bridge_runtime = PiAgentCoreRuntime::from_runtime_config(&runtime, &dir).unwrap();
        let cancel = BridgeCancellation::default();
        let worker_cancel = cancel.clone();
        let request = AgentQueryRequest {
            model: "openai:gpt-4.1".to_string(),
            cwd: dir.clone(),
            system_prompt: "system".to_string(),
            prompt: "question".to_string(),
        };

        let started = Instant::now();
        let worker = thread::spawn(move || {
            bridge_runtime.query_blocking_with_cancellation(request, &worker_cancel)
        });
        thread::sleep(Duration::from_millis(150));
        cancel.cancel();

        let err = worker.join().unwrap().unwrap_err().to_string();
        let _ = fs::remove_dir_all(&dir);

        assert!(err.contains("abort requested"));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "cancellation should not wait for bridge script sleep"
        );
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }
}
