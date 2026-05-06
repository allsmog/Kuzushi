use std::env;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_core::{
    append_bootstrap_context, detect_refusal_in_text, AgentQueryRequest, AgentQueryResponse,
    AgentRuntime, AgentToolPolicy, RuntimeConfig, TriageOutcome, TriageRequest, TriageVerdict,
    V2Config,
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
}

#[async_trait]
impl AgentRuntime for PiAgentCoreRuntime {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        let system_prompt = append_bootstrap_context(&request.system_prompt, &request.cwd);
        let bridge_request = BridgeRequest {
            model: request.model,
            cwd: request.cwd.display().to_string(),
            system_prompt,
            prompt: request.prompt,
            api_key_env: self.api_key_env.clone(),
            api_key: self.api_key.clone(),
            base_url: self.base_url.clone(),
            thinking_level: self.thinking_level.clone(),
            tool_policy: request.tool_policy,
        };

        let response = run_bridge(&self.command, &bridge_request)?;
        if !response.ok {
            anyhow::bail!(
                "pi-agent-core bridge failed: {}",
                response
                    .error
                    .unwrap_or_else(|| "unknown error".to_string())
            );
        }

        Ok(AgentQueryResponse {
            text: response.text.unwrap_or_default(),
            structured: response.structured,
        })
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        let prompt = triage_prompt(&request.finding, request.prompt_template.as_deref())?;
        let response = self.query_blocking(AgentQueryRequest::new(
            request.model,
            request.cwd,
            TRIAGE_SYSTEM_PROMPT.to_string(),
            prompt,
        ))?;

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
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Could not start pi-agent-core bridge {}", command[0]))?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .context("Could not open pi-agent-core bridge stdin")?;
        let body = serde_json::to_vec(request).context("Could not encode bridge request")?;
        stdin.write_all(&body)?;
    }

    let output = child
        .wait_with_output()
        .context("Could not read pi-agent-core bridge output")?;
    if !output.status.success() {
        if !output.stdout.is_empty() {
            if let Ok(response) = serde_json::from_slice::<BridgeResponse>(&output.stdout) {
                return Ok(response);
            }
        }
        anyhow::bail!(
            "pi-agent-core bridge exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    serde_json::from_slice::<BridgeResponse>(&output.stdout).with_context(|| {
        format!(
            "Could not parse bridge JSON: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
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
    annotate_refusal(&mut outcome);
    outcome
}

/// If the model's rationale contains refusal-language ("I cannot",
/// "skipped because", …), prepend a ⚠ marker so it surfaces in every
/// downstream channel (shell logs, report.md, JSON output) without any
/// caller change. Idempotent — re-applying does not stack markers.
fn annotate_refusal(outcome: &mut TriageOutcome) {
    if outcome.rationale.starts_with("⚠ refusal") {
        return;
    }
    let report = detect_refusal_in_text(&outcome.rationale);
    if report.refused {
        outcome.rationale = format!("⚠ refusal — {}", outcome.rationale.trim_start());
    }
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
    tool_policy: AgentToolPolicy,
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
}
