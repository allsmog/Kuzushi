use std::env;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_core::{
    AgentLoopStep, AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentToolLoopRequest,
    AgentToolPolicy, LoopHistoryEntry, RuntimeConfig, ToolCall, TriageOutcome, TriageRequest,
    TriageVerdict, V2Config,
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
        let bridge_request = BridgeRequest {
            model: request.model,
            cwd: request.cwd.display().to_string(),
            system_prompt: request.system_prompt,
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

        // pi-agent-core bridge doesn't surface token usage in its
        // current schema; cost defaults to 0 here. The native
        // AnthropicOAuthRuntime is the path that populates real cost.
        Ok(AgentQueryResponse {
            text: response.text.unwrap_or_default(),
            structured: response.structured,
            cost_usd: 0.0,
            input_tokens: 0,
            output_tokens: 0,
        })
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        let prompt = triage_prompt(&request.finding, request.prompt_template.as_deref())?;
        let response = self.query_blocking(AgentQueryRequest {
            model: request.model,
            cwd: request.cwd,
            system_prompt: TRIAGE_SYSTEM_PROMPT.to_string(),
            prompt,
            tool_policy: AgentToolPolicy::default(),
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
                ..Default::default()
            });
        }

        Ok(TriageOutcome {
            verdict: TriageVerdict::NeedsReview,
            confidence: 0.0,
            rationale: "pi-agent-core bridge returned no triage content".to_string(),
            ..Default::default()
        })
    }

    fn supports_tools(&self) -> bool {
        true
    }

    fn next_step_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        let bridge_request = NextStepBridgeRequest {
            envelope_type: "next-step",
            model: request.model.clone(),
            cwd: request.cwd.display().to_string(),
            system_prompt: request.system_prompt.clone(),
            messages: build_messages_for_anthropic(&request.prompt, history),
            tools: request
                .tools
                .iter()
                .map(|tool| BridgeTool {
                    name: tool.name.clone(),
                    description: tool.description.clone(),
                    input_schema: tool.input_schema.clone(),
                })
                .collect(),
            max_tokens: 4096,
            api_key_env: self.api_key_env.clone(),
            api_key: self.api_key.clone(),
            base_url: self.base_url.clone(),
        };

        let response = run_next_step_bridge(&self.command, &bridge_request)?;
        if !response.ok {
            anyhow::bail!(
                "pi-agent-core next-step bridge failed: {}",
                response
                    .error
                    .unwrap_or_else(|| "unknown error".to_string())
            );
        }

        match response.step.as_deref() {
            Some("tool_call") => {
                // The bridge currently emits at most one call per
                // step, but the trait now carries `Vec<ToolCall>`.
                // Wrap whatever it returned in a one-element vec.
                let call = response
                    .call
                    .context("next-step: tool_call missing call body")?;
                Ok(AgentLoopStep::ToolCall {
                    calls: vec![ToolCall {
                        name: call.name,
                        input: call.input,
                        call_id: call.call_id,
                    }],
                })
            }
            Some("final") => Ok(AgentLoopStep::Final {
                text: response.text.unwrap_or_default(),
                structured: response.structured,
                cost_usd: response.cost_usd,
            }),
            other => anyhow::bail!(
                "next-step bridge returned unexpected step: {:?}",
                other.unwrap_or("(missing)")
            ),
        }
    }
}

fn build_messages_for_anthropic(initial_prompt: &str, history: &[LoopHistoryEntry]) -> Vec<Value> {
    let mut messages = Vec::with_capacity(history.len() + 1);
    messages.push(serde_json::json!({
        "role": "user",
        "content": initial_prompt,
    }));
    for entry in history {
        match entry {
            LoopHistoryEntry::AssistantToolCall(call) => {
                messages.push(serde_json::json!({
                    "role": "assistant",
                    "content": [{
                        "type": "tool_use",
                        "id": call.call_id,
                        "name": call.name,
                        "input": call.input,
                    }],
                }));
            }
            LoopHistoryEntry::ToolResult(result) => {
                messages.push(serde_json::json!({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": result.call_id,
                        "content": stringify_tool_output(&result.output),
                        "is_error": result.is_error,
                    }],
                }));
            }
            LoopHistoryEntry::AssistantText(text) => {
                messages.push(serde_json::json!({
                    "role": "assistant",
                    "content": text,
                }));
            }
        }
    }
    messages
}

fn stringify_tool_output(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "<non-serialisable>".to_string()),
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
        // A bridge that exits early (e.g. failure case bridges in
        // tests, or production scripts that fast-fail on missing
        // credentials) closes its stdin before we finish writing.
        // BrokenPipe is expected in that path — swallow it and let
        // the wait_with_output below surface the script's actual
        // exit status / stdout.
        if let Err(err) = stdin.write_all(&body) {
            if err.kind() != std::io::ErrorKind::BrokenPipe {
                return Err(err.into());
            }
        }
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NextStepBridgeRequest {
    #[serde(rename = "type")]
    envelope_type: &'static str,
    model: String,
    cwd: String,
    system_prompt: String,
    messages: Vec<Value>,
    tools: Vec<BridgeTool>,
    max_tokens: u32,
    api_key_env: String,
    api_key: Option<String>,
    base_url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BridgeTool {
    name: String,
    description: String,
    input_schema: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NextStepBridgeResponse {
    ok: bool,
    #[serde(default)]
    step: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    structured: Option<Value>,
    #[serde(default)]
    cost_usd: Option<f64>,
    #[serde(default)]
    call: Option<NextStepBridgeCall>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NextStepBridgeCall {
    name: String,
    #[serde(default)]
    input: Value,
    #[serde(rename = "callId")]
    call_id: String,
}

fn run_next_step_bridge(
    command: &[String],
    request: &NextStepBridgeRequest,
) -> Result<NextStepBridgeResponse> {
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "Could not start pi-agent-core next-step bridge {}",
                command[0]
            )
        })?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .context("Could not open pi-agent-core next-step bridge stdin")?;
        let body = serde_json::to_vec(request).context("Could not encode next-step request")?;
        if let Err(err) = stdin.write_all(&body) {
            if err.kind() != std::io::ErrorKind::BrokenPipe {
                return Err(err.into());
            }
        }
    }

    let output = child
        .wait_with_output()
        .context("Could not read pi-agent-core next-step bridge output")?;
    if !output.status.success() {
        if !output.stdout.is_empty() {
            if let Ok(response) = serde_json::from_slice::<NextStepBridgeResponse>(&output.stdout) {
                return Ok(response);
            }
        }
        anyhow::bail!(
            "pi-agent-core next-step bridge exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    serde_json::from_slice::<NextStepBridgeResponse>(&output.stdout).with_context(|| {
        format!(
            "Could not parse next-step bridge JSON: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
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

        assert!(
            err.contains("pi-agent-core bridge failed"),
            "actual err: {err}"
        );
        assert!(
            err.contains("install @mariozechner/pi-agent-core"),
            "actual err: {err}"
        );
    }

    #[test]
    fn next_step_bridge_surfaces_error_payload() {
        use kuzushi_core::AgentTool;

        let runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "ANTHROPIC_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf '%s' '{\"ok\":false,\"error\":\"no Anthropic credentials\"}'; exit 1"
                    .to_string(),
            ]),
        };
        let bridge = PiAgentCoreRuntime::from_runtime_config(&runtime, ".").unwrap();
        let request = AgentToolLoopRequest {
            model: "anthropic:claude-sonnet-4-6".to_string(),
            cwd: ".".into(),
            system_prompt: "sys".to_string(),
            prompt: "p".to_string(),
            tools: vec![AgentTool {
                name: "x".to_string(),
                description: String::new(),
                input_schema: serde_json::json!({"type":"object"}),
            }],
            max_steps: 1,
        };
        let err = bridge
            .next_step_blocking(&request, &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("next-step"), "{err}");
        assert!(err.contains("no Anthropic credentials"), "{err}");
    }
}
