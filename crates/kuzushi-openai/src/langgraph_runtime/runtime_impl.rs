use anyhow::Result;
use async_trait::async_trait;
use kuzushi_core::{
    AgentLoopStep, AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentStructuredOutput,
    AgentToolLoopRequest, LoopHistoryEntry, TriageOutcome, TriageRequest,
};

use super::bridge_payloads::{BridgeRequest, BridgeResponse, LANGGRAPH_BRIDGE_PROTOCOL_VERSION};
use super::bridge_process::{public_bridge_error, run_bridge};
use super::next_step_bridge::next_step_blocking as run_next_step_blocking;
use super::next_step_bridge::preflight_tool_loop_blocking as run_preflight_tool_loop_blocking;
use super::runtime_config::LangGraphRuntime;
use super::triage::{
    clamp_outcome, normalize_triage_confidence, triage_prompt, triage_system_prompt,
};
use std::thread;
use std::time::Duration;

fn clamp_token_count_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[async_trait]
impl AgentRuntime for LangGraphRuntime {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        let credential = self.credential_for_model(&request.model)?;
        let structured_output = request.structured_output;
        let runtime_options = request.runtime_options;
        let thinking_level = request
            .thinking_level
            .or_else(|| self.thinking_level.clone());
        let bridge_request = BridgeRequest {
            protocol_version: LANGGRAPH_BRIDGE_PROTOCOL_VERSION,
            model: request.model,
            cwd: request.cwd.display().to_string(),
            system_prompt: request.system_prompt,
            prompt: request.prompt,
            structured_output,
            api_key_env: credential.env,
            api_key: credential.value,
            base_url: self.base_url.clone(),
            thinking_level,
            max_output_tokens: request.max_output_tokens,
            tool_policy: request.tool_policy,
            runtime_options,
            temperature: request.temperature,
        };

        let response = run_bridge_with_transport_retries(
            &self.command,
            bridge_request,
            self.cancellation.as_ref(),
        )?;

        Ok(AgentQueryResponse {
            text: response.text.unwrap_or_default(),
            structured: response.structured,
            cost_usd: response.cost_usd.unwrap_or(0.0),
            input_tokens: clamp_token_count_u32(response.input_tokens.unwrap_or(0)),
            output_tokens: clamp_token_count_u32(response.output_tokens.unwrap_or(0)),
            truncated: response.truncated,
            stop_reason: response.stop_reason,
        })
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        let prompt = triage_prompt(&request.finding, request.prompt_template.as_deref())?;
        let response = self.query_blocking(
            AgentQueryRequest::new(request.model, request.cwd, triage_system_prompt(), prompt)
                .with_structured_output(triage_structured_output())
                .with_temperature(0.0),
        )?;
        triage_outcome_from_response(response)
    }

    fn supports_tools(&self) -> bool {
        // Anthropic-only in this version (bridge enforces). Routed
        // queries with non-Anthropic models will surface a clear error
        // from the bridge itself.
        true
    }

    fn next_step_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        run_next_step_blocking(self, request, history)
    }

    fn preflight_tool_loop_blocking(&self, request: &AgentToolLoopRequest) -> Result<()> {
        run_preflight_tool_loop_blocking(self, request)
    }
}

pub(crate) struct ModelCredential {
    pub(crate) env: String,
    pub(crate) value: Option<String>,
}

impl LangGraphRuntime {
    pub(crate) fn credential_for_model(&self, model: &str) -> Result<ModelCredential> {
        let env = kuzushi_core::runtime::bridge_api_key_env_for_model(model, &self.api_key_env)?;
        let value = if env == self.api_key_env {
            self.api_key.clone()
        } else {
            std::env::var(&env)
                .ok()
                .filter(|value| !value.trim().is_empty())
        };
        Ok(ModelCredential { env, value })
    }
}

fn run_bridge_with_transport_retries(
    command: &[String],
    request: BridgeRequest,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
) -> Result<BridgeResponse> {
    const ATTEMPTS: usize = 3;
    let mut last_error: Option<anyhow::Error> = None;
    for attempt in 1..=ATTEMPTS {
        ensure_not_cancelled(cancellation)?;
        match bridge_attempt_outcome(
            run_bridge(command, &request, cancellation),
            attempt == ATTEMPTS,
        )? {
            BridgeAttempt::Success(response) => return Ok(response),
            BridgeAttempt::Retry(error) => last_error = Some(error),
        }
        ensure_not_cancelled(cancellation)?;
        thread::sleep(Duration::from_millis(retry_delay_ms(attempt)));
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("LangGraph bridge failed")))
}

fn ensure_not_cancelled(cancellation: Option<&kuzushi_core::ScanCancellation>) -> Result<()> {
    if cancellation.is_some_and(kuzushi_core::ScanCancellation::is_cancelled) {
        anyhow::bail!("LangGraph bridge cancelled");
    }
    Ok(())
}

enum BridgeAttempt {
    Success(BridgeResponse),
    Retry(anyhow::Error),
}

fn bridge_attempt_outcome(
    result: Result<BridgeResponse>,
    final_attempt: bool,
) -> Result<BridgeAttempt> {
    match result {
        Ok(response) if response.ok => Ok(BridgeAttempt::Success(response)),
        Ok(response) => bridge_response_error(response, final_attempt),
        Err(error) => bridge_transport_error(error, final_attempt),
    }
}

fn bridge_response_error(response: BridgeResponse, final_attempt: bool) -> Result<BridgeAttempt> {
    let message = response
        .error
        .unwrap_or_else(|| "unknown error".to_string());
    if final_attempt || !is_transient_bridge_error(&message) {
        anyhow::bail!("LangGraph bridge failed: {}", public_bridge_error(&message));
    }
    Ok(BridgeAttempt::Retry(anyhow::anyhow!(
        "LangGraph bridge failed: {}",
        public_bridge_error(&message)
    )))
}

fn bridge_transport_error(error: anyhow::Error, final_attempt: bool) -> Result<BridgeAttempt> {
    let message = error.to_string();
    if final_attempt || !is_transient_bridge_error(&message) {
        anyhow::bail!("{}", public_bridge_error(&message));
    }
    Ok(BridgeAttempt::Retry(anyhow::anyhow!(
        "{}",
        public_bridge_error(&message)
    )))
}

pub(super) fn retry_delay_ms(attempt: usize) -> u64 {
    match attempt {
        0 | 1 => 250,
        2 => 500,
        _ => 1_000,
    }
}

pub(super) fn is_transient_bridge_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    [
        "websocket closed 1006",
        "websocket closed",
        "socket hang up",
        "econnreset",
        "etimedout",
        "network error",
        "fetch failed",
        "429",
        "rate limit",
        "temporarily unavailable",
        "internal server error",
        "bad gateway",
        "service unavailable",
        "gateway timeout",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

pub(crate) fn triage_outcome_from_response(response: AgentQueryResponse) -> Result<TriageOutcome> {
    let call_cost = response.cost_usd;
    if let Some(structured) = response.structured {
        return structured_triage_outcome(structured, call_cost);
    }
    text_triage_outcome(response, call_cost)
}

fn structured_triage_outcome(
    mut structured: serde_json::Value,
    call_cost: f64,
) -> Result<TriageOutcome> {
    normalize_triage_confidence(&mut structured);
    let mut outcome = serde_json::from_value::<TriageOutcome>(structured)
        .map_err(|error| anyhow::anyhow!("LangGraph triage JSON violated schema: {error}"))?;
    outcome.cost_usd = call_cost;
    Ok(clamp_outcome(outcome))
}

fn text_triage_outcome(response: AgentQueryResponse, call_cost: f64) -> Result<TriageOutcome> {
    if response.truncated {
        let stop_reason = response.stop_reason.as_deref().unwrap_or("length");
        anyhow::bail!(
            "LangGraph triage response was truncated (stopReason: {stop_reason:?}); refusing to synthesize a verdict"
        );
    }
    let text = response.text.trim();
    if text.is_empty() {
        anyhow::bail!("LangGraph bridge returned no triage content");
    }
    let mut value = serde_json::from_str::<serde_json::Value>(strip_whole_json_fence(text))
        .map_err(|error| {
            anyhow::anyhow!(
                "LangGraph triage response was not valid triage JSON: {error}; raw response: {text}"
            )
        })?;
    normalize_triage_confidence(&mut value);
    let mut outcome = serde_json::from_value::<TriageOutcome>(value).map_err(|error| {
        anyhow::anyhow!(
            "LangGraph triage response violated triage schema: {error}; raw response: {text}"
        )
    })?;
    outcome.cost_usd = call_cost;
    Ok(clamp_outcome(outcome))
}

fn strip_whole_json_fence(text: &str) -> &str {
    let Some(without_open) = text.strip_prefix("```") else {
        return text;
    };
    let without_lang = without_open
        .strip_prefix("json")
        .or_else(|| without_open.strip_prefix("JSON"))
        .unwrap_or(without_open)
        .trim_start();
    without_lang
        .strip_suffix("```")
        .map(str::trim)
        .unwrap_or(text)
}

fn triage_structured_output() -> AgentStructuredOutput {
    AgentStructuredOutput::json_schema(
        "kuzushi_triage_outcome",
        serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["verdict", "confidence", "rationale"],
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["true_positive", "false_positive", "needs_review"]
                },
                "confidence": {
                    "oneOf": [
                        {"type": "number", "minimum": 0.0, "maximum": 1.0},
                        {"type": "string", "enum": ["high", "medium", "low"]}
                    ]
                },
                "rationale": {"type": "string"}
            }
        }),
    )
}
