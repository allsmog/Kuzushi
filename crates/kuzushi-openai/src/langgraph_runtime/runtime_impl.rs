use anyhow::Result;
use async_trait::async_trait;
use kuzushi_core::{
    AgentLoopStep, AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentToolLoopRequest,
    LoopHistoryEntry, TriageOutcome, TriageRequest, TriageVerdict,
};

use super::bridge_payloads::{BridgeRequest, BridgeResponse};
use super::bridge_process::{public_bridge_error, run_bridge};
use super::next_step_bridge::next_step_blocking as run_next_step_blocking;
use super::next_step_bridge::preflight_tool_loop_blocking as run_preflight_tool_loop_blocking;
use super::runtime_config::LangGraphRuntime;
use super::triage::{clamp_outcome, fallback_triage_outcome, triage_prompt, TRIAGE_SYSTEM_PROMPT};
use std::thread;
use std::time::Duration;

fn clamp_token_count_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[async_trait]
impl AgentRuntime for LangGraphRuntime {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        let structured_output = request.structured_output;
        let runtime_options = request.runtime_options;
        let thinking_level = request
            .thinking_level
            .or_else(|| self.thinking_level.clone());
        let bridge_request = BridgeRequest {
            model: request.model,
            cwd: request.cwd.display().to_string(),
            system_prompt: request.system_prompt,
            prompt: request.prompt,
            structured_output,
            api_key_env: self.api_key_env.clone(),
            api_key: self.api_key.clone(),
            base_url: self.base_url.clone(),
            thinking_level,
            max_output_tokens: request.max_output_tokens,
            tool_policy: request.tool_policy,
            runtime_options,
            temperature: request.temperature,
        };

        let response = run_bridge_with_transport_retries(&self.command, bridge_request)?;

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
        let response = self.query_blocking(AgentQueryRequest::new(
            request.model,
            request.cwd,
            TRIAGE_SYSTEM_PROMPT.to_string(),
            prompt,
        ))?;
        Ok(triage_outcome_from_response(response))
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

fn run_bridge_with_transport_retries(
    command: &[String],
    request: BridgeRequest,
) -> Result<BridgeResponse> {
    const ATTEMPTS: usize = 3;
    let mut last_error: Option<anyhow::Error> = None;
    for attempt in 1..=ATTEMPTS {
        match bridge_attempt_outcome(run_bridge(command, &request), attempt == ATTEMPTS)? {
            BridgeAttempt::Success(response) => return Ok(response),
            BridgeAttempt::Retry(error) => last_error = Some(error),
        }
        thread::sleep(Duration::from_millis(retry_delay_ms(attempt)));
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("LangGraph bridge failed")))
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

fn triage_outcome_from_response(response: AgentQueryResponse) -> TriageOutcome {
    let call_cost = response.cost_usd;
    structured_triage_outcome(response.structured, call_cost)
        .or_else(|| text_triage_outcome(response.text, call_cost))
        .unwrap_or_else(empty_triage_outcome)
}

fn structured_triage_outcome(
    structured: Option<serde_json::Value>,
    call_cost: f64,
) -> Option<TriageOutcome> {
    let structured = structured?;
    serde_json::from_value::<TriageOutcome>(structured)
        .ok()
        .map(|mut outcome| {
            outcome.cost_usd = call_cost;
            clamp_outcome(outcome)
        })
}

fn text_triage_outcome(text: String, call_cost: f64) -> Option<TriageOutcome> {
    if text.is_empty() {
        return None;
    }
    let mut outcome =
        parsed_text_triage_outcome(&text).unwrap_or_else(|| fallback_triage_outcome(text));
    outcome.cost_usd = call_cost;
    Some(outcome)
}

fn parsed_text_triage_outcome(text: &str) -> Option<TriageOutcome> {
    serde_json::from_str::<TriageOutcome>(text)
        .ok()
        .map(clamp_outcome)
}

fn empty_triage_outcome() -> TriageOutcome {
    TriageOutcome {
        verdict: TriageVerdict::NeedsReview,
        confidence: 0.0,
        rationale: "LangGraph bridge returned no triage content".to_string(),
        ..Default::default()
    }
}
