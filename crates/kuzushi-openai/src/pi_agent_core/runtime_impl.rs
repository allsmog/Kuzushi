use anyhow::Result;
use async_trait::async_trait;
use kuzushi_core::{
    AgentLoopStep, AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentToolLoopRequest,
    LoopHistoryEntry, TriageOutcome, TriageRequest, TriageVerdict,
};

use super::bridge_payloads::BridgeRequest;
use super::bridge_process::run_bridge;
use super::next_step_bridge::next_step_blocking as run_next_step_blocking;
use super::next_step_bridge::preflight_tool_loop_blocking as run_preflight_tool_loop_blocking;
use super::runtime_config::PiAgentCoreRuntime;
use super::triage::{clamp_outcome, fallback_triage_outcome, triage_prompt, TRIAGE_SYSTEM_PROMPT};
use std::thread;
use std::time::Duration;

fn clamp_token_count_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[async_trait]
impl AgentRuntime for PiAgentCoreRuntime {
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
) -> Result<super::bridge_payloads::BridgeResponse> {
    const ATTEMPTS: usize = 3;
    let mut last_error: Option<anyhow::Error> = None;
    for attempt in 1..=ATTEMPTS {
        match run_bridge(command, &request) {
            Ok(response) if response.ok => return Ok(response),
            Ok(response) => {
                let message = response
                    .error
                    .unwrap_or_else(|| "unknown error".to_string());
                if !is_transient_bridge_error(&message) || attempt == ATTEMPTS {
                    anyhow::bail!("pi-agent-core bridge failed: {message}");
                }
                last_error = Some(anyhow::anyhow!("pi-agent-core bridge failed: {message}"));
            }
            Err(error) => {
                let message = error.to_string();
                if !is_transient_bridge_error(&message) || attempt == ATTEMPTS {
                    return Err(error);
                }
                last_error = Some(error);
            }
        }
        thread::sleep(Duration::from_millis(retry_delay_ms(attempt)));
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("pi-agent-core bridge failed")))
}

fn retry_delay_ms(attempt: usize) -> u64 {
    match attempt {
        0 | 1 => 250,
        2 => 500,
        _ => 1_000,
    }
}

fn is_transient_bridge_error(message: &str) -> bool {
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
    structured_triage_outcome(response.structured)
        .or_else(|| text_triage_outcome(response.text))
        .unwrap_or_else(empty_triage_outcome)
}

fn structured_triage_outcome(structured: Option<serde_json::Value>) -> Option<TriageOutcome> {
    let structured = structured?;
    serde_json::from_value::<TriageOutcome>(structured)
        .ok()
        .map(clamp_outcome)
}

fn text_triage_outcome(text: String) -> Option<TriageOutcome> {
    if text.is_empty() {
        return None;
    }
    Some(parsed_text_triage_outcome(&text).unwrap_or_else(|| fallback_triage_outcome(text)))
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
        rationale: "pi-agent-core bridge returned no triage content".to_string(),
        ..Default::default()
    }
}
