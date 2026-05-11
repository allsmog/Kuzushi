use anyhow::Result;
use async_trait::async_trait;
use kuzushi_core::{
    AgentLoopStep, AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentToolLoopRequest,
    LoopHistoryEntry, TriageOutcome, TriageRequest, TriageVerdict,
};

use super::bridge_payloads::BridgeRequest;
use super::bridge_process::run_bridge;
use super::next_step_bridge::next_step_blocking as run_next_step_blocking;
use super::runtime_config::PiAgentCoreRuntime;
use super::triage::{clamp_outcome, fallback_triage_outcome, triage_prompt, TRIAGE_SYSTEM_PROMPT};

#[async_trait]
impl AgentRuntime for PiAgentCoreRuntime {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        let structured_output = request.structured_output;
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
            truncated: response.truncated,
            stop_reason: response.stop_reason,
            ..Default::default()
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
