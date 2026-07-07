use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_core::{
    AgentLoopStep, AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentStructuredOutput,
    AgentToolLoopRequest, LoopHistoryEntry, ModelTier, TriageOutcome, TriageRequest,
};
use serde_json::Value;

use super::options::AnthropicOAuthRuntime;
use super::response::anthropic_model_for_tier;

pub(crate) const TRIAGE_SYSTEM_PROMPT: &str = "You are Kuzushi's security triage agent. \
Reply only with JSON of the shape \
{\"verdict\":\"true_positive|false_positive|needs_review\",\"confidence\":0.0-1.0,\"rationale\":\"<short evidence-based reason>\"}.";

#[async_trait]
impl AgentRuntime for AnthropicOAuthRuntime {
    fn model_for_tier(&self, tier: ModelTier, configured: &str) -> String {
        anthropic_model_for_tier(tier, configured)
    }

    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("AnthropicOAuthRuntime: could not start a tokio runtime")?;
        runtime.block_on(self.send_messages(request))
    }

    async fn query(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.send_messages(request).await
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("AnthropicOAuthRuntime: could not start a tokio runtime")?;
        runtime.block_on(self.triage_finding(request))
    }

    async fn triage_finding(&self, request: TriageRequest) -> Result<TriageOutcome> {
        let prompt = build_triage_prompt(&request)?;
        let response = self
            .send_messages(
                AgentQueryRequest::new(request.model, request.cwd, TRIAGE_SYSTEM_PROMPT, prompt)
                    .with_structured_output(triage_structured_output())
                    .with_temperature(0.0),
            )
            .await?;

        triage_outcome_from_response(response)
    }

    fn supports_tools(&self) -> bool {
        // Native Anthropic Messages tool-use loop (see `tool_loop.rs`). Reaches
        // parity with the LangGraph bridge's `next-step` envelope for
        // Anthropic-backed models.
        true
    }

    fn next_step_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        // Mirror `query_blocking`: the shared driver reaches this via
        // `block_in_place`, so a fresh current-thread runtime can drive the
        // single async round-trip without nesting inside another executor.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("AnthropicOAuthRuntime: could not start a tokio runtime")?;
        runtime.block_on(self.run_tool_loop_step(request, history))
    }
}

pub(crate) fn triage_outcome_from_response(response: AgentQueryResponse) -> Result<TriageOutcome> {
    let call_cost = response.cost_usd;
    if let Some(structured) = response.structured {
        return structured_triage_outcome(structured, call_cost);
    }
    text_triage_outcome(response, call_cost)
}

pub(crate) fn structured_triage_outcome(
    structured: Value,
    call_cost: f64,
) -> Result<TriageOutcome> {
    let mut outcome = serde_json::from_value::<TriageOutcome>(structured)
        .map_err(|error| anyhow::anyhow!("Anthropic OAuth triage JSON violated schema: {error}"))?;
    outcome.cost_usd = call_cost;
    Ok(clamp_outcome(outcome))
}

pub(crate) fn text_triage_outcome(
    response: AgentQueryResponse,
    call_cost: f64,
) -> Result<TriageOutcome> {
    if response.truncated {
        let stop_reason = response.stop_reason.as_deref().unwrap_or("max_tokens");
        anyhow::bail!(
            "Anthropic OAuth triage response was truncated (stopReason: {stop_reason:?}); refusing to synthesize a verdict"
        );
    }
    let text = response.text.trim();
    if text.is_empty() {
        anyhow::bail!("AnthropicOAuthRuntime returned no triage content");
    }
    let mut outcome = serde_json::from_str::<TriageOutcome>(strip_whole_json_fence(text))
        .map_err(|error| {
            anyhow::anyhow!(
                "Anthropic OAuth triage response was not valid triage JSON: {error}; raw response: {text}"
            )
        })?;
    outcome.cost_usd = call_cost;
    Ok(clamp_outcome(outcome))
}

pub(crate) fn build_triage_prompt(request: &TriageRequest) -> Result<String> {
    crate::triage_prompt::compact_triage_prompt(
        &request.finding,
        request.prompt_template.as_deref(),
    )
}

pub(crate) fn clamp_outcome(mut outcome: TriageOutcome) -> TriageOutcome {
    outcome.confidence = outcome.confidence.clamp(0.0, 1.0);
    outcome
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
                "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "rationale": {"type": "string"}
            }
        }),
    )
}
