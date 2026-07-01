use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_core::{
    AgentQueryRequest, AgentQueryResponse, AgentRuntime, ModelTier, TriageOutcome, TriageRequest,
    TriageVerdict,
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
            .send_messages(AgentQueryRequest::new(
                request.model,
                request.cwd,
                TRIAGE_SYSTEM_PROMPT,
                prompt,
            ))
            .await?;

        Ok(triage_outcome_from_response(response))
    }
}

pub(crate) fn triage_outcome_from_response(response: AgentQueryResponse) -> TriageOutcome {
    let call_cost = response.cost_usd;
    if let Some(outcome) = structured_triage_outcome(response.structured.as_ref(), call_cost) {
        return outcome;
    }
    text_triage_outcome(response.text, call_cost)
}

pub(crate) fn structured_triage_outcome(
    structured: Option<&Value>,
    call_cost: f64,
) -> Option<TriageOutcome> {
    let mut outcome = serde_json::from_value::<TriageOutcome>(structured?.clone()).ok()?;
    outcome.cost_usd = call_cost;
    Some(clamp_outcome(outcome))
}

pub(crate) fn text_triage_outcome(text: String, call_cost: f64) -> TriageOutcome {
    if text.is_empty() {
        return TriageOutcome {
            verdict: TriageVerdict::NeedsReview,
            confidence: 0.0,
            rationale: "AnthropicOAuthRuntime returned no triage content".to_string(),
            cost_usd: call_cost,
        };
    }
    if let Ok(mut outcome) = serde_json::from_str::<TriageOutcome>(&text) {
        outcome.cost_usd = call_cost;
        return clamp_outcome(outcome);
    }
    TriageOutcome {
        verdict: TriageVerdict::NeedsReview,
        confidence: 0.25,
        rationale: text,
        cost_usd: call_cost,
    }
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
