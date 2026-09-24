use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_core::{
    runtime::RuntimeCostReport, AgentQueryRequest, AgentQueryResponse, AgentRuntime,
    AgentStructuredOutput, ModelTier, Observed, TriageOutcome, TriageRequest,
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
        self.query_observed_blocking(request)
            .map(Observed::into_value)
    }

    fn query_observed_blocking(
        &self,
        request: AgentQueryRequest,
    ) -> Result<Observed<AgentQueryResponse>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("AnthropicOAuthRuntime: could not start a tokio runtime")?;
        runtime
            .block_on(self.send_messages_observed(request))?
            .try_map(AgentQueryResponse::validate_cost)
    }

    async fn query(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.query_observed(request).await.map(Observed::into_value)
    }

    async fn query_observed(
        &self,
        request: AgentQueryRequest,
    ) -> Result<Observed<AgentQueryResponse>> {
        self.send_messages_observed(request)
            .await?
            .try_map(AgentQueryResponse::validate_cost)
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        self.triage_finding_observed_blocking(request)
            .map(Observed::into_value)
    }

    fn triage_finding_observed_blocking(
        &self,
        request: TriageRequest,
    ) -> Result<Observed<TriageOutcome>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("AnthropicOAuthRuntime: could not start a tokio runtime")?;
        runtime.block_on(self.triage_finding_observed(request))
    }

    async fn triage_finding(&self, request: TriageRequest) -> Result<TriageOutcome> {
        self.triage_finding_observed(request)
            .await
            .map(Observed::into_value)
    }

    async fn triage_finding_observed(
        &self,
        request: TriageRequest,
    ) -> Result<Observed<TriageOutcome>> {
        let prompt = build_triage_prompt(&request)?;
        let response = self
            .send_messages_observed(
                AgentQueryRequest::new(request.model, request.cwd, TRIAGE_SYSTEM_PROMPT, prompt)
                    .with_structured_output(triage_structured_output())
                    .with_temperature(0.0),
            )
            .await?
            .try_map(AgentQueryResponse::validate_cost)?;

        response.try_map(triage_outcome_from_response)
    }
}

pub(crate) fn triage_outcome_from_response(response: AgentQueryResponse) -> Result<TriageOutcome> {
    let response = response.validate_cost()?;
    let call_cost = response.checked_cost_report()?;
    if let Some(structured) = response.structured {
        return structured_triage_outcome(structured, call_cost);
    }
    text_triage_outcome(response, call_cost)
}

pub(crate) fn structured_triage_outcome(
    structured: Value,
    call_cost: RuntimeCostReport,
) -> Result<TriageOutcome> {
    let mut outcome = serde_json::from_value::<TriageOutcome>(structured)
        .map_err(|_| anyhow::anyhow!("Anthropic OAuth triage JSON violated schema"))?;
    apply_call_cost(&mut outcome, call_cost);
    clamp_outcome(outcome).validate_cost()
}

pub(crate) fn text_triage_outcome(
    response: AgentQueryResponse,
    call_cost: RuntimeCostReport,
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
    let mut outcome =
        serde_json::from_str::<TriageOutcome>(strip_whole_json_fence(text)).map_err(|_| {
            anyhow::anyhow!("Anthropic OAuth triage response was not valid triage JSON")
        })?;
    apply_call_cost(&mut outcome, call_cost);
    clamp_outcome(outcome).validate_cost()
}

fn apply_call_cost(outcome: &mut TriageOutcome, call_cost: RuntimeCostReport) {
    outcome.cost_usd = call_cost.observed_usd();
    outcome.cost_usd_exact = call_cost.is_complete();
    outcome.estimated_cost_usd = call_cost.unmetered_estimate_usd();
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
