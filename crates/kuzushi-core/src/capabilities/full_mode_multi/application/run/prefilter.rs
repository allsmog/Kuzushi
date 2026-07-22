use crate::agent_router::RoutedRuntime;
use crate::capabilities::full_mode_multi::application::chunk_prompt::render_chunk_prompt;
use crate::capabilities::full_mode_multi::domain::{
    ChunkPlan, FullModeConfig, PrefilteredChunk, DEFAULT_PREFILTER_DEPOSIT_USD,
    DEFAULT_PREFILTER_SKIP_BELOW,
};
use crate::runtime::{AgentQueryRequest, RuntimeCostReport};
use crate::semantic_cache::SemanticCache;
use crate::spend::{Operation, SpendLimiter, SpendTicket};
use crate::structured_output::{
    query_cached_structured_json_with_cost, StructuredJsonContract, StructuredOutputError,
};
use anyhow::{Context, Result};
use serde::Deserialize;

/// The router judges the chunk's risk surface only — it must not attempt the
/// deep review itself, and a wrong "boring" verdict is recoverable because
/// the skip is recorded, so the bar it sets is deliberately low.
const PREFILTER_SYSTEM_PROMPT: &str = r#"You are Kuzushi's scan router. You see one chunk of files
from a larger codebase. Decide how much a deep security review of THIS chunk is worth.

Score 0-10:
- 0-2: no attacker-relevant surface — generated code, pure data or constants, build glue,
  test fixtures, documentation.
- 3-5: ordinary application logic that handles little or no untrusted input.
- 6-10: parses, decodes, or transports untrusted input; does pointer or length arithmetic;
  allocates from computed sizes; spawns processes or builds commands/queries/paths from
  variables; touches auth, crypto, or serialization.

Judge the code's risk surface, not its style or quality. When torn between two bands,
score the higher one — a wasted deep read is cheaper than a missed vulnerable chunk.

Return ONLY JSON: {"score": int, "reason": "one short line naming what drove the score"}."#;

pub(super) struct PrefilterOutcome {
    /// `Some` when the chunk scored below the threshold and must skip the
    /// deep scan; `None` means dispatch it.
    pub(super) skip: Option<PrefilteredChunk>,
    pub(super) cost_usd: Option<f64>,
    pub(super) observed_cost_usd: f64,
}

#[derive(Debug, Deserialize)]
struct PrefilterVerdict {
    score: u8,
    #[serde(default)]
    reason: String,
}

pub(super) fn prefilter_full_mode_chunk(
    runtime: &RoutedRuntime<'_>,
    spend: Option<&SpendLimiter>,
    cfg: &FullModeConfig,
    chunk: &ChunkPlan,
    prefilter_model: &str,
    cache: Option<&SemanticCache>,
) -> Result<PrefilterOutcome> {
    let prompt = render_chunk_prompt(&cfg.workspace_root, chunk)?;
    let ticket = reserve_prefilter_budget(spend)?;
    let result = query_prefilter_verdict(runtime, cfg, prefilter_model, prompt, cache);
    let cost = prefilter_cost_report(&result)?;
    settle_prefilter_budget(spend, ticket, cost.exact_usd())?;
    let verdict = result?.costed.value;
    let threshold = cfg
        .prefilter_skip_below
        .unwrap_or(DEFAULT_PREFILTER_SKIP_BELOW);
    let skip = (verdict.score < threshold).then_some(PrefilteredChunk {
        chunk_id: chunk.id,
        score: verdict.score,
        reason: verdict.reason,
    });
    Ok(PrefilterOutcome {
        skip,
        cost_usd: cost.exact_usd(),
        observed_cost_usd: cost.observed_usd(),
    })
}

fn query_prefilter_verdict(
    runtime: &RoutedRuntime<'_>,
    cfg: &FullModeConfig,
    model: &str,
    prompt: String,
    cache: Option<&SemanticCache>,
) -> Result<crate::structured_output::CachedStructuredJson<PrefilterVerdict>> {
    let request = AgentQueryRequest::new(
        model.to_string(),
        cfg.workspace_root.clone(),
        PREFILTER_SYSTEM_PROMPT.to_string(),
        prompt,
    );
    query_cached_structured_json_with_cost(
        cache,
        runtime,
        request,
        StructuredJsonContract::new(
            "full-mode-multi:prefilter",
            "FullModePrefilterVerdict",
            prefilter_schema(),
        ),
        parse_prefilter_verdict,
    )
}

fn prefilter_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": ["score", "reason"],
        "additionalProperties": false,
        "properties": {
            "score": {"type": "integer", "minimum": 0, "maximum": 10},
            "reason": {"type": "string"}
        }
    })
}

fn parse_prefilter_verdict(value: serde_json::Value) -> Result<PrefilterVerdict> {
    let verdict: PrefilterVerdict = serde_json::from_value(value)
        .context("full-mode-multi prefilter output must be {\"score\": int, \"reason\": string}")?;
    anyhow::ensure!(
        verdict.score <= 10,
        "prefilter score {} is outside 0-10",
        verdict.score
    );
    Ok(verdict)
}

fn reserve_prefilter_budget(spend: Option<&SpendLimiter>) -> Result<Option<SpendTicket>> {
    match spend {
        Some(limiter) => limiter
            .deposit(Operation::FullModeMulti, DEFAULT_PREFILTER_DEPOSIT_USD)
            .context("full_mode_multi: prefilter deposit failed")
            .map(Some),
        None => Ok(None),
    }
}

fn settle_prefilter_budget(
    spend: Option<&SpendLimiter>,
    ticket: Option<SpendTicket>,
    actual_cost: Option<f64>,
) -> Result<()> {
    if let (Some(limiter), Some(ticket), Some(actual_cost)) = (spend, ticket, actual_cost) {
        limiter.refund(ticket, actual_cost)?;
    }
    Ok(())
}

fn prefilter_cost_report(
    result: &Result<crate::structured_output::CachedStructuredJson<PrefilterVerdict>>,
) -> Result<RuntimeCostReport> {
    match result {
        Ok(cached) => cached.costed.cost_report(),
        Err(error) => Ok(error
            .downcast_ref::<StructuredOutputError>()
            .map(StructuredOutputError::cost_report)
            .unwrap_or(RuntimeCostReport::INCOMPLETE_ZERO)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn verdict_parses_and_rejects_out_of_range_scores() {
        let verdict = parse_prefilter_verdict(json!({"score": 7, "reason": "parses input"}))
            .expect("in-range verdict must parse");
        assert_eq!(verdict.score, 7);
        assert_eq!(verdict.reason, "parses input");

        assert!(parse_prefilter_verdict(json!({"score": 11, "reason": "x"})).is_err());
        assert!(parse_prefilter_verdict(json!({"reason": "missing score"})).is_err());
    }

    #[test]
    fn system_prompt_keeps_the_score_contract_fields() {
        for token in ["score", "reason", "0-10"] {
            assert!(
                PREFILTER_SYSTEM_PROMPT.contains(token),
                "prefilter prompt drifted: missing {token:?}"
            );
        }
    }
}
