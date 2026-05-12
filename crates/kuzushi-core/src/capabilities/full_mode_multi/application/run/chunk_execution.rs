use crate::agent_router::RoutedRuntime;
use crate::capabilities::full_mode_multi::application::chunk_prompt::{
    full_mode_findings_schema, parse_chunk_value, render_chunk_prompt,
};
use crate::capabilities::full_mode_multi::domain::{ChunkPlan, FullModeConfig};
use crate::findings::Finding;
use crate::runtime::AgentQueryRequest;
use crate::spend::{Operation, SpendLimiter, SpendTicket};
use crate::structured_output::{query_required_structured_json, StructuredJsonContract};
use anyhow::{Context, Result};

pub(super) struct FullModeChunkResult {
    pub(super) succeeded: bool,
    pub(super) findings: Vec<Finding>,
    pub(super) cost_usd: f64,
    /// Full anyhow chain string for a failed chunk. `None` for successes.
    /// The dispatcher keeps the first one and surfaces it to the operator
    /// so we don't repeat the "27 chunks failed, no diagnostic info" trap.
    pub(super) error: Option<String>,
}

pub(super) fn run_full_mode_chunk(
    runtime: &RoutedRuntime,
    spend: Option<&SpendLimiter>,
    cfg: &FullModeConfig,
    chunk: &ChunkPlan,
    model: &str,
    system_prompt: &str,
) -> Result<FullModeChunkResult> {
    let ticket = reserve_full_mode_chunk_budget(spend, cfg.deposit_usd_per_chunk)?;
    let result = query_full_mode_chunk(runtime, cfg, chunk, model, system_prompt);
    let actual_cost = successful_chunk_cost(&result, cfg.deposit_usd_per_chunk);
    refund_full_mode_chunk_budget(spend, ticket, actual_cost)?;
    Ok(chunk_result_from_query(result, actual_cost))
}

fn reserve_full_mode_chunk_budget(
    spend: Option<&SpendLimiter>,
    deposit_usd: f64,
) -> Result<Option<SpendTicket>> {
    match spend {
        Some(limiter) => limiter
            .deposit(Operation::FullModeMulti, deposit_usd)
            .context("full_mode_multi: deposit failed")
            .map(Some),
        None => Ok(None),
    }
}

fn query_full_mode_chunk(
    runtime: &RoutedRuntime,
    cfg: &FullModeConfig,
    chunk: &ChunkPlan,
    model: &str,
    system_prompt: &str,
) -> Result<Vec<Finding>> {
    let prompt = render_chunk_prompt(&cfg.workspace_root, chunk)?;
    if let Ok(findings) =
        query_full_mode_chunk_with_prompt(runtime, cfg, model, system_prompt, prompt.clone())
    {
        return Ok(findings);
    }
    let repair_prompt = format!(
        "{prompt}\n\nIMPORTANT: return strict JSON only that matches FullModeFindingArray. \
         No prose, no markdown fences, no commentary."
    );
    query_full_mode_chunk_with_prompt(runtime, cfg, model, system_prompt, repair_prompt)
}

fn query_full_mode_chunk_with_prompt(
    runtime: &RoutedRuntime,
    cfg: &FullModeConfig,
    model: &str,
    system_prompt: &str,
    prompt: String,
) -> Result<Vec<Finding>> {
    let request = AgentQueryRequest::new(
        model.to_string(),
        cfg.workspace_root.clone(),
        system_prompt.to_string(),
        prompt,
    );

    query_required_structured_json(
        runtime,
        request,
        StructuredJsonContract::new(
            "full-mode-multi:chunk",
            "FullModeFindingArray",
            full_mode_findings_schema(),
        ),
        parse_chunk_value,
    )
}

fn successful_chunk_cost(result: &Result<Vec<Finding>>, deposit_usd: f64) -> f64 {
    if result.is_ok() {
        deposit_usd
    } else {
        0.0
    }
}

fn refund_full_mode_chunk_budget(
    spend: Option<&SpendLimiter>,
    ticket: Option<SpendTicket>,
    actual_cost: f64,
) -> Result<()> {
    if let (Some(limiter), Some(ticket)) = (spend, ticket) {
        limiter.refund(ticket, actual_cost)?;
    }
    Ok(())
}

fn chunk_result_from_query(result: Result<Vec<Finding>>, actual_cost: f64) -> FullModeChunkResult {
    match result {
        Ok(findings) => FullModeChunkResult {
            succeeded: true,
            findings,
            cost_usd: actual_cost,
            error: None,
        },
        Err(error) => FullModeChunkResult {
            succeeded: false,
            findings: Vec::new(),
            cost_usd: 0.0,
            // `{:#}` walks the full anyhow chain so the dispatcher's
            // operator-facing summary keeps the bridge / provider cause
            // (e.g. "Anthropic API 429" or "Cannot find package
            // @mariozechner/pi-agent-core") instead of dropping it.
            error: Some(format!("{error:#}")),
        },
    }
}
