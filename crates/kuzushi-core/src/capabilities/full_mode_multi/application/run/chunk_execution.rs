use crate::agent_router::RoutedRuntime;
use crate::capabilities::full_mode_multi::application::chunk_prompt::{
    full_mode_findings_schema, parse_chunk_value, render_chunk_prompt,
};
use crate::capabilities::full_mode_multi::domain::{ChunkPlan, FullModeConfig};
use crate::findings::Finding;
use crate::runtime::{AgentQueryRequest, RuntimeCostReport};
use crate::spend::{Operation, SpendLimiter, SpendTicket};
use crate::structured_output::{
    query_required_structured_json_with_cost, CostedStructuredJson, StructuredJsonContract,
    StructuredOutputError,
};
use anyhow::{Context, Result};

pub(super) struct FullModeChunkResult {
    pub(super) succeeded: bool,
    pub(super) findings: Vec<Finding>,
    pub(super) cost_usd: Option<f64>,
    pub(super) observed_cost_usd: f64,
    /// Full anyhow chain string for a failed chunk. `None` for successes.
    /// The dispatcher keeps the first one and surfaces it to the operator
    /// so we don't repeat the "27 chunks failed, no diagnostic info" trap.
    pub(super) error: Option<String>,
}

pub(super) fn run_full_mode_chunk(
    runtime: &RoutedRuntime<'_>,
    spend: Option<&SpendLimiter>,
    cfg: &FullModeConfig,
    chunk: &ChunkPlan,
    model: &str,
    system_prompt: &str,
) -> Result<FullModeChunkResult> {
    let prompt = render_chunk_prompt(&cfg.workspace_root, chunk)?;
    let ticket = reserve_full_mode_chunk_budget(spend, cfg.deposit_usd_per_chunk)?;
    let result = query_full_mode_chunk(runtime, cfg, model, system_prompt, prompt);
    let cost = chunk_cost_report(&result)?;
    settle_full_mode_chunk_budget(spend, ticket, cost.exact_usd())?;
    let mut chunk_result = chunk_result_from_query(result, cost);
    restore_absolute_lines(chunk, &mut chunk_result.findings);
    Ok(chunk_result)
}

/// Window buckets show the model a slice of a large file, so reported lines
/// are window-relative. Restore absolute lines from the bucket's
/// `start_line`. Only unambiguous (single-bucket-per-path) matches are
/// adjusted; a chunk never carries two windows of one file in practice
/// because each window exceeds the chunk token cap and plans as a
/// singleton.
pub(crate) fn restore_absolute_lines(chunk: &ChunkPlan, findings: &mut [Finding]) {
    for finding in findings {
        let mut matches = chunk
            .files
            .iter()
            .filter(|bucket| bucket.path == finding.file_path);
        let (Some(bucket), None) = (matches.next(), matches.next()) else {
            continue;
        };
        if !bucket.is_window() || bucket.start_line <= 1 {
            continue;
        }
        let offset = (bucket.start_line - 1) as u32;
        finding.start_line = finding.start_line.saturating_add(offset);
        if let Some(end) = finding.end_line {
            finding.end_line = Some(end.saturating_add(offset));
        }
    }
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
    runtime: &RoutedRuntime<'_>,
    cfg: &FullModeConfig,
    model: &str,
    system_prompt: &str,
    prompt: String,
) -> Result<CostedStructuredJson<Vec<Finding>>> {
    let request = AgentQueryRequest::new(
        model.to_string(),
        cfg.workspace_root.clone(),
        system_prompt.to_string(),
        prompt,
    );

    query_required_structured_json_with_cost(
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

fn chunk_cost_report(
    result: &Result<CostedStructuredJson<Vec<Finding>>>,
) -> Result<RuntimeCostReport> {
    match result {
        Ok(costed) => costed.cost_report(),
        Err(error) => Ok(error
            .downcast_ref::<StructuredOutputError>()
            .map(StructuredOutputError::cost_report)
            .unwrap_or(RuntimeCostReport::INCOMPLETE_ZERO)),
    }
}

fn settle_full_mode_chunk_budget(
    spend: Option<&SpendLimiter>,
    ticket: Option<SpendTicket>,
    actual_cost: Option<f64>,
) -> Result<()> {
    if let (Some(limiter), Some(ticket), Some(actual_cost)) = (spend, ticket, actual_cost) {
        limiter.refund(ticket, actual_cost)?;
    }
    Ok(())
}

fn chunk_result_from_query(
    result: Result<CostedStructuredJson<Vec<Finding>>>,
    cost: RuntimeCostReport,
) -> FullModeChunkResult {
    match result {
        Ok(costed) => FullModeChunkResult {
            succeeded: true,
            findings: costed.value,
            cost_usd: cost.exact_usd(),
            observed_cost_usd: cost.observed_usd(),
            error: None,
        },
        Err(error) => FullModeChunkResult {
            succeeded: false,
            findings: Vec::new(),
            cost_usd: cost.exact_usd(),
            observed_cost_usd: cost.observed_usd(),
            // `{:#}` walks the full anyhow chain so the dispatcher's
            // operator-facing summary keeps the bridge / provider cause
            // (e.g. "Anthropic API 429" or "Cannot find package
            // @earendil-works/LangGraph") instead of dropping it.
            error: Some(format!("{error:#}")),
        },
    }
}
