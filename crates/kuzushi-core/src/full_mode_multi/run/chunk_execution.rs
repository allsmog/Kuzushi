use super::*;

pub(super) struct FullModeChunkResult {
    pub(super) succeeded: bool,
    pub(super) findings: Vec<Finding>,
    pub(super) cost_usd: f64,
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
        },
        Err(_error) => FullModeChunkResult {
            succeeded: false,
            findings: Vec::new(),
            cost_usd: 0.0,
        },
    }
}
