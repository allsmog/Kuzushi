use super::*;

mod chunk_execution;
mod run_setup;

pub fn run(
    runtime: &RoutedRuntime,
    spend: Option<&SpendLimiter>,
    cfg: &FullModeConfig,
) -> Result<FullModeReport> {
    let plan = plan(cfg).context("full_mode_multi: planning failed")?;

    if cfg.dry_run {
        return Ok(run_setup::dry_run_report(plan));
    }

    let model = run_setup::resolve_full_mode_model(runtime)?;
    let system_prompt = run_setup::system_prompt_for_language(cfg.language);
    dispatch_full_mode_chunks(runtime, spend, cfg, plan, &model, &system_prompt)
}

fn dispatch_full_mode_chunks(
    runtime: &RoutedRuntime,
    spend: Option<&SpendLimiter>,
    cfg: &FullModeConfig,
    plan: FullModePlan,
    model: &str,
    system_prompt: &str,
) -> Result<FullModeReport> {
    let mut all_findings = Vec::new();
    let mut dispatched = 0u32;
    let mut failed = 0u32;
    let mut cost = 0.0f64;

    for chunk in &plan.chunks {
        let chunk_result =
            chunk_execution::run_full_mode_chunk(runtime, spend, cfg, chunk, model, system_prompt)?;
        if chunk_result.succeeded {
            dispatched += 1;
            cost += chunk_result.cost_usd;
            all_findings.extend(chunk_result.findings);
        } else {
            failed += 1;
        }
    }

    Ok(FullModeReport {
        findings: all_findings,
        plan,
        chunks_dispatched: dispatched,
        chunks_failed: failed,
        cost_usd: cost,
        dry_run: false,
    })
}
