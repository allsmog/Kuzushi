use super::plan::plan;
use crate::agent_router::RoutedRuntime;
use crate::capabilities::full_mode_multi::domain::{
    FailedChunkError, FullModeConfig, FullModePlan, FullModeReport,
};
use crate::spend::SpendLimiter;
use anyhow::{Context, Result};

mod chunk_execution;
mod run_setup;

pub fn run(
    runtime: &RoutedRuntime<'_>,
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
    runtime: &RoutedRuntime<'_>,
    spend: Option<&SpendLimiter>,
    cfg: &FullModeConfig,
    plan: FullModePlan,
    model: &str,
    system_prompt: &str,
) -> Result<FullModeReport> {
    let mut chunks = FullModeChunkAccumulator::default();
    for chunk in &plan.chunks {
        if should_skip_chunk(cfg, chunk.id) {
            continue;
        }
        let chunk_result =
            chunk_execution::run_full_mode_chunk(runtime, spend, cfg, chunk, model, system_prompt)?;
        chunks.record(chunk.id, chunk_result);
    }

    Ok(chunks.into_report(plan))
}

fn should_skip_chunk(cfg: &FullModeConfig, chunk_id: u32) -> bool {
    cfg.failed_chunk_ids
        .as_ref()
        .is_some_and(|ids| !ids.contains(&chunk_id))
}

#[derive(Default)]
struct FullModeChunkAccumulator {
    findings: Vec<crate::findings::Finding>,
    dispatched: u32,
    failed: u32,
    failed_chunk_errors: Vec<FailedChunkError>,
    cost_usd: f64,
    first_chunk_error: Option<String>,
}

impl FullModeChunkAccumulator {
    fn record(&mut self, chunk_id: u32, result: chunk_execution::FullModeChunkResult) {
        if result.succeeded {
            self.record_success(result);
            return;
        }

        self.record_failure(chunk_id, result.error);
    }

    fn record_success(&mut self, result: chunk_execution::FullModeChunkResult) {
        self.dispatched += 1;
        self.cost_usd += result.cost_usd;
        self.findings.extend(result.findings);
    }

    fn record_failure(&mut self, chunk_id: u32, error: Option<String>) {
        self.failed += 1;
        let reason = error.unwrap_or_else(|| "unknown chunk failure".to_string());
        self.first_chunk_error.get_or_insert_with(|| reason.clone());
        self.failed_chunk_errors
            .push(FailedChunkError { chunk_id, reason });
    }

    fn into_report(self, plan: FullModePlan) -> FullModeReport {
        FullModeReport {
            findings: self.findings,
            chunks_dispatched: self.dispatched,
            chunks_failed: self.failed,
            failed_chunk_errors: self.failed_chunk_errors,
            cost_usd: self.cost_usd,
            first_chunk_error: self.first_chunk_error,
            dry_run: false,
            plan,
        }
    }
}
