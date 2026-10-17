use super::plan::plan_with_observer;
use crate::agent_router::RoutedRuntime;
use crate::capabilities::full_mode_multi::domain::{
    FailedChunkError, FullModeConfig, FullModePlan, FullModeReport, PrefilteredChunk,
};
use crate::runtime::RuntimeCost;
use crate::semantic_cache::SemanticCache;
use crate::spend::SpendLimiter;
use anyhow::{Context, Result};

mod chunk_execution;
#[cfg(test)]
pub(crate) use chunk_execution::restore_absolute_lines;
mod prefilter;
mod run_setup;

pub fn run(
    runtime: &RoutedRuntime<'_>,
    spend: Option<&SpendLimiter>,
    cfg: &FullModeConfig,
) -> Result<FullModeReport> {
    run_with_observer(runtime, spend, cfg, &mut |_| {}, &|| false)
}

pub(crate) fn run_with_observer(
    runtime: &RoutedRuntime<'_>,
    spend: Option<&SpendLimiter>,
    cfg: &FullModeConfig,
    progress: &mut dyn FnMut(usize),
    canceled: &dyn Fn() -> bool,
) -> Result<FullModeReport> {
    let plan =
        plan_with_observer(cfg, progress, canceled).context("full_mode_multi: planning failed")?;

    if cfg.dry_run {
        return Ok(run_setup::dry_run_report(plan));
    }
    plan.ensure_execution_ready()?;

    let model = run_setup::resolve_full_mode_model(runtime)?;
    if let Some(prefilter_model) = &cfg.prefilter_model {
        crate::runtime::validate_model_spec(prefilter_model)
            .context("full_mode_multi: invalid prefilter model")?;
    }
    let system_prompt = run_setup::system_prompt_for_language(cfg.language);
    // Cache trouble degrades to every-chunk-live, never to a failed scan.
    let cache = cfg
        .reuse_cached_chunks
        .then(|| SemanticCache::open_for_target(&cfg.workspace_root))
        .flatten();
    dispatch_full_mode_chunks(
        runtime,
        spend,
        cfg,
        plan,
        &model,
        &system_prompt,
        cache.as_ref(),
    )
}

fn dispatch_full_mode_chunks(
    runtime: &RoutedRuntime<'_>,
    spend: Option<&SpendLimiter>,
    cfg: &FullModeConfig,
    plan: FullModePlan,
    model: &str,
    system_prompt: &str,
    cache: Option<&SemanticCache>,
) -> Result<FullModeReport> {
    let mut chunks = FullModeChunkAccumulator::default();
    // Once set, no further chunk is dispatched; every remaining chunk is
    // recorded under this reason so a `failedChunkIds` retry can finish
    // the plan while the findings gathered so far persist normally.
    let mut stop_reason: Option<String> = None;
    for chunk in &plan.chunks {
        if should_skip_chunk(cfg, chunk.id) {
            continue;
        }
        if stop_reason.is_none() {
            stop_reason = run_budget_stop_reason(cfg, chunks.cost_usd);
        }
        if let Some(reason) = &stop_reason {
            chunks.record_failure(chunk.id, Some(reason.clone()));
            continue;
        }
        if let Some(prefilter_model) = &cfg.prefilter_model {
            match prefilter::prefilter_full_mode_chunk(
                runtime,
                spend,
                cfg,
                chunk,
                prefilter_model,
                cache,
            ) {
                Ok(outcome) => {
                    chunks.record_ancillary_cost(outcome.cost_usd, outcome.observed_cost_usd)?;
                    if let Some(skipped) = outcome.skip {
                        chunks.record_prefiltered(skipped);
                        continue;
                    }
                }
                Err(error) if is_spend_cap_exhausted(&error) => {
                    let reason = format!("not dispatched: {error:#}");
                    chunks.record_failure(chunk.id, Some(reason.clone()));
                    stop_reason = Some(reason);
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        match chunk_execution::run_full_mode_chunk(
            runtime,
            spend,
            cfg,
            chunk,
            model,
            system_prompt,
            cache,
        ) {
            Ok(chunk_result) => chunks.record(chunk.id, chunk_result)?,
            Err(error) if is_spend_cap_exhausted(&error) => {
                let reason = format!("not dispatched: {error:#}");
                chunks.record_failure(chunk.id, Some(reason.clone()));
                stop_reason = Some(reason);
            }
            Err(error) => return Err(error),
        }
    }

    Ok(chunks.into_report(plan))
}

/// A graceful stop keeps completed-chunk findings instead of losing the
/// whole hunt: crossing `budgetUsd` (or exhausting a workspace spend cap)
/// must not degrade into an external kill that discards every result.
fn run_budget_stop_reason(cfg: &FullModeConfig, observed_cost_usd: f64) -> Option<String> {
    let budget = cfg.run_budget_usd?;
    (observed_cost_usd >= budget).then(|| {
        format!(
            "not dispatched: run budget ${budget:.2} exhausted \
             (observed cost ${observed_cost_usd:.2})"
        )
    })
}

fn is_spend_cap_exhausted(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<crate::spend::SpendError>(),
        Some(
            crate::spend::SpendError::Exceeded { .. }
                | crate::spend::SpendError::HardCeilingExceeded { .. }
        )
    )
}

fn should_skip_chunk(cfg: &FullModeConfig, chunk_id: u32) -> bool {
    cfg.failed_chunk_ids
        .as_ref()
        .is_some_and(|ids| !ids.contains(&chunk_id))
}

#[cfg(test)]
mod graceful_stop_tests {
    use super::{is_spend_cap_exhausted, run_budget_stop_reason};
    use crate::capabilities::full_mode_multi::domain::FullModeConfig;

    fn config_with_budget(budget: Option<f64>) -> FullModeConfig {
        FullModeConfig {
            run_budget_usd: budget,
            ..FullModeConfig::default()
        }
    }

    #[test]
    fn no_budget_never_stops() {
        assert_eq!(
            run_budget_stop_reason(&config_with_budget(None), 999.0),
            None
        );
    }

    #[test]
    fn under_budget_keeps_dispatching() {
        assert_eq!(
            run_budget_stop_reason(&config_with_budget(Some(2.5)), 2.49),
            None
        );
    }

    #[test]
    fn crossing_the_budget_stops_with_an_actionable_reason() {
        let reason = run_budget_stop_reason(&config_with_budget(Some(2.5)), 2.61)
            .expect("crossing the run budget must stop dispatch");
        assert!(
            reason.contains("$2.50"),
            "reason should name the budget: {reason}"
        );
        assert!(
            reason.contains("$2.61"),
            "reason should name observed cost: {reason}"
        );
    }

    #[test]
    fn spend_cap_errors_are_a_graceful_stop_even_behind_context() {
        let error = anyhow::Error::from(crate::spend::SpendError::Exceeded {
            op: "full-mode-multi",
            cap: 1.0,
            committed: 0.9,
            request: 0.2,
        })
        .context("full_mode_multi: deposit failed");
        assert!(is_spend_cap_exhausted(&error));
    }

    #[test]
    fn ordinary_chunk_errors_still_abort_the_hunt() {
        assert!(!is_spend_cap_exhausted(&anyhow::anyhow!("bridge crashed")));
    }
}

#[derive(Default)]
struct FullModeChunkAccumulator {
    findings: Vec<crate::findings::Finding>,
    dispatched: u32,
    failed: u32,
    from_cache: u32,
    prefiltered: Vec<PrefilteredChunk>,
    failed_chunk_errors: Vec<FailedChunkError>,
    cost_usd: f64,
    unresolved_provider_spend: bool,
    first_chunk_error: Option<String>,
}

impl FullModeChunkAccumulator {
    fn record(
        &mut self,
        chunk_id: u32,
        result: chunk_execution::FullModeChunkResult,
    ) -> Result<()> {
        self.record_ancillary_cost(result.cost_usd, result.observed_cost_usd)?;
        if result.succeeded {
            self.record_success(result);
            return Ok(());
        }

        self.record_failure(chunk_id, result.error);
        Ok(())
    }

    /// Folds a call's cost into the run total without recording a chunk
    /// outcome — used directly for prefilter calls, whose spend must count
    /// toward the run budget even when the chunk never deep-scans.
    fn record_ancillary_cost(
        &mut self,
        cost_usd: Option<f64>,
        observed_cost_usd: f64,
    ) -> Result<()> {
        self.cost_usd = RuntimeCost::checked_sum(
            [self.cost_usd, observed_cost_usd],
            "full-mode observed chunk fan-out cost",
        )?
        .usd();
        self.unresolved_provider_spend |= cost_usd.is_none();
        Ok(())
    }

    fn record_success(&mut self, result: chunk_execution::FullModeChunkResult) {
        self.dispatched += 1;
        if result.from_cache {
            self.from_cache += 1;
        }
        self.findings.extend(result.findings);
    }

    fn record_prefiltered(&mut self, skipped: PrefilteredChunk) {
        self.prefiltered.push(skipped);
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
            chunks_from_cache: self.from_cache,
            prefiltered_chunks: self.prefiltered,
            failed_chunk_errors: self.failed_chunk_errors,
            cost_usd: (!self.unresolved_provider_spend).then_some(self.cost_usd),
            observed_cost_usd: self.cost_usd,
            unresolved_provider_spend: self.unresolved_provider_spend,
            first_chunk_error: self.first_chunk_error,
            dry_run: false,
            plan,
        }
    }
}
