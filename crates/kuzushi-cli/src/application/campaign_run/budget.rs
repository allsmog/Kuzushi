//! Per-job budget guard: the cost ceiling for one running child and the
//! live spend probe that enforces it.
//!
//! The campaign-level `--budget` is checked between dispatches only; a
//! running job used to spend unbounded (measured: $32 against a $15 cap).
//! This module closes that hole. The child's canonical `trace.jsonl` is
//! appended live by the run, so polling its summed terminal model-call
//! cost gives the dispatcher a bounded view of in-flight spend without a
//! side channel.

use kuzushi_core::run_artifacts::{run_artifact_path, terminal_model_call_cost_report, RunTraceStep};
use std::path::Path;

/// The ceiling for one job: the tightest of the dispatcher-wide
/// `--job-budget` and the plan row's `jobBudgetUsd`. Two present values
/// take the min — a guard must honor the strictest cap it was given.
pub(super) fn effective_job_budget(cli_usd: Option<f64>, plan_usd: Option<f64>) -> Option<f64> {
    match (positive(cli_usd), positive(plan_usd)) {
        (Some(cli), Some(plan)) => Some(cli.min(plan)),
        (cli, plan) => cli.or(plan),
    }
}

fn positive(value: Option<f64>) -> Option<f64> {
    value.filter(|usd| *usd > 0.0)
}

/// Sum of terminal model-call costs observed so far in a run's live trace.
///
/// Tolerant by design: a live trace can end in a torn line mid-append and a
/// dead poll must not kill a healthy job, so unparsable lines and invalid
/// cost rows are skipped rather than treated as evidence. Missing trace =
/// $0 spent — the strict variant (`trace_cost_report`) remains the
/// settlement-time accounting path.
pub(super) fn live_run_spend_usd(target: &Path, run_id: &str) -> f64 {
    let path = run_artifact_path(target, run_id, "trace.jsonl");
    let Ok(body) = std::fs::read_to_string(&path) else {
        return 0.0;
    };
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<RunTraceStep>(line).ok())
        .filter_map(|step| terminal_model_call_cost_report(&step).ok().flatten())
        .map(|report| report.observed_usd())
        .sum::<f64>()
        + 0.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_budget_takes_the_tightest_present_cap() {
        assert_eq!(effective_job_budget(None, None), None);
        assert_eq!(effective_job_budget(Some(5.0), None), Some(5.0));
        assert_eq!(effective_job_budget(None, Some(3.0)), Some(3.0));
        assert_eq!(effective_job_budget(Some(5.0), Some(3.0)), Some(3.0));
        assert_eq!(effective_job_budget(Some(2.0), Some(3.0)), Some(2.0));
        // Zero/negative caps are configuration noise, not "kill instantly".
        assert_eq!(effective_job_budget(Some(0.0), None), None);
        assert_eq!(effective_job_budget(Some(-1.0), Some(3.0)), Some(3.0));
    }

    #[test]
    fn live_spend_sums_terminal_calls_and_survives_a_torn_tail() {
        let tmp = tempfile::tempdir().unwrap();
        let path = run_artifact_path(tmp.path(), "live", "trace.jsonl");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let terminal = |n: usize, usd: f64| {
            format!(
                r#"{{"n":{n},"kind":"reasoning","label":"model","latency_ms":1,"cost_usd":{usd},"model":"m","provider":"p","prompt_hash":"h"}}"#
            )
        };
        let body = format!(
            "{}\n{}\n{}\n{}",
            terminal(1, 0.4),
            r#"{"n":2,"kind":"tool","label":"grep"}"#, // non-call row: no cost
            terminal(3, 0.35),
            r#"{"n":4,"kind":"reasoning","la"#, // torn live append
        );
        std::fs::write(&path, body).unwrap();
        assert!((live_run_spend_usd(tmp.path(), "live") - 0.75).abs() < 1e-12);
    }

    #[test]
    fn live_spend_is_zero_before_the_trace_exists() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(live_run_spend_usd(tmp.path(), "absent"), 0.0);
    }
}
