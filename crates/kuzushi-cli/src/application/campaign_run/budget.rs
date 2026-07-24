//! Per-job budget guard: the cost ceiling for one running child and the
//! live spend probe that enforces it.
//!
//! The campaign-level `--budget` is checked between dispatches only; a
//! running job used to spend unbounded (measured: $32 against a $15 cap).
//! This module closes that hole. The child's canonical `items.jsonl` is
//! appended live by the run, so polling its summed terminal model-call
//! cost gives the dispatcher a bounded view of in-flight spend without a
//! side channel.

use kuzushi_core::run_artifacts::{run_artifact_path, terminal_model_call_cost_report};
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

/// Sum of terminal model-call costs observed so far in a run's lifecycle.
///
/// Tolerant by design: a live lifecycle stream can end in a torn line mid-append and a
/// dead poll must not kill a healthy job, so unparsable lines and invalid
/// cost rows are skipped rather than treated as evidence. A missing stream =
/// $0 spent — the strict lifecycle cost reader remains the
/// settlement-time accounting path.
pub(super) fn live_run_spend_usd(target: &Path, run_id: &str) -> f64 {
    let Ok(body) = std::fs::read_to_string(run_artifact_path(target, run_id, "items.jsonl")) else {
        return 0.0;
    };
    sum_terminal_call_costs(&body)
}

fn sum_terminal_call_costs(lines: &str) -> f64 {
    lines
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            serde_json::from_str::<kuzushi_core::run_lifecycle::RunItemEnvelopeV1>(line).ok()
        })
        .filter_map(|envelope| terminal_model_call_cost_report(&envelope.item))
        .map(|report| report.observed_usd())
        .sum::<f64>()
        + 0.0
}

/// Incremental live-spend poller: remembers the byte offset of the last
/// complete line it folded, so a 2-second poll over a multi-hour lifecycle
/// reads only the appended tail instead of re-folding from byte 0 every
/// tick (which made a long job's polling cost quadratic).
pub(super) struct LiveSpendPoller {
    path: std::path::PathBuf,
    offset: u64,
    spent: f64,
}

impl LiveSpendPoller {
    pub(super) fn new(target: &Path, run_id: &str) -> Self {
        Self {
            path: run_artifact_path(target, run_id, "items.jsonl"),
            offset: 0,
            spent: 0.0,
        }
    }

    /// Fold any newly appended complete lines and return total spend so
    /// far. Same tolerance contract as `live_run_spend_usd`: a missing or
    /// unreadable stream reports the last known total, torn tails wait for
    /// their newline.
    pub(super) fn poll(&mut self) -> f64 {
        use std::io::{Read, Seek, SeekFrom};
        let Ok(mut file) = std::fs::File::open(&self.path) else {
            return self.spent;
        };
        if file.seek(SeekFrom::Start(self.offset)).is_err() {
            return self.spent;
        }
        let mut tail = String::new();
        if file.read_to_string(&mut tail).is_err() {
            return self.spent;
        }
        let complete = match tail.rfind('\n') {
            Some(position) => &tail[..=position],
            None => return self.spent,
        };
        self.spent = self.spent + sum_terminal_call_costs(complete) + 0.0;
        self.offset += complete.len() as u64;
        self.spent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terminal_line(run_id: &str, n: u64, usd: f64) -> String {
        use kuzushi_core::run_lifecycle::{
            ModelUsage, RunCallId, RunId, RunItemEnvelopeV1, RunItemId, RunItemSource,
            RunItemStatus, RunItemV1, SafeText,
        };
        let cost = kuzushi_core::runtime::RuntimeCostReport::known(
            kuzushi_core::runtime::RuntimeCost::from_usd(usd, "campaign test").unwrap(),
        );
        let envelope = RunItemEnvelopeV1::new(
            n + 1,
            RunId::parse(run_id).unwrap(),
            RunItemId::new(),
            RunItemSource::Runtime,
            RunItemV1::ModelCallFinished {
                provider: SafeText::operator_visible("test"),
                model: SafeText::operator_visible("test:model"),
                status: RunItemStatus::Completed,
                latency_ms: 1,
                usage: ModelUsage {
                    input_tokens: None,
                    output_tokens: None,
                },
                cost,
                error_class: None,
            },
            None,
        )
        .unwrap()
        .with_call(RunCallId::new())
        .unwrap();
        serde_json::to_string(&envelope).unwrap()
    }

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
        let path = run_artifact_path(tmp.path(), "live", "items.jsonl");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let body = format!(
            "{}\n{}\n{}\n{}",
            terminal_line("live", 1, 0.4),
            r#"{"unrelated":true}"#,
            terminal_line("live", 3, 0.35),
            r#"{"schemaVersion":1,"seq"#,
        );
        std::fs::write(&path, body).unwrap();
        assert!((live_run_spend_usd(tmp.path(), "live") - 0.75).abs() < 1e-12);
    }

    #[test]
    fn live_spend_is_zero_before_the_lifecycle_exists() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(live_run_spend_usd(tmp.path(), "absent"), 0.0);
    }

    /// A 4-hour job's lifecycle (100k lines) must not be re-folded from byte 0
    /// on every 2-second poll: after the first fold, a no-growth poll reads
    /// only file metadata + EOF and stays in the low-millisecond range, and
    /// appended tails fold incrementally with torn tails deferred.
    #[test]
    fn incremental_poll_over_100k_lifecycle_reads_only_the_tail() {
        let tmp = tempfile::tempdir().unwrap();
        let path = run_artifact_path(tmp.path(), "long", "items.jsonl");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let terminal = terminal_line("long", 0, 0.001);
        let body = vec![terminal; 100_000].join("\n") + "\n";
        std::fs::write(&path, &body).unwrap();

        let mut poller = LiveSpendPoller::new(tmp.path(), "long");
        let first = poller.poll();
        assert!((first - 100.0).abs() < 1e-6, "{first}");

        // Steady-state polls with no growth must be effectively free.
        let started = std::time::Instant::now();
        for _ in 0..50 {
            assert!((poller.poll() - 100.0).abs() < 1e-6);
        }
        let per_poll = started.elapsed() / 50;
        assert!(
            per_poll < std::time::Duration::from_millis(5),
            "steady-state poll cost {per_poll:?} — tail polling regressed to a full re-fold"
        );

        // A torn append is deferred, then folded once its newline lands.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        use std::io::Write;
        let next = terminal_line("long", 100_000, 0.001);
        write!(file, "{}", &next[..40]).unwrap();
        file.flush().unwrap();
        assert!((poller.poll() - 100.0).abs() < 1e-6, "torn tail must wait");
        writeln!(file, "{}", &next[40..]).unwrap();
        file.flush().unwrap();
        assert!((poller.poll() - 100.001).abs() < 1e-6);
    }
}
