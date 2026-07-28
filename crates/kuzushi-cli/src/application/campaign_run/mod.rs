//! `kuzushi campaign run` — the campaign dispatcher.
//!
//! Executes a `campaign:plan` job matrix as bounded `kuzushi run` child
//! processes: a worker pool (1-8), the exit-code retry ladder from the
//! batch contract, quota-wall global pauses, a USD budget cap summed from
//! child run costs, and durable `queue.json` + `events.jsonl` state that
//! `campaign:status` and the cockpit fold over the plan. Deterministic by
//! construction: the dispatcher itself never calls a model.

mod budget;
mod child;
mod policy;
mod queue;

use crate::application::run_exit::RunCommandExit;
use crate::command::CampaignCommand;
use anyhow::{Context, Result};
use budget::{effective_job_budget, live_run_spend_usd};
use child::{run_child, ChildReport, ChildSpec};
use kuzushi_core::capabilities::campaign::{acquire_dispatcher_lease, CampaignDispatcherLease};
use kuzushi_core::run_artifacts::load_run_summary;
use policy::{
    budget_exhausted, looks_rate_limited, transition_for, JobOutcome, QuotaWall, Transition,
};
use queue::{now_ms, QueueStore};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::task::JoinSet;

const MAX_WORKERS: usize = 8;

pub(crate) async fn campaign_command(
    command: CampaignCommand,
    default_target: Option<PathBuf>,
) -> Result<()> {
    let CampaignCommand::Run {
        campaign_id,
        workers,
        max_attempts,
        job_timeout_secs,
        quota_wall_threshold,
        quota_wall_pause_secs,
        retry_backoff_secs,
        budget,
        job_budget,
        resume,
        jobs,
        dry_run,
    } = command;
    let target = crate::support::require_cli_target("campaign run", None, default_target)?;
    let settings = DispatchSettings {
        workers: clamped_workers(workers)?,
        max_attempts: max_attempts.max(1),
        job_timeout: Duration::from_secs(job_timeout_secs.max(1)),
        quota_wall_threshold,
        quota_wall_pause: Duration::from_secs(quota_wall_pause_secs.max(1)),
        retry_backoff_secs: retry_backoff_secs.max(1),
        budget_usd: budget,
        job_budget_usd: job_budget,
        resume,
    };
    let plan_jobs = load_plan_jobs(&target, &campaign_id, &jobs)?;
    if dry_run {
        return print_dry_run(&campaign_id, &plan_jobs);
    }
    Dispatcher::open(target, campaign_id, plan_jobs, settings)?
        .run()
        .await
}

fn clamped_workers(requested: usize) -> Result<usize> {
    anyhow::ensure!(requested >= 1, "--workers must be at least 1");
    if requested > MAX_WORKERS {
        eprintln!("campaign: --workers {requested} clamped to the hard cap of {MAX_WORKERS}");
    }
    Ok(requested.min(MAX_WORKERS))
}

struct DispatchSettings {
    workers: usize,
    max_attempts: u32,
    job_timeout: Duration,
    quota_wall_threshold: usize,
    quota_wall_pause: Duration,
    retry_backoff_secs: u64,
    budget_usd: Option<f64>,
    /// Default per-job USD ceiling; a plan row's `jobBudgetUsd` tightens it.
    job_budget_usd: Option<f64>,
    /// Return failed/resumably-parked jobs to `planned` before dispatching.
    resume: bool,
}

#[derive(Debug, Clone)]
struct PlanJob {
    job_id: String,
    tool: String,
    input_json: String,
    job_budget_usd: Option<f64>,
}

fn campaign_dir(target: &Path, campaign_id: &str) -> PathBuf {
    kuzushi_core::workspace::workspace_state_dir(target)
        .join("campaigns")
        .join(campaign_id)
}

/// Plan order is the dispatch order: `campaign:plan` already sorted jobs by
/// priority, and re-deriving rank here would let the two drift apart.
fn load_plan_jobs(target: &Path, campaign_id: &str, filter: &[String]) -> Result<Vec<PlanJob>> {
    let plan_path = campaign_dir(target, campaign_id).join("plan.json");
    let body = std::fs::read_to_string(&plan_path).with_context(|| {
        format!(
            "no campaign plan at {} — run `kuzushi run campaign:plan` first",
            plan_path.display()
        )
    })?;
    let plan: Value = serde_json::from_str(&body)
        .with_context(|| format!("{} is malformed", plan_path.display()))?;
    let rows = plan
        .get("jobs")
        .and_then(Value::as_array)
        .with_context(|| format!("{} has no jobs array", plan_path.display()))?;
    let jobs = rows.iter().map(plan_job_row).collect::<Result<Vec<_>>>()?;
    filtered_jobs(jobs, filter)
}

fn plan_job_row(row: &Value) -> Result<PlanJob> {
    let job_id = row
        .get("jobId")
        .and_then(Value::as_str)
        .context("plan job is missing jobId")?
        .to_string();
    let tool = row
        .get("tool")
        .and_then(Value::as_str)
        .with_context(|| format!("plan job {job_id} is missing tool"))?
        .to_string();
    let input = row
        .get("input")
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));
    Ok(PlanJob {
        job_id,
        tool,
        input_json: input.to_string(),
        job_budget_usd: row.get("jobBudgetUsd").and_then(Value::as_f64),
    })
}

fn filtered_jobs(jobs: Vec<PlanJob>, filter: &[String]) -> Result<Vec<PlanJob>> {
    if filter.is_empty() {
        return Ok(jobs);
    }
    for wanted in filter {
        anyhow::ensure!(
            jobs.iter().any(|job| &job.job_id == wanted),
            "--jobs names {wanted:?}, which is not in the plan"
        );
    }
    Ok(jobs
        .into_iter()
        .filter(|job| filter.contains(&job.job_id))
        .collect())
}

fn print_dry_run(campaign_id: &str, jobs: &[PlanJob]) -> Result<()> {
    println!(
        "campaign {campaign_id}: {} job(s) in dispatch order",
        jobs.len()
    );
    for job in jobs {
        println!("  {}  {}  {}", job.job_id, job.tool, job.input_json);
    }
    Ok(())
}

struct Dispatcher {
    target: PathBuf,
    campaign_id: String,
    binary: PathBuf,
    logs_dir: PathBuf,
    plan_jobs: Vec<PlanJob>,
    store: QueueStore,
    settings: DispatchSettings,
    wall: QuotaWall,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    _lease: CampaignDispatcherLease,
}

impl Dispatcher {
    fn open(
        target: PathBuf,
        campaign_id: String,
        plan_jobs: Vec<PlanJob>,
        settings: DispatchSettings,
    ) -> Result<Self> {
        let lease = acquire_dispatcher_lease(&target, &campaign_id)?;
        let dir = campaign_dir(&target, &campaign_id);
        let logs_dir = dir.join("logs");
        std::fs::create_dir_all(&logs_dir)
            .with_context(|| format!("Could not create {}", logs_dir.display()))?;
        let store = open_dispatch_queue(&target, &dir, &campaign_id, &plan_jobs, &settings)?;
        let binary = std::env::current_exe().context("Could not resolve the kuzushi binary")?;
        let wall = QuotaWall::new(settings.quota_wall_threshold);
        Ok(Self {
            target,
            campaign_id,
            binary,
            logs_dir,
            plan_jobs,
            store,
            settings,
            wall,
            shutdown_rx: spawn_ctrl_c_watch(),
            _lease: lease,
        })
    }

    async fn run(mut self) -> Result<()> {
        self.store.append_event(
            "dispatch-start",
            None,
            serde_json::json!({ "workers": self.settings.workers, "jobs": self.plan_jobs.len() }),
        )?;
        let mut running: JoinSet<(String, String, Result<ChildReport>)> = JoinSet::new();
        loop {
            if *self.shutdown_rx.borrow() {
                break;
            }
            self.wait_out_quota_pause().await;
            self.dispatch_ready(&mut running)?;
            if running.is_empty() {
                if !self.sleep_until_next_ready().await {
                    break;
                }
                continue;
            }
            if let Some(joined) = running.join_next().await {
                let (job_id, run_id, report) = joined.context("job worker panicked")?;
                self.settle_job(&job_id, &run_id, report?)?;
            }
        }
        self.drain_after_shutdown(running).await?;
        self.finish()
    }

    /// Fill idle worker slots with ready jobs, marking each `running` and
    /// consuming its attempt before the child spawns.
    fn dispatch_ready(
        &mut self,
        running: &mut JoinSet<(String, String, Result<ChildReport>)>,
    ) -> Result<()> {
        while running.len() < self.settings.workers {
            if self.store.provider_spend_unresolved() {
                self.park_pending("provider-spend-unresolved")?;
                return Ok(());
            }
            if budget_exhausted(self.store.total_cost_usd(), self.settings.budget_usd) {
                self.park_pending("budget-exhausted")?;
                return Ok(());
            }
            let Some(job) = self.next_ready_job() else {
                return Ok(());
            };
            let entry = self.store.job(&job.job_id);
            let attempt = entry.map(|entry| entry.attempts).unwrap_or(0) + 1;
            // Run ids come from the never-reset dispatch counter, not the
            // attempt budget: a resumed job re-minting an old run id would
            // inherit that run's artifacts, and the live budget guard would
            // kill the fresh child on the stale trace's spend.
            let dispatch = entry.map(|entry| entry.dispatches).unwrap_or(0) + 1;
            let run_id = format!("{}-{}-a{dispatch}", self.campaign_id, job.job_id);
            self.store.update_job(&job.job_id, "job-start", |entry| {
                entry.state = "running".to_string();
                entry.attempts = attempt;
                entry.dispatches = dispatch;
                entry.run_id = Some(run_id.clone());
                entry.not_before_ms = None;
            })?;
            running.spawn(job_future(
                self.child_spec(&job, &run_id),
                job.job_id,
                run_id,
                self.shutdown_rx.clone(),
            ));
        }
        Ok(())
    }

    fn child_spec(&self, job: &PlanJob, run_id: &str) -> ChildSpec {
        ChildSpec {
            binary: self.binary.clone(),
            target: self.target.clone(),
            tool: job.tool.clone(),
            input_json: job.input_json.clone(),
            run_id: run_id.to_string(),
            log_path: self.logs_dir.join(format!("{run_id}.log")),
            timeout: self.settings.job_timeout,
            job_budget_usd: effective_job_budget(self.settings.job_budget_usd, job.job_budget_usd),
        }
    }

    fn next_ready_job(&self) -> Option<PlanJob> {
        let now = now_ms();
        self.plan_jobs
            .iter()
            .find(|job| {
                self.store.job(&job.job_id).is_some_and(|entry| {
                    matches!(entry.state.as_str(), "planned" | "requeued")
                        && entry.not_before_ms.unwrap_or(0) <= now
                })
            })
            .cloned()
    }

    fn settle_job(&mut self, job_id: &str, run_id: &str, mut report: ChildReport) -> Result<()> {
        let summary = load_child_summary(&self.target, run_id, &report)?;
        report.outcome = reconciled_child_outcome(&report, summary.as_ref())?;
        let summary_error = summary.as_ref().and_then(|summary| summary.error.clone());
        // A killed child (over-budget/timeout/shutdown) never finalized its
        // summary, but its money is already spent: fall back to the live
        // trace sum so the campaign-level budget still sees that spend.
        let (cost, provider_spend_unresolved) =
            campaign_attempt_cost(summary.as_ref(), &self.target, run_id, report.outcome);
        let failure_text = format!(
            "{} {}",
            summary_error.unwrap_or_default(),
            report.output_tail
        );
        let rate_limited =
            report.outcome != JobOutcome::Completed && looks_rate_limited(&failure_text);
        let attempts = self
            .store
            .job(job_id)
            .map(|entry| entry.attempts)
            .unwrap_or(1);
        let transition = transition_for(
            report.outcome,
            rate_limited,
            attempts,
            self.settings.max_attempts,
            self.settings.retry_backoff_secs,
        );
        self.apply_transition(job_id, &report, cost, provider_spend_unresolved, transition)?;
        if self.wall.observe(rate_limited) {
            self.pause_for_quota_wall()?;
        }
        Ok(())
    }

    fn apply_transition(
        &mut self,
        job_id: &str,
        report: &ChildReport,
        cost: Option<f64>,
        provider_spend_unresolved: bool,
        transition: Transition,
    ) -> Result<()> {
        let outcome = report.outcome.label();
        let exit_code = report.exit_code;
        self.store.update_job(job_id, outcome, |entry| {
            entry.exit_code = exit_code;
            entry.cost_usd = accumulated_job_cost(entry.cost_usd, cost);
            entry.provider_spend_unresolved |= provider_spend_unresolved;
            match transition {
                Transition::Complete => entry.state = "completed".to_string(),
                Transition::Fail => entry.state = "failed".to_string(),
                Transition::Park { reason } => {
                    entry.state = "parked".to_string();
                    entry.reason = Some(reason);
                }
                Transition::Requeue {
                    backoff_secs,
                    consume_attempt,
                } => {
                    entry.state = "requeued".to_string();
                    entry.not_before_ms = Some(now_ms() + backoff_secs * 1000);
                    if !consume_attempt {
                        entry.attempts = entry.attempts.saturating_sub(1);
                    }
                }
            }
        })
    }

    fn pause_for_quota_wall(&mut self) -> Result<()> {
        let until = now_ms() + self.settings.quota_wall_pause.as_millis() as u64;
        eprintln!(
            "campaign: quota wall detected — pausing all dispatch for {}s",
            self.settings.quota_wall_pause.as_secs()
        );
        self.store.set_paused_until(Some(until))
    }

    async fn wait_out_quota_pause(&mut self) {
        let Some(until) = self.store.doc.paused_until_ms else {
            return;
        };
        let now = now_ms();
        if until > now {
            sleep_or_shutdown(Duration::from_millis(until - now), &mut self.shutdown_rx).await;
        }
        let _ = self.store.set_paused_until(None);
    }

    /// True when a future-scheduled (backoff) job exists and we slept toward
    /// it; false when no dispatchable work remains at all.
    async fn sleep_until_next_ready(&mut self) -> bool {
        let now = now_ms();
        let next = self
            .plan_jobs
            .iter()
            .filter_map(|job| self.store.job(&job.job_id))
            .filter(|entry| matches!(entry.state.as_str(), "planned" | "requeued"))
            .map(|entry| entry.not_before_ms.unwrap_or(0))
            .min();
        match next {
            Some(when) => {
                let wait = Duration::from_millis(when.saturating_sub(now).max(50));
                sleep_or_shutdown(wait, &mut self.shutdown_rx).await;
                true
            }
            None => false,
        }
    }

    fn park_pending(&mut self, reason: &str) -> Result<()> {
        let pending = self
            .plan_jobs
            .iter()
            .map(|job| job.job_id.clone())
            .filter(|job_id| {
                self.store
                    .job(job_id)
                    .is_some_and(|entry| matches!(entry.state.as_str(), "planned" | "requeued"))
            })
            .collect::<Vec<_>>();
        for job_id in pending {
            let reason = reason.to_string();
            self.store.update_job(&job_id, "park", |entry| {
                entry.state = "parked".to_string();
                entry.reason = Some(reason);
            })?;
        }
        Ok(())
    }

    async fn drain_after_shutdown(
        &mut self,
        mut running: JoinSet<(String, String, Result<ChildReport>)>,
    ) -> Result<()> {
        if running.is_empty() {
            return Ok(());
        }
        // The watch flag is already true, so every child future kills its
        // process group and reports Interrupted; await them all.
        while let Some(joined) = running.join_next().await {
            let (job_id, run_id, report) = joined.context("job worker panicked")?;
            self.settle_job(&job_id, &run_id, report?)?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        if *self.shutdown_rx.borrow() {
            self.park_pending("interrupted")?;
        }
        let counts = self.store.state_counts();
        let cost = self.store.total_cost_usd();
        let provider_spend_unresolved = self.store.provider_spend_unresolved();
        let summary = counts
            .iter()
            .map(|(state, count)| format!("{count} {state}"))
            .collect::<Vec<_>>()
            .join(", ");
        self.store.append_event(
            "dispatch-end",
            None,
            serde_json::json!({
                "states": counts,
                "totalCostUsd": cost,
                "providerSpendUnresolved": provider_spend_unresolved,
            }),
        )?;
        println!(
            "campaign {} finished: {summary}; {}",
            self.campaign_id,
            campaign_cost_label(cost, provider_spend_unresolved)
        );
        let completed = counts.get("completed").copied().unwrap_or(0);
        let total: usize = counts.values().sum();
        if completed == total {
            return Ok(());
        }
        Err(RunCommandExit::new(3, format!("campaign {}: {summary}", self.campaign_id)).into())
    }
}

fn campaign_cost_label(observed_usd: f64, provider_spend_unresolved: bool) -> String {
    if provider_spend_unresolved {
        return format!("total cost >=${observed_usd:.2} (provider spend incomplete)");
    }
    format!("total cost ${observed_usd:.2}")
}

fn open_dispatch_queue(
    target: &Path,
    campaign_dir: &Path,
    campaign_id: &str,
    plan_jobs: &[PlanJob],
    settings: &DispatchSettings,
) -> Result<QueueStore> {
    let job_ids = plan_jobs
        .iter()
        .map(|job| job.job_id.clone())
        .collect::<Vec<_>>();
    let mut store = QueueStore::open(
        target,
        campaign_dir,
        campaign_id,
        &job_ids,
        settings.budget_usd,
        settings.job_budget_usd,
    )?;
    if settings.resume {
        report_resumed_jobs(&mut store)?;
    }
    Ok(store)
}

fn report_resumed_jobs(store: &mut QueueStore) -> Result<()> {
    let resumed = store.resume_resumable()?;
    if !resumed.is_empty() {
        eprintln!(
            "campaign: resumed {} job(s) to planned: {}",
            resumed.len(),
            resumed.join(", ")
        );
    }
    Ok(())
}

fn campaign_attempt_cost(
    summary: Option<&kuzushi_core::RunSummary>,
    target: &Path,
    run_id: &str,
    outcome: JobOutcome,
) -> (Option<f64>, bool) {
    if let Some(summary) = summary {
        let observed = summary.cost_usd.or(summary.observed_cost_usd);
        return (observed, summary.provider_spend_unresolved);
    }
    let live = live_run_spend_usd(target, run_id);
    let observed = (live > 0.0).then_some(live);
    let unresolved = observed.is_some()
        || matches!(
            outcome,
            JobOutcome::TimedOut | JobOutcome::Interrupted | JobOutcome::OverBudget
        );
    (observed, unresolved)
}

fn load_child_summary(
    target: &Path,
    run_id: &str,
    report: &ChildReport,
) -> Result<Option<kuzushi_core::RunSummary>> {
    match load_run_summary(target, run_id) {
        Ok(summary) => Ok(Some(summary)),
        Err(_) if report.exit_code.is_none() || report.outcome == JobOutcome::OperationalError => {
            Ok(None)
        }
        Err(error) => Err(error).with_context(|| {
            format!("campaign child {run_id} exited without readable terminal metadata")
        }),
    }
}

fn reconciled_child_outcome(
    report: &ChildReport,
    summary: Option<&kuzushi_core::RunSummary>,
) -> Result<JobOutcome> {
    let Some(exit_code) = report.exit_code else {
        return Ok(report.outcome);
    };
    let Some(summary) = summary else {
        return Ok(report.outcome);
    };
    anyhow::ensure!(
        exit_agrees_with_persisted_status(exit_code, &summary.status),
        "campaign child exit {exit_code} disagrees with persisted status {:?}",
        summary.status
    );
    JobOutcome::from_persisted_status(&summary.status).with_context(|| {
        format!(
            "campaign child has unknown persisted status {:?}",
            summary.status
        )
    })
}

fn exit_agrees_with_persisted_status(exit_code: i32, status: &str) -> bool {
    matches!(
        (exit_code, status),
        (0, "completed" | "skipped")
            | (2, "blocked")
            | (3, "failed" | "interrupted")
            | (4, "partial")
            | (130, "canceled")
    )
}

/// A job's `costUsd` is the sum of every attempt's spend — each settle adds
/// its attempt's cost exactly once. Overwriting (the old behavior) silently
/// under-counted multi-attempt jobs by all but the last attempt. An attempt
/// with no observable cost leaves the accumulator untouched; `+ 0.0`
/// normalizes IEEE negative zero.
fn accumulated_job_cost(prior: Option<f64>, attempt: Option<f64>) -> Option<f64> {
    match attempt {
        Some(cost) => Some(prior.unwrap_or(0.0) + cost + 0.0),
        None => prior,
    }
}

async fn job_future(
    spec: ChildSpec,
    job_id: String,
    run_id: String,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> (String, String, Result<ChildReport>) {
    let report = run_child(&spec, shutdown).await;
    (job_id, run_id, report)
}

/// Ctrl+C flips a watch flag every child future selects on. Children live in
/// their own process groups (terminal SIGINT does not reach them), so this
/// explicit forwarding is what guarantees no orphaned scanner survives.
fn spawn_ctrl_c_watch() -> tokio::sync::watch::Receiver<bool> {
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("campaign: interrupt received — killing job children and saving state");
            let _ = tx.send(true);
        }
    });
    rx
}

async fn sleep_or_shutdown(wait: Duration, shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    tokio::select! {
        _ = tokio::time::sleep(wait) => {}
        _ = shutdown.changed() => {}
    }
}

#[cfg(test)]
mod cost_accounting_tests {
    use super::*;

    #[test]
    fn child_exit_contract_accepts_only_its_persisted_terminal_statuses() {
        assert!(exit_agrees_with_persisted_status(130, "canceled"));
        assert!(exit_agrees_with_persisted_status(3, "interrupted"));
        assert!(exit_agrees_with_persisted_status(2, "blocked"));
        assert!(!exit_agrees_with_persisted_status(0, "failed"));
        assert!(!exit_agrees_with_persisted_status(130, "completed"));
    }

    #[test]
    fn campaign_attempt_cost_preserves_incomplete_provider_spend() {
        let target = tempfile::tempdir().unwrap();
        let mut summary = kuzushi_core::RunSummary::running("run-cost", "run", None, "target");
        summary.observed_cost_usd = Some(0.75);
        summary.provider_spend_unresolved = true;

        assert_eq!(
            campaign_attempt_cost(
                Some(&summary),
                target.path(),
                "run-cost",
                JobOutcome::ToolFailed
            ),
            (Some(0.75), true)
        );
    }

    #[test]
    fn campaign_cost_label_marks_observed_spend_as_a_lower_bound() {
        assert_eq!(campaign_cost_label(0.75, false), "total cost $0.75");
        assert_eq!(
            campaign_cost_label(0.75, true),
            "total cost >=$0.75 (provider spend incomplete)"
        );
    }

    #[test]
    fn accumulated_cost_adds_each_attempt_once_and_skips_costless_attempts() {
        assert_eq!(accumulated_job_cost(None, None), None);
        assert_eq!(accumulated_job_cost(None, Some(1.5)), Some(1.5));
        assert_eq!(accumulated_job_cost(Some(1.5), Some(2.25)), Some(3.75));
        assert_eq!(accumulated_job_cost(Some(1.5), None), Some(1.5));
        // IEEE negative zero from a cost-free traced run stays plain zero.
        assert_eq!(accumulated_job_cost(None, Some(-0.0)), Some(0.0));
        assert!(accumulated_job_cost(None, Some(-0.0))
            .unwrap()
            .is_sign_positive());
    }

    /// Property: over a synthetic multi-attempt, multi-job campaign, the
    /// queue's reported total equals the sum of every attempt's cost exactly
    /// once — no per-attempt overwrite undercount, no settle double-count.
    #[test]
    fn queue_total_equals_the_sum_of_all_attempt_costs_exactly_once() {
        let tmp = tempfile::tempdir().unwrap();
        let job_ids: Vec<String> = (0..5).map(|n| format!("job-{n}")).collect();
        let mut store =
            queue::QueueStore::open(tmp.path(), tmp.path(), "camp", &job_ids, None, None).unwrap();

        // Deterministic pseudo-random attempt schedule: job n gets n+1
        // attempts; some attempts observe no cost at all.
        let mut expected = 0.0f64;
        for (n, job_id) in job_ids.iter().enumerate() {
            for attempt in 0..=n {
                let cost = match attempt % 3 {
                    0 => Some(0.25 + n as f64 * 0.1 + attempt as f64 * 0.01),
                    1 => Some(-0.0),
                    _ => None,
                };
                expected += cost.unwrap_or(0.0);
                store
                    .update_job(job_id, "settle", |entry| {
                        entry.attempts = attempt as u32 + 1;
                        entry.cost_usd = accumulated_job_cost(entry.cost_usd, cost);
                        entry.state = "requeued".to_string();
                    })
                    .unwrap();
            }
        }

        let total = store.total_cost_usd();
        assert!(
            (total - expected).abs() < 1e-9,
            "queue total {total} != sum of attempt costs {expected}"
        );
        assert!(total.is_sign_positive());
    }
}
