//! `kuzushi campaign run` — the campaign dispatcher.
//!
//! Executes a `campaign:plan` job matrix as bounded `kuzushi run` child
//! processes: a worker pool (1-8), the exit-code retry ladder from the
//! batch contract, quota-wall global pauses, a USD budget cap summed from
//! child run costs, and durable `queue.json` + `events.jsonl` state that
//! `campaign:status` and the cockpit fold over the plan. Deterministic by
//! construction: the dispatcher itself never calls a model.

mod allowance_pause;
mod approved_work;
mod budget;
mod child;
#[cfg(test)]
mod matrix_tests;
mod policy;
mod queue;
mod shutdown;

use crate::application::run_exit::RunCommandExit;
use crate::command::CampaignCommand;
use anyhow::{Context, Result};
use budget::effective_job_budget;
use child::{run_child, ChildReport, ChildSpec};
use kuzushi_core::capabilities::campaign::{
    acquire_dispatcher_lease, CampaignDispatcherLease, MAX_CAMPAIGN_WORKERS,
};
use kuzushi_core::run_artifacts::load_run_summary;
use policy::{
    budget_exhausted, looks_rate_limited, transition_for, JobOutcome, QuotaWall, Transition,
};
use queue::{now_ms, QueueStore};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::task::JoinSet;

pub(crate) async fn campaign_command(
    command: CampaignCommand,
    default_target: Option<PathBuf>,
) -> Result<()> {
    match command {
        batch @ CampaignCommand::Batch { .. } => {
            super::scan_batch::run_existing_batch_command(batch, default_target).await
        }
        run @ CampaignCommand::Run { .. } => campaign_run_command(run, default_target).await,
    }
}

async fn campaign_run_command(
    command: CampaignCommand,
    default_target: Option<PathBuf>,
) -> Result<()> {
    let request = public_campaign_request(command)?;
    let target = crate::support::require_cli_target("campaign run", None, default_target)?;
    run_loaded_campaign(
        target,
        request.campaign_id,
        request.jobs,
        request.dry_run,
        request.settings,
        DispatchAuthority::PublicCampaign,
    )
    .await
}

struct PublicCampaignRequest {
    campaign_id: String,
    jobs: Vec<String>,
    dry_run: bool,
    settings: DispatchSettings,
}

fn public_campaign_request(command: CampaignCommand) -> Result<PublicCampaignRequest> {
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
    } = command
    else {
        unreachable!("batch controller routed to the raw campaign dispatcher")
    };
    Ok(PublicCampaignRequest {
        campaign_id,
        jobs,
        dry_run,
        settings: DispatchSettings {
            workers: clamped_workers(workers)?,
            max_attempts: max_attempts.max(1),
            job_timeout: Duration::from_secs(job_timeout_secs.max(1)),
            quota_wall_threshold,
            quota_wall_pause: Duration::from_secs(quota_wall_pause_secs.max(1)),
            retry_backoff_secs: retry_backoff_secs.max(1),
            budget_usd: budget,
            job_budget_usd: job_budget,
            resume,
        },
    })
}

async fn run_loaded_campaign(
    target: PathBuf,
    campaign_id: String,
    jobs: Vec<String>,
    dry_run: bool,
    settings: DispatchSettings,
    authority: DispatchAuthority,
) -> Result<()> {
    let loaded_plan = load_plan_jobs(&target, &campaign_id, &jobs)?;
    authorize_loaded_plan(&loaded_plan, authority, &campaign_id)?;
    enforce_scan_batch_worker_boundary(&loaded_plan, &settings)?;
    if dry_run {
        return print_dry_run(&campaign_id, &loaded_plan.jobs);
    }
    Dispatcher::open(target, campaign_id, loaded_plan, settings)?
        .run()
        .await
}

pub(crate) async fn dispatch_scan_batch_plan(
    target: PathBuf,
    campaign_id: String,
    workers: usize,
) -> Result<()> {
    let settings = standard_batch_dispatch_settings(workers)?;
    run_loaded_campaign(
        target,
        campaign_id,
        Vec::new(),
        false,
        settings,
        DispatchAuthority::ScanBatchController,
    )
    .await
}

fn standard_batch_dispatch_settings(workers: usize) -> Result<DispatchSettings> {
    Ok(DispatchSettings {
        workers: clamped_workers(workers)?,
        max_attempts: 2,
        job_timeout: Duration::from_secs(3600),
        quota_wall_threshold: 3,
        quota_wall_pause: Duration::from_secs(900),
        retry_backoff_secs: 5,
        budget_usd: None,
        job_budget_usd: None,
        resume: true,
    })
}

fn clamped_workers(requested: usize) -> Result<usize> {
    anyhow::ensure!(requested >= 1, "--workers must be at least 1");
    if requested > MAX_CAMPAIGN_WORKERS {
        eprintln!(
            "campaign: --workers {requested} clamped to the hard cap of {MAX_CAMPAIGN_WORKERS}"
        );
    }
    Ok(requested.min(MAX_CAMPAIGN_WORKERS))
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
    approved_attempts: Option<u32>,
}

struct LoadedPlan {
    context_study: bool,
    case_study: bool,
    jobs: Vec<PlanJob>,
    batch_guard: Option<ScanBatchGuard>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchAuthority {
    PublicCampaign,
    ScanBatchController,
}

fn authorize_loaded_plan(
    plan: &LoadedPlan,
    authority: DispatchAuthority,
    campaign_id: &str,
) -> Result<()> {
    if plan.batch_guard.is_some()
        && !plan.case_study
        && authority == DispatchAuthority::PublicCampaign
    {
        anyhow::bail!(
            "scan batch {campaign_id} must run through `kuzushi campaign batch {campaign_id}`; raw `campaign run` is refused"
        );
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ScanBatchGuard {
    expected_key: String,
    base_input: Value,
    effective_workers: usize,
    trials_planned: usize,
}

fn campaign_dir(target: &Path, campaign_id: &str) -> PathBuf {
    kuzushi_core::workspace::workspace_state_dir(target)
        .join("campaigns")
        .join(campaign_id)
}

/// Plan order is the dispatch order: `campaign:plan` already sorted jobs by
/// priority, and re-deriving rank here would let the two drift apart.
fn load_plan_jobs(target: &Path, campaign_id: &str, filter: &[String]) -> Result<LoadedPlan> {
    let plan_path = campaign_dir(target, campaign_id).join("plan.json");
    let plan =
        kuzushi_core::capabilities::campaign::read_campaign_plan_document(target, campaign_id)
            .with_context(|| {
                format!(
                    "no campaign plan at {} — run `kuzushi run campaign:plan` first",
                    plan_path.display()
                )
            })?;
    let batch_guard = scan_batch_guard(campaign_id, &plan, filter)?;
    let rows = plan
        .get("jobs")
        .and_then(Value::as_array)
        .with_context(|| format!("{} has no jobs array", plan_path.display()))?;
    let jobs = rows.iter().map(plan_job_row).collect::<Result<Vec<_>>>()?;
    let mut jobs = if batch_guard.is_some() {
        jobs
    } else {
        filtered_jobs(jobs, filter)?
    };
    approved_work::bind_approved_work(target, campaign_id, &plan, &mut jobs)?;
    Ok(LoadedPlan {
        jobs,
        batch_guard,
        context_study: plan["kind"] == "context-study",
        case_study: matches!(
            plan["kind"].as_str(),
            Some(
                kuzushi_core::capabilities::campaign::CONTEXT_MATRIX_KIND
                    | kuzushi_core::capabilities::campaign::SCOPE_STUDY_KIND
            )
        ),
    })
}

fn scan_batch_guard(
    campaign_id: &str,
    plan: &Value,
    filter: &[String],
) -> Result<Option<ScanBatchGuard>> {
    if plan["kind"] == kuzushi_core::capabilities::campaign::SCOPE_STUDY_KIND {
        return scope_dispatch_guard(campaign_id, plan, filter).map(Some);
    }
    if plan["kind"] == kuzushi_core::capabilities::campaign::CONTEXT_MATRIX_KIND {
        return matrix_dispatch_guard(campaign_id, plan, filter).map(Some);
    }
    if plan.get("kind").and_then(Value::as_str)
        != Some(kuzushi_core::capabilities::campaign::SCAN_BATCH_KIND)
    {
        return Ok(None);
    }
    anyhow::ensure!(
        filter.is_empty(),
        "scan batches cannot use --jobs exclusions; compile a new batch instead"
    );
    let checked = kuzushi_core::capabilities::campaign::validate_scan_batch_execution_plan(
        campaign_id,
        plan,
    )?;
    Ok(Some(ScanBatchGuard {
        expected_key: checked.equivalence_key,
        base_input: checked.base_input,
        effective_workers: checked.effective_workers,
        trials_planned: checked.trials_planned,
    }))
}

fn scope_dispatch_guard(id: &str, plan: &Value, filter: &[String]) -> Result<ScanBatchGuard> {
    anyhow::ensure!(
        filter.is_empty(),
        "Scope studies cannot exclude jobs; revise and approve remaining work explicitly"
    );
    let scopes = kuzushi_core::capabilities::campaign::validate_scope_study_plan(id, plan)?;
    let first = scopes.first()?;
    Ok(ScanBatchGuard {
        expected_key: first.equivalence.sha256.clone(),
        base_input: first.base_input.clone(),
        effective_workers: plan["effectiveWorkers"]
            .as_u64()
            .context("Scope workers missing")? as usize,
        trials_planned: plan["jobCount"]
            .as_u64()
            .context("Scope job count missing")? as usize,
    })
}

fn matrix_dispatch_guard(id: &str, plan: &Value, filter: &[String]) -> Result<ScanBatchGuard> {
    anyhow::ensure!(
        filter.is_empty(),
        "Context matrices cannot exclude jobs; revise and approve the remaining work explicitly"
    );
    let matrix = kuzushi_core::capabilities::campaign::validate_context_matrix_plan(id, plan)?;
    let baseline = matrix.baseline()?;
    Ok(ScanBatchGuard {
        expected_key: baseline.equivalence.sha256.clone(),
        base_input: baseline.base_input.clone(),
        effective_workers: plan["effectiveWorkers"]
            .as_u64()
            .context("Context matrix workers missing")? as usize,
        trials_planned: plan["jobCount"]
            .as_u64()
            .context("Context matrix job count missing")? as usize,
    })
}

fn enforce_scan_batch_worker_boundary(
    plan: &LoadedPlan,
    settings: &DispatchSettings,
) -> Result<()> {
    if plan.context_study {
        enforce_frozen_worker_count(1, settings.workers)?;
    }
    if let Some(guard) = &plan.batch_guard {
        enforce_frozen_worker_count(guard.effective_workers, settings.workers)?;
    }
    Ok(())
}

fn enforce_frozen_worker_count(expected: usize, received: usize) -> Result<()> {
    anyhow::ensure!(
        received == expected,
        "study plan freezes effective workers at {expected}; dispatcher received {received}"
    );
    Ok(())
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
        approved_attempts: None,
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
    batch_guard: Option<ScanBatchGuard>,
    case_study: bool,
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
        loaded_plan: LoadedPlan,
        settings: DispatchSettings,
    ) -> Result<Self> {
        let lease = acquire_dispatcher_lease(&target, &campaign_id)?;
        let dir = campaign_dir(&target, &campaign_id);
        let logs_dir = dir.join("logs");
        std::fs::create_dir_all(&logs_dir)
            .with_context(|| format!("Could not create {}", logs_dir.display()))?;
        let store = open_dispatch_queue(
            &target,
            &dir,
            &campaign_id,
            &loaded_plan.jobs,
            loaded_plan.batch_guard.as_ref(),
            &settings,
        )?;
        let binary = std::env::current_exe().context("Could not resolve the kuzushi binary")?;
        let wall = QuotaWall::new(settings.quota_wall_threshold);
        Ok(Self {
            target,
            campaign_id,
            binary,
            logs_dir,
            plan_jobs: loaded_plan.jobs,
            batch_guard: loaded_plan.batch_guard,
            case_study: loaded_plan.case_study,
            store,
            settings,
            wall,
            shutdown_rx: shutdown::spawn(lease.control()),
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
            let Some(job) = self.next_job_for_dispatch()? else {
                return Ok(());
            };
            self.start_dispatch_job(running, job)?;
        }
        Ok(())
    }

    fn next_job_for_dispatch(&mut self) -> Result<Option<PlanJob>> {
        if self.stop_before_dispatch()? {
            return Ok(None);
        }
        self.verify_scan_batch_before_launch()?;
        if let Some(reason) = self.dispatch_stop_reason() {
            self.park_pending(reason)?;
            return Ok(None);
        }
        let Some(job) = self.next_ready_job() else {
            return Ok(None);
        };
        if let Some(reason) = allowance_pause::stop_reason(&self.target, &self.campaign_id, &job)? {
            self.park_pending(reason)?;
            return Ok(None);
        }
        Ok(Some(job))
    }

    fn stop_before_dispatch(&mut self) -> Result<bool> {
        if !*self.shutdown_rx.borrow() && !shutdown::requested_or_invalid(&self._lease.control()) {
            return Ok(false);
        }
        self.park_pending("interrupted")?;
        Ok(true)
    }

    fn dispatch_stop_reason(&self) -> Option<&'static str> {
        if self.store.provider_spend_unresolved()
            && !approved_work::call_allowance_covers_unpriced_work(&self.plan_jobs, &self.settings)
        {
            return Some("provider-spend-unresolved");
        }
        budget_exhausted(self.store.total_cost_usd(), self.settings.budget_usd)
            .then_some("budget-exhausted")
    }

    fn start_dispatch_job(
        &mut self,
        running: &mut JoinSet<(String, String, Result<ChildReport>)>,
        job: PlanJob,
    ) -> Result<()> {
        let (attempt, dispatch) = self.next_attempt_numbers(&job.job_id);
        let run_id = format!("{}-{}-a{dispatch}", self.campaign_id, job.job_id);
        self.mark_job_running(&job.job_id, &run_id, attempt, dispatch)?;
        running.spawn(job_future(
            self.child_spec(&job, &run_id),
            job.job_id,
            run_id,
            self.shutdown_rx.clone(),
        ));
        Ok(())
    }

    fn next_attempt_numbers(&self, job_id: &str) -> (u32, u32) {
        let entry = self.store.job(job_id);
        (
            entry.map(|entry| entry.attempts).unwrap_or(0) + 1,
            entry.map(|entry| entry.dispatches).unwrap_or(0) + 1,
        )
    }

    fn mark_job_running(
        &mut self,
        job_id: &str,
        run_id: &str,
        attempt: u32,
        dispatch: u32,
    ) -> Result<()> {
        self.store.update_job(job_id, "job-start", |entry| {
            entry.state = "running".to_string();
            entry.attempts = attempt;
            entry.dispatches = dispatch;
            entry.run_id = Some(run_id.to_string());
            entry.not_before_ms = None;
            entry.record_attempt_start(run_id, attempt, dispatch);
        })
    }

    fn verify_scan_batch_before_launch(&mut self) -> Result<()> {
        let Some(guard) = self.batch_guard.as_ref() else {
            return Ok(());
        };
        if self.next_ready_job().is_none() {
            return Ok(());
        }
        let current = current_batch_equivalence(&self.target, &guard.base_input)?;
        if current.sha256 == guard.expected_key {
            return Ok(());
        }
        let expected = guard.expected_key.clone();
        self.park_pending("batch-equivalence-drift")?;
        self.store.append_event(
            "batch-equivalence-drift",
            None,
            serde_json::json!({ "expected": expected, "actual": current.sha256 }),
        )?;
        anyhow::bail!(
            "scan batch {} stopped before the next trial: BatchEquivalenceKey changed (expected {}, actual {})",
            self.campaign_id,
            expected,
            current.sha256
        )
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
        // The child carries the last strictly authenticated live spend. Settlement
        // must not reread a missing/corrupt stream and erase that lower bound.
        let (cost, provider_spend_unresolved) = campaign_attempt_cost(summary.as_ref(), &report);
        let failure_text = format!(
            "{} {}",
            summary_error.unwrap_or_default(),
            report.output_tail
        );
        let rate_limited = !matches!(
            report.outcome,
            JobOutcome::Completed | JobOutcome::BudgetEvidenceUnavailable
        ) && looks_rate_limited(&failure_text);
        let attempts = self
            .store
            .job(job_id)
            .map(|entry| entry.attempts)
            .unwrap_or(1);
        let transition = approved_work::job_transition(
            self.plan_jobs.iter().find(|job| job.job_id == job_id),
            report.outcome,
            rate_limited,
            attempts,
            &self.settings,
        );
        self.apply_transition(
            job_id,
            run_id,
            &report,
            cost,
            provider_spend_unresolved,
            transition,
        )?;
        if self.wall.observe(rate_limited) {
            self.pause_for_quota_wall()?;
        }
        Ok(())
    }

    fn apply_transition(
        &mut self,
        job_id: &str,
        run_id: &str,
        report: &ChildReport,
        cost: Option<f64>,
        provider_spend_unresolved: bool,
        transition: Transition,
    ) -> Result<()> {
        let outcome = self.batch_attempt_outcome(run_id, report)?;
        let exit_code = report.exit_code;
        self.store.update_job(job_id, &outcome, |entry| {
            entry.exit_code = exit_code;
            entry.cost_usd = accumulated_job_cost(entry.cost_usd, cost);
            entry.provider_spend_unresolved |= provider_spend_unresolved;
            entry.record_attempt_terminal(run_id, &outcome, exit_code, cost);
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

    fn batch_attempt_outcome(&self, run_id: &str, report: &ChildReport) -> Result<String> {
        let outcome = report.outcome.label().to_string();
        if self.batch_guard.is_none() {
            return Ok(outcome);
        }
        use kuzushi_core::run_artifacts::RunArtifactRead;
        match kuzushi_core::run_artifacts::read_run_artifact_text(
            &self.target,
            run_id,
            kuzushi_core::capabilities::campaign::SCAN_BATCH_EQUIVALENCE_RECEIPT_FILE,
        ) {
            RunArtifactRead::Ready { .. } => {
                kuzushi_core::capabilities::campaign::load_scan_batch_child_equivalence_receipt(
                    &self.target,
                    run_id,
                )?;
                Ok(outcome)
            }
            RunArtifactRead::Missing { .. } if report.outcome != JobOutcome::Completed => {
                Ok(kuzushi_core::capabilities::campaign::RECEIPTLESS_ATTEMPT_OUTCOME.to_string())
            }
            RunArtifactRead::Missing { .. } => {
                anyhow::bail!("completed scan-batch child {run_id} omitted its equivalence receipt")
            }
            other => {
                other.require("scan-batch child equivalence receipt")?;
                unreachable!("ready and missing receipt states were handled")
            }
        }
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
        self.print_finish_summary(&summary, cost, provider_spend_unresolved);
        self.publish_case_study_result()?;
        let completed = counts.get("completed").copied().unwrap_or(0);
        let total: usize = counts.values().sum();
        if completed == total {
            return Ok(());
        }
        let exit_code = if self.batch_guard.is_some() { 1 } else { 3 };
        Err(RunCommandExit::new(
            exit_code,
            format!("campaign {}: {summary}", self.campaign_id),
        )
        .into())
    }

    fn publish_case_study_result(&self) -> Result<()> {
        if !self.case_study {
            return Ok(());
        }
        let workspace = kuzushi_core::WorkspaceTarget::new(&self.target)?;
        let findings = kuzushi_core::FindingStore::open_read_only(workspace.findings_db_path())?;
        kuzushi_core::capabilities::campaign::record_scan_batch_phase_result(
            &self.target,
            &self.campaign_id,
            &findings,
        )
        .context("could not save matrix results for explicit Scan acceptance")?;
        Ok(())
    }

    fn print_finish_summary(&self, summary: &str, cost: f64, unresolved: bool) {
        let line = format!(
            "campaign {} finished: {summary}; {}",
            self.campaign_id,
            campaign_cost_label(cost, unresolved)
        );
        if self.batch_guard.is_some() {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    }
}

fn current_batch_equivalence(
    target: &Path,
    base_input: &Value,
) -> Result<kuzushi_core::capabilities::campaign::BatchEquivalenceKey> {
    let config = crate::application::config_diagnostics::load_cli_config(Some(target))?;
    let registry = kuzushi_core::ModuleRegistry::with_v2_builtins();
    kuzushi_core::capabilities::campaign::capture_batch_equivalence(
        target, base_input, &config, &registry,
    )
}

fn campaign_cost_label(observed_usd: f64, provider_spend_unresolved: bool) -> String {
    if provider_spend_unresolved {
        if observed_usd <= 0.0 {
            return "total cost unavailable (provider spend incomplete)".into();
        }
        return format!("total cost >=${observed_usd:.2} (provider spend incomplete)");
    }
    format!("total cost ${observed_usd:.2}")
}

fn open_dispatch_queue(
    target: &Path,
    campaign_dir: &Path,
    campaign_id: &str,
    plan_jobs: &[PlanJob],
    batch_guard: Option<&ScanBatchGuard>,
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
    if let Some(guard) = batch_guard {
        store.require_exact_scan_batch_jobs(&job_ids, guard.trials_planned)?;
    }
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
    report: &ChildReport,
) -> (Option<f64>, bool) {
    let traced = positive_observed_spend(report.observed_spend_usd);
    if let Some(summary) = summary {
        let summarized = summary.cost_usd.or(summary.observed_cost_usd);
        let observed = max_observed_cost(summarized, traced);
        let unresolved =
            summary.provider_spend_unresolved || outcome_requires_unresolved_spend(report.outcome);
        return (observed, unresolved);
    }
    let unresolved = traced.is_some() || outcome_requires_unresolved_spend(report.outcome);
    (traced, unresolved)
}

fn positive_observed_spend(spent_usd: f64) -> Option<f64> {
    (spent_usd > 0.0).then_some(spent_usd + 0.0)
}

fn max_observed_cost(left: Option<f64>, right: Option<f64>) -> Option<f64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right) + 0.0),
        (left, right) => left.or(right),
    }
}

fn outcome_requires_unresolved_spend(outcome: JobOutcome) -> bool {
    matches!(
        outcome,
        JobOutcome::TimedOut
            | JobOutcome::Interrupted
            | JobOutcome::OverBudget
            | JobOutcome::BudgetEvidenceUnavailable
    )
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
    if report.outcome == JobOutcome::BudgetEvidenceUnavailable {
        return Ok(report.outcome);
    }
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

async fn sleep_or_shutdown(wait: Duration, shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    tokio::select! {
        _ = tokio::time::sleep(wait) => {}
        _ = shutdown.changed() => {}
    }
}

#[cfg(test)]
mod batch_worker_receipt_tests {
    use super::*;
    use kuzushi_core::capabilities::campaign::{
        compile_scan_batch_plan, ScanBatchGatePolicy, ScanBatchPlanSpec,
    };
    use kuzushi_core::{ModuleRegistry, V2Config};
    use serde_json::json;

    fn compile_batch(root: &Path) -> String {
        std::fs::write(root.join("source.rs"), "fn main() {}\n").unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        compile_scan_batch_plan(ScanBatchPlanSpec {
            root,
            batch_id: Some("batch-dispatch-auth".to_string()),
            trials: 2,
            requested_workers: 1,
            gate_policy: ScanBatchGatePolicy::default(),
            prepared_input: json!({
                "triage": false,
                "taskMode": "manual",
                "tasks": ["secret-scan"]
            }),
            config: &V2Config::default(),
            registry: &registry,
        })
        .unwrap()
        .campaign_id
    }

    #[test]
    fn dispatcher_requires_the_authenticated_effective_worker_count() {
        assert!(enforce_frozen_worker_count(3, 3).is_ok());
        assert!(enforce_frozen_worker_count(3, 2).is_err());
        assert!(enforce_frozen_worker_count(3, 4).is_err());
    }

    #[test]
    fn scan_batch_job_filtering_is_refused() {
        let target = tempfile::tempdir().unwrap();
        let batch_id = compile_batch(target.path());
        let error = load_plan_jobs(target.path(), &batch_id, &["trial-0001".to_string()])
            .err()
            .unwrap();
        assert!(error.to_string().contains("cannot use --jobs exclusions"));
    }

    #[test]
    fn tampered_batch_is_refused_before_queue_creation() {
        let target = tempfile::tempdir().unwrap();
        let batch_id = compile_batch(target.path());
        let directory = campaign_dir(target.path(), &batch_id);
        let plan_path = directory.join("plan.json");
        let mut plan: Value = serde_json::from_slice(&std::fs::read(&plan_path).unwrap()).unwrap();
        plan["jobs"][0]["input"]["trial"] = json!(2);
        std::fs::write(&plan_path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();

        assert!(load_plan_jobs(target.path(), &batch_id, &[]).is_err());
        assert!(!directory.join("queue.json").exists());
    }

    #[tokio::test]
    async fn public_campaign_run_cannot_bypass_the_batch_controller_or_resume_queue() {
        let target = tempfile::tempdir().unwrap();
        let batch_id = compile_batch(target.path());
        let directory = campaign_dir(target.path(), &batch_id);
        let mut settings = standard_batch_dispatch_settings(1).unwrap();
        settings.resume = true;

        let error = run_loaded_campaign(
            target.path().to_path_buf(),
            batch_id.clone(),
            Vec::new(),
            false,
            settings,
            DispatchAuthority::PublicCampaign,
        )
        .await
        .expect_err("public campaign run must not dispatch a scan batch");

        assert!(error.to_string().contains("raw `campaign run` is refused"));
        assert!(error.to_string().contains("campaign batch"));
        assert!(!directory.join("queue.json").exists());
    }
}

#[cfg(all(test, unix))]
mod dispatcher_recovery_tests;

#[cfg(test)]
mod cost_accounting_tests {
    use super::*;

    fn report(outcome: JobOutcome, observed_spend_usd: f64) -> ChildReport {
        ChildReport {
            outcome,
            exit_code: None,
            output_tail: String::new(),
            observed_spend_usd,
        }
    }

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
        let mut summary = kuzushi_core::RunSummary::running("run-cost", "run", None, "target");
        summary.observed_cost_usd = Some(0.75);
        summary.provider_spend_unresolved = true;

        assert_eq!(
            campaign_attempt_cost(Some(&summary), &report(JobOutcome::ToolFailed, 0.0)),
            (Some(0.75), true)
        );
    }

    #[test]
    fn unavailable_budget_evidence_keeps_validated_spend_as_a_lower_bound() {
        assert_eq!(
            campaign_attempt_cost(None, &report(JobOutcome::BudgetEvidenceUnavailable, 0.75)),
            (Some(0.75), true)
        );
        assert_eq!(
            campaign_attempt_cost(None, &report(JobOutcome::BudgetEvidenceUnavailable, 0.0)),
            (None, true),
            "zero observed spend still leaves provider spend unresolved"
        );
    }

    #[test]
    fn unavailable_budget_evidence_survives_terminal_summary_reconciliation() {
        let mut summary = kuzushi_core::RunSummary::running("run-evidence", "run", None, "target");
        summary.status = "completed".to_string();
        let mut child = report(JobOutcome::BudgetEvidenceUnavailable, 0.0);
        child.exit_code = Some(0);

        assert_eq!(
            reconciled_child_outcome(&child, Some(&summary)).unwrap(),
            JobOutcome::BudgetEvidenceUnavailable
        );
    }

    #[test]
    fn settlement_never_discards_a_higher_validated_live_lower_bound() {
        let mut summary = kuzushi_core::RunSummary::running("run-cost", "run", None, "target");
        summary.observed_cost_usd = Some(0.5);
        assert_eq!(
            campaign_attempt_cost(
                Some(&summary),
                &report(JobOutcome::BudgetEvidenceUnavailable, 0.75)
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
        assert_eq!(
            campaign_cost_label(0.0, true),
            "total cost unavailable (provider spend incomplete)"
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
