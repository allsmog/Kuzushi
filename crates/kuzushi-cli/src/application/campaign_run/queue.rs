//! Durable campaign queue state and event log.
//!
//! `queue.json` is the dispatcher-owned lifecycle truth `campaign:status`
//! and the cockpit fold over the plan; it is republished atomically
//! (tmp+rename) after every transition so readers never see a torn
//! document. `events.jsonl` is the append-only transition history.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct QueueDoc {
    pub(super) campaign_id: String,
    pub(super) updated_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) paused_until_ms: Option<u64>,
    /// USD cap of the most recent dispatcher launch; republished on every
    /// open so the cockpit burn bar reflects the live dispatcher, not a
    /// stale earlier launch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) budget_usd: Option<f64>,
    /// Per-job USD ceiling of the most recent dispatcher launch (a plan
    /// row's own `jobBudgetUsd` may tighten it further per job).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) job_budget_usd: Option<f64>,
    pub(super) jobs: BTreeMap<String, QueueJob>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct QueueJob {
    pub(super) state: String,
    #[serde(default)]
    pub(super) attempts: u32,
    /// Total spawns ever made for this job. Unlike `attempts` it is never
    /// reset by `--resume`, because it mints run ids: reusing one would
    /// collide with the previous dispatch's run artifacts.
    #[serde(default)]
    pub(super) dispatches: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) cost_usd: Option<f64>,
    #[serde(default)]
    pub(super) provider_spend_unresolved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<String>,
    /// Epoch ms before which a requeued job must not be redispatched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) not_before_ms: Option<u64>,
    /// Immutable run identities for every spawn of this logical job. The
    /// current `runId` remains a convenience pointer to the latest attempt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) attempt_runs: Vec<QueueAttemptRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct QueueAttemptRun {
    pub(super) run_id: String,
    pub(super) attempt: u32,
    pub(super) dispatch: u32,
    pub(super) started_at_ms: u64,
    pub(super) state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) cost_usd: Option<f64>,
}

impl QueueJob {
    pub(super) fn record_attempt_start(&mut self, run_id: &str, attempt: u32, dispatch: u32) {
        if self.attempt_runs.iter().any(|run| run.run_id == run_id) {
            return;
        }
        self.attempt_runs.push(QueueAttemptRun {
            run_id: run_id.to_string(),
            attempt,
            dispatch,
            started_at_ms: now_ms(),
            state: "running".to_string(),
            outcome: None,
            exit_code: None,
            cost_usd: None,
        });
    }

    pub(super) fn record_attempt_terminal(
        &mut self,
        run_id: &str,
        outcome: &str,
        exit_code: Option<i32>,
        cost_usd: Option<f64>,
    ) {
        let Some(attempt) = self
            .attempt_runs
            .iter_mut()
            .find(|attempt| attempt.run_id == run_id)
        else {
            return;
        };
        attempt.state = "terminal".to_string();
        attempt.outcome = Some(outcome.to_string());
        attempt.exit_code = exit_code;
        attempt.cost_usd = cost_usd;
    }
}

pub(super) struct QueueStore {
    path: PathBuf,
    events_path: PathBuf,
    pub(super) doc: QueueDoc,
}

impl QueueStore {
    /// Open or create the queue for a campaign. A stale `running` row folds
    /// terminal child metadata when present, or returns to `planned` only
    /// when the child never published metadata.
    pub(super) fn open(
        target: &Path,
        campaign_dir: &Path,
        campaign_id: &str,
        job_ids: &[String],
        budget_usd: Option<f64>,
        job_budget_usd: Option<f64>,
    ) -> Result<Self> {
        let path = campaign_dir.join("queue.json");
        let events_path = campaign_dir.join("events.jsonl");
        let mut doc = load_or_new_doc(&path, campaign_id)?;
        anyhow::ensure!(
            doc.campaign_id == campaign_id,
            "campaign queue id disagrees with its directory"
        );
        doc.budget_usd = budget_usd;
        doc.job_budget_usd = job_budget_usd;
        add_missing_jobs(&mut doc, job_ids);
        let recovered = recover_stale_running_jobs(target, &mut doc)?;
        migrate_dispatch_counters(&mut doc);
        let store = Self {
            path,
            events_path,
            doc,
        };
        store.save()?;
        record_recoveries(&store, recovered)?;
        Ok(store)
    }

    pub(super) fn job(&self, job_id: &str) -> Option<&QueueJob> {
        self.doc.jobs.get(job_id)
    }

    pub(super) fn require_exact_scan_batch_jobs(
        &self,
        expected_ids: &[String],
        trials_planned: usize,
    ) -> Result<()> {
        let expected = expected_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        let actual = self
            .doc
            .jobs
            .keys()
            .collect::<std::collections::BTreeSet<_>>();
        anyhow::ensure!(
            expected.len() == trials_planned && actual == expected,
            "scan-batch queue jobs must exactly match trialsPlanned"
        );
        Ok(())
    }

    pub(super) fn update_job(
        &mut self,
        job_id: &str,
        event: &str,
        apply: impl FnOnce(&mut QueueJob),
    ) -> Result<()> {
        let entry = self.doc.jobs.entry(job_id.to_string()).or_default();
        apply(entry);
        let detail = json!({
            "state": entry.state,
            "attempts": entry.attempts,
            "runId": entry.run_id,
            "exitCode": entry.exit_code,
            "reason": entry.reason,
        });
        self.save()?;
        self.append_event(event, Some(job_id), detail)
    }

    /// Return failed and resumably-parked jobs to `planned` with a fresh
    /// attempt budget. Cost history is kept — that money was really spent.
    /// Prepare-failed parks stay parked: same input → same rejection.
    pub(super) fn resume_resumable(&mut self) -> Result<Vec<String>> {
        let ids = self
            .doc
            .jobs
            .iter()
            .filter(|(_, job)| job_is_resumable(job))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in &ids {
            self.update_job(id, "resume", |entry| {
                entry.state = "planned".to_string();
                entry.attempts = 0;
                entry.reason = None;
                entry.exit_code = None;
                entry.not_before_ms = None;
            })?;
        }
        Ok(ids)
    }

    pub(super) fn set_paused_until(&mut self, until_ms: Option<u64>) -> Result<()> {
        self.doc.paused_until_ms = until_ms;
        self.save()?;
        self.append_event("pause", None, json!({ "pausedUntilMs": until_ms }))
    }

    pub(super) fn append_event(
        &self,
        event: &str,
        job_id: Option<&str>,
        detail: serde_json::Value,
    ) -> Result<()> {
        let line = json!({
            "tsMs": now_ms(),
            "event": event,
            "jobId": job_id,
            "detail": detail,
        });
        rotate_events_log_if_oversized(&self.events_path)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.events_path)
            .with_context(|| format!("Could not open {}", self.events_path.display()))?;
        writeln!(file, "{line}")
            .with_context(|| format!("Could not append {}", self.events_path.display()))
    }

    pub(super) fn total_cost_usd(&self) -> f64 {
        // `+ 0.0` normalizes IEEE negative zero from cost-free child runs.
        self.doc
            .jobs
            .values()
            .filter_map(|job| job.cost_usd)
            .sum::<f64>()
            + 0.0
    }

    pub(super) fn provider_spend_unresolved(&self) -> bool {
        self.doc
            .jobs
            .values()
            .any(|job| job.provider_spend_unresolved)
    }

    pub(super) fn state_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for job in self.doc.jobs.values() {
            *counts.entry(job.state.clone()).or_insert(0) += 1;
        }
        counts
    }

    fn save(&self) -> Result<()> {
        let mut doc = serde_json::to_value(&self.doc).context("Could not serialize queue")?;
        doc["updatedAtMs"] = json!(now_ms());
        let body = serde_json::to_string_pretty(&doc).context("Could not serialize queue")?;
        let campaign_dir = self
            .path
            .parent()
            .context("campaign queue path has no parent directory")?;
        kuzushi_core::workspace::write_workspace_file(
            campaign_dir,
            Path::new("queue.json"),
            body.as_bytes(),
        )
        .map(|_| ())
        .with_context(|| format!("Could not publish {}", self.path.display()))
    }
}

fn add_missing_jobs(doc: &mut QueueDoc, job_ids: &[String]) {
    for job_id in job_ids {
        doc.jobs.entry(job_id.clone()).or_insert_with(|| QueueJob {
            state: "planned".to_string(),
            ..QueueJob::default()
        });
    }
}

fn migrate_dispatch_counters(doc: &mut QueueDoc) {
    // Legacy queues minted run ids from `attempts`; start the new counter
    // there so reopening cannot re-mint an already-used run id.
    for job in doc.jobs.values_mut() {
        job.dispatches = job.dispatches.max(job.attempts);
    }
}

fn record_recoveries(store: &QueueStore, recovered: Vec<String>) -> Result<()> {
    for job_id in recovered {
        let job = store.job(&job_id);
        store.append_event(
            "recovered-stale-running",
            Some(&job_id),
            json!({
                "runId": job.and_then(|entry| entry.run_id.clone()),
                "state": job.map(|entry| entry.state.as_str()),
                "reason": job.and_then(|entry| entry.reason.clone()),
            }),
        )?;
    }
    Ok(())
}

fn load_or_new_doc(path: &Path, campaign_id: &str) -> Result<QueueDoc> {
    if !path.exists() {
        return Ok(QueueDoc {
            campaign_id: campaign_id.to_string(),
            updated_at_ms: now_ms(),
            paused_until_ms: None,
            budget_usd: None,
            job_budget_usd: None,
            jobs: BTreeMap::new(),
        });
    }
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("Could not read {}", path.display()))?;
    serde_json::from_str(&body).with_context(|| format!("{} is malformed", path.display()))
}

fn job_is_resumable(job: &QueueJob) -> bool {
    match job.state.as_str() {
        "failed" => true,
        "parked" => !matches!(job.reason.as_deref(), Some("prepare-failed" | "blocked")),
        _ => false,
    }
}

fn recover_stale_running_jobs(target: &Path, doc: &mut QueueDoc) -> Result<Vec<String>> {
    let mut recovered = Vec::new();
    for (job_id, job) in doc.jobs.iter_mut() {
        if job.state != "running" {
            continue;
        }
        recover_running_job(target, job_id, job)?;
        recovered.push(job_id.clone());
    }
    Ok(recovered)
}

fn recover_running_job(target: &Path, job_id: &str, job: &mut QueueJob) -> Result<()> {
    let Some(run_id) = job.run_id.as_deref() else {
        recover_without_child_metadata(job);
        return Ok(());
    };
    let run_id = kuzushi_core::RunId::parse(run_id)
        .with_context(|| format!("campaign job {job_id} has an invalid run id"))?;
    let Some(summary) = load_recoverable_summary(target, job_id, &run_id)? else {
        recover_without_child_metadata(job);
        return Ok(());
    };
    apply_recovered_terminal(job, &summary, job_id)
}

fn load_recoverable_summary(
    target: &Path,
    job_id: &str,
    run_id: &kuzushi_core::RunId,
) -> Result<Option<kuzushi_core::RunSummary>> {
    let metadata = kuzushi_core::run_artifact_path(target, run_id.as_str(), "run.json");
    match std::fs::symlink_metadata(&metadata) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("Could not inspect {}", metadata.display()))
        }
        Ok(_) => {}
    }
    let summary = kuzushi_core::load_run_summary(target, run_id.as_str())
        .with_context(|| format!("could not verify running campaign job {job_id}"))?;
    reject_unrecoverable_running_summary(job_id, run_id.as_str(), &summary)?;
    Ok(Some(summary))
}

fn reject_unrecoverable_running_summary(
    job_id: &str,
    run_id: &str,
    summary: &kuzushi_core::RunSummary,
) -> Result<()> {
    if summary.status != "running" {
        return Ok(());
    }
    let detail = if summary.process_id.is_some() {
        "still has an authenticated live child owner"
    } else {
        "has legacy running metadata without an authenticated process owner"
    };
    anyhow::bail!("campaign job {job_id} {detail} for run {run_id}; refusing automatic recovery")
}

fn apply_recovered_terminal(
    job: &mut QueueJob,
    summary: &kuzushi_core::RunSummary,
    job_id: &str,
) -> Result<()> {
    let run_id = job.run_id.clone();
    let terminal = recovered_terminal_state(&summary.status)
        .with_context(|| format!("campaign job {job_id} has unknown persisted status"))?;
    job.state = terminal.state.to_string();
    job.exit_code = Some(terminal.exit_code);
    job.reason = terminal.reason.map(str::to_string);
    job.cost_usd = accumulated_cost(job.cost_usd, summary.cost_usd.or(summary.observed_cost_usd));
    job.provider_spend_unresolved |= summary.provider_spend_unresolved;
    if let Some(run_id) = run_id {
        job.record_attempt_terminal(
            &run_id,
            &summary.status,
            Some(terminal.exit_code),
            summary.cost_usd.or(summary.observed_cost_usd),
        );
    }
    Ok(())
}

fn recover_without_child_metadata(job: &mut QueueJob) {
    if let Some(run_id) = job.run_id.clone() {
        job.record_attempt_terminal(
            &run_id,
            kuzushi_core::capabilities::campaign::RECEIPTLESS_ATTEMPT_OUTCOME,
            None,
            None,
        );
    }
    job.state = "planned".to_string();
    job.reason = Some("recovered from dead dispatcher before child metadata".to_string());
}

struct RecoveredTerminalState {
    state: &'static str,
    exit_code: i32,
    reason: Option<&'static str>,
}

fn recovered_terminal_state(status: &str) -> Result<RecoveredTerminalState> {
    const STATES: [(&str, &str, i32, Option<&str>); 7] = [
        ("completed", "completed", 0, None),
        ("skipped", "completed", 0, None),
        ("blocked", "parked", 2, Some("blocked")),
        ("canceled", "parked", 130, Some("canceled")),
        ("interrupted", "parked", 3, Some("interrupted")),
        ("failed", "failed", 3, Some("failed")),
        ("partial", "failed", 4, Some("partial")),
    ];
    STATES
        .iter()
        .find(|entry| entry.0 == status)
        .map(|entry| RecoveredTerminalState {
            state: entry.1,
            exit_code: entry.2,
            reason: entry.3,
        })
        .with_context(|| format!("unsupported terminal run status {status:?}"))
}

fn accumulated_cost(prior: Option<f64>, recovered_attempt: Option<f64>) -> Option<f64> {
    recovered_attempt.map_or(prior, |cost| Some(prior.unwrap_or(0.0) + cost + 0.0))
}

/// events.jsonl was the last unbounded append-only campaign artifact: a
/// long-lived campaign with aggressive retries could grow it without limit.
/// One-generation rotation (`events.jsonl` → `events.jsonl.1`) keeps recent
/// history greppable while bounding disk to ~2× the cap.
const EVENTS_LOG_ROTATE_BYTES: u64 = 16 * 1024 * 1024;

fn rotate_events_log_if_oversized(path: &Path) -> Result<()> {
    let size = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("Could not inspect {}", path.display()))
        }
    };
    if size < EVENTS_LOG_ROTATE_BYTES {
        return Ok(());
    }
    let rotated = path.with_extension("jsonl.1");
    std::fs::rename(path, &rotated)
        .with_context(|| format!("Could not rotate {}", path.display()))?;
    eprintln!(
        "campaign: rotated oversized event log to {} ({} bytes)",
        rotated.display(),
        size
    );
    Ok(())
}

pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded_store(
        dir: &Path,
        jobs: &[(&str, &str, Option<&str>, u32, Option<f64>)],
    ) -> QueueStore {
        let ids = jobs
            .iter()
            .map(|(id, ..)| id.to_string())
            .collect::<Vec<_>>();
        let mut store = QueueStore::open(dir, dir, "camp", &ids, None, None).unwrap();
        for (id, state, reason, attempts, cost_usd) in jobs {
            store
                .update_job(id, "seed", |entry| {
                    entry.state = state.to_string();
                    entry.reason = reason.map(str::to_string);
                    entry.attempts = *attempts;
                    entry.cost_usd = *cost_usd;
                    entry.exit_code = Some(3);
                })
                .unwrap();
        }
        store
    }

    #[test]
    fn resume_returns_failed_and_resumable_parks_to_planned_with_fresh_attempts() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = seeded_store(
            tmp.path(),
            &[
                ("job-a", "failed", None, 2, Some(1.5)),
                ("job-b", "parked", Some("over-budget"), 1, Some(5.2)),
                ("job-c", "parked", Some("budget-exhausted"), 0, None),
                ("job-d", "parked", Some("interrupted"), 1, None),
            ],
        );

        let resumed = store.resume_resumable().unwrap();

        assert_eq!(resumed, vec!["job-a", "job-b", "job-c", "job-d"]);
        for id in ["job-a", "job-b", "job-c", "job-d"] {
            let job = store.job(id).unwrap();
            assert_eq!(job.state, "planned", "{id}");
            assert_eq!(job.attempts, 0, "{id}");
            assert_eq!(job.reason, None, "{id}");
            assert_eq!(job.exit_code, None, "{id}");
        }
        // Spend history survives the resume — that money is really gone.
        assert_eq!(store.job("job-b").unwrap().cost_usd, Some(5.2));
        assert!((store.total_cost_usd() - 6.7).abs() < 1e-12);
    }

    #[test]
    fn resume_never_resets_the_dispatch_counter_that_mints_run_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = seeded_store(tmp.path(), &[("job-a", "failed", None, 2, Some(1.5))]);
        store
            .update_job("job-a", "seed-dispatches", |entry| entry.dispatches = 2)
            .unwrap();

        store.resume_resumable().unwrap();

        let job = store.job("job-a").unwrap();
        assert_eq!(job.attempts, 0, "attempts are the retry budget and reset");
        assert_eq!(
            job.dispatches, 2,
            "dispatches mint run ids; resetting them would re-mint a used run id \
             and the budget guard would kill the fresh child on the stale trace"
        );
    }

    #[test]
    fn legacy_queues_start_the_dispatch_counter_at_the_attempt_count() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let mut store = seeded_store(tmp.path(), &[("job-a", "failed", None, 3, None)]);
            // Simulate a pre-dispatch-counter queue on disk.
            store.doc.jobs.get_mut("job-a").unwrap().dispatches = 0;
            store.save().unwrap();
        }

        let store = QueueStore::open(
            tmp.path(),
            tmp.path(),
            "camp",
            &["job-a".to_string()],
            None,
            None,
        )
        .unwrap();

        assert_eq!(
            store.job("job-a").unwrap().dispatches,
            3,
            "run ids a1..a3 were minted from attempts before the counter existed"
        );
    }

    /// Post-mortem contract: a dispatcher killed mid-campaign leaves rows
    /// `running`; the next open recovers them AND records the recovery in
    /// events.jsonl with the run id, so `grep <runId>` explains the gap.
    #[test]
    fn dead_dispatcher_recovery_is_recorded_in_the_event_log() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let mut store = seeded_store(tmp.path(), &[("job-a", "planned", None, 1, None)]);
            store
                .update_job("job-a", "job-start", |entry| {
                    entry.state = "running".to_string();
                    entry.run_id = Some("camp-job-a-a1".to_string());
                    entry.record_attempt_start("camp-job-a-a1", 1, 1);
                })
                .unwrap();
            // Simulated SIGKILL: no terminal transition is written.
        }

        let store = QueueStore::open(
            tmp.path(),
            tmp.path(),
            "camp",
            &["job-a".to_string()],
            None,
            None,
        )
        .unwrap();

        let job = store.job("job-a").unwrap();
        assert_eq!(job.state, "planned");
        assert_eq!(
            job.reason.as_deref(),
            Some("recovered from dead dispatcher before child metadata")
        );
        assert_eq!(
            job.attempt_runs[0].outcome.as_deref(),
            Some(kuzushi_core::capabilities::campaign::RECEIPTLESS_ATTEMPT_OUTCOME)
        );
        let events = std::fs::read_to_string(tmp.path().join("events.jsonl")).unwrap();
        let recovery = events
            .lines()
            .filter(|line| line.contains("recovered-stale-running"))
            .collect::<Vec<_>>();
        assert_eq!(recovery.len(), 1, "{events}");
        assert!(recovery[0].contains("camp-job-a-a1"), "{}", recovery[0]);
        assert!(recovery[0].contains("job-a"));
    }

    #[test]
    fn live_running_job_identity_refuses_recovery_without_queue_mutation() {
        let target = tempfile::tempdir().unwrap();
        let campaign = target.path().join("campaign");
        std::fs::create_dir_all(&campaign).unwrap();
        let run_id = "camp-job-live-a1";
        seed_live_running_job(target.path(), &campaign, run_id);
        let queue_path = campaign.join("queue.json");
        let before = std::fs::read(&queue_path).unwrap();

        let error = QueueStore::open(
            target.path(),
            &campaign,
            "camp",
            &["job-live".to_string()],
            None,
            None,
        )
        .err()
        .expect("a live child owner must block stale recovery");

        assert!(error
            .to_string()
            .contains("still has an authenticated live child owner"));
        assert_eq!(std::fs::read(queue_path).unwrap(), before);
    }

    #[test]
    fn legacy_running_summary_without_process_identity_refuses_recovery() {
        let summary = kuzushi_core::RunSummary::running("legacy-run", "run", None, "target");

        let error = reject_unrecoverable_running_summary("job-legacy", "legacy-run", &summary)
            .expect_err("legacy running metadata has no authenticated owner");

        assert!(error.to_string().contains("legacy running metadata"));
        assert!(error.to_string().contains("refusing automatic recovery"));
    }

    fn seed_live_running_job(target: &Path, campaign: &Path, run_id: &str) {
        let mut store = QueueStore::open(
            target,
            campaign,
            "camp",
            &["job-live".to_string()],
            None,
            None,
        )
        .unwrap();
        store
            .update_job("job-live", "job-start", |entry| {
                entry.state = "running".to_string();
                entry.run_id = Some(run_id.to_string());
            })
            .unwrap();
        let summary = kuzushi_core::RunSummary::running(run_id, "run", None, "target")
            .with_process_id(std::process::id());
        kuzushi_core::write_run_summary(target, &summary).unwrap();
    }

    #[test]
    fn terminal_child_recovery_never_replans_completed_work() {
        let completed = recovered_terminal_state("completed").unwrap();
        assert_eq!(completed.state, "completed");
        assert_eq!(completed.exit_code, 0);
        assert_eq!(completed.reason, None);

        let failed = recovered_terminal_state("failed").unwrap();
        assert_eq!(failed.state, "failed");
        assert_eq!(failed.reason, Some("failed"));

        assert!(recovered_terminal_state("running").is_err());
        assert_eq!(accumulated_cost(Some(1.25), Some(0.75)), Some(2.0));
    }

    #[test]
    fn recovered_terminal_applies_state_cost_and_spend_truth() {
        let mut job = QueueJob {
            state: "running".to_string(),
            cost_usd: Some(1.25),
            ..QueueJob::default()
        };
        let mut summary =
            kuzushi_core::RunSummary::running("run-a", "run", None, "target").complete();
        summary.cost_usd = Some(0.75);
        summary.provider_spend_unresolved = true;

        apply_recovered_terminal(&mut job, &summary, "job-a").unwrap();

        assert_eq!(job.state, "completed");
        assert_eq!(job.exit_code, Some(0));
        assert_eq!(job.reason, None);
        assert_eq!(job.cost_usd, Some(2.0));
        assert!(job.provider_spend_unresolved);
    }

    #[test]
    fn queue_save_does_not_reuse_a_fixed_temp_sibling() {
        let tmp = tempfile::tempdir().unwrap();
        let fixed_temp = tmp.path().join("queue.json.tmp");
        std::fs::write(&fixed_temp, "unrelated staging file").unwrap();
        let mut store = seeded_store(tmp.path(), &[("job-a", "planned", None, 0, None)]);

        store
            .update_job("job-a", "job-start", |entry| {
                entry.state = "running".to_string()
            })
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(fixed_temp).unwrap(),
            "unrelated staging file"
        );
        let queue: serde_json::Value =
            serde_json::from_slice(&std::fs::read(tmp.path().join("queue.json")).unwrap()).unwrap();
        assert_eq!(queue["jobs"]["job-a"]["state"], "running");
    }

    #[test]
    fn unresolved_provider_spend_survives_queue_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let mut store = seeded_store(tmp.path(), &[("job-a", "completed", None, 1, None)]);
            store
                .update_job("job-a", "settle", |entry| {
                    entry.cost_usd = Some(0.75);
                    entry.provider_spend_unresolved = true;
                })
                .unwrap();
        }

        let store = QueueStore::open(
            tmp.path(),
            tmp.path(),
            "camp",
            &["job-a".to_string()],
            None,
            None,
        )
        .unwrap();

        assert_eq!(store.total_cost_usd(), 0.75);
        assert!(store.provider_spend_unresolved());
    }

    #[test]
    fn oversized_event_log_rotates_one_generation_before_appending() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = seeded_store(tmp.path(), &[("job-a", "planned", None, 0, None)]);
        let events = tmp.path().join("events.jsonl");
        let oversized = vec![b'x'; EVENTS_LOG_ROTATE_BYTES as usize];
        std::fs::write(&events, oversized).unwrap();

        store
            .update_job("job-a", "job-start", |entry| {
                entry.state = "running".to_string();
            })
            .unwrap();

        let rotated = tmp.path().join("events.jsonl.1");
        assert!(rotated.exists(), "oversized log must rotate");
        assert_eq!(
            std::fs::metadata(&rotated).unwrap().len(),
            EVENTS_LOG_ROTATE_BYTES
        );
        let fresh = std::fs::read_to_string(&events).unwrap();
        assert!(fresh.contains("job-start"), "{fresh}");
        assert!(
            std::fs::metadata(&events).unwrap().len() < 4096,
            "fresh log must start near-empty"
        );
    }

    #[test]
    fn resume_leaves_prepare_failed_parks_and_terminal_successes_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = seeded_store(
            tmp.path(),
            &[
                ("job-done", "completed", None, 1, Some(2.0)),
                ("job-rejected", "parked", Some("prepare-failed"), 1, None),
                ("job-fresh", "planned", None, 0, None),
            ],
        );

        let resumed = store.resume_resumable().unwrap();

        assert!(resumed.is_empty());
        assert_eq!(store.job("job-done").unwrap().state, "completed");
        assert_eq!(store.job("job-rejected").unwrap().state, "parked");
        assert_eq!(
            store.job("job-rejected").unwrap().reason.as_deref(),
            Some("prepare-failed")
        );
    }
}
