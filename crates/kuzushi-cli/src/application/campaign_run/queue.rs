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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<String>,
    /// Epoch ms before which a requeued job must not be redispatched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) not_before_ms: Option<u64>,
}

pub(super) struct QueueStore {
    path: PathBuf,
    events_path: PathBuf,
    pub(super) doc: QueueDoc,
}

impl QueueStore {
    /// Open or create the queue for a campaign. Jobs left `running` by a
    /// dead dispatcher are honestly recovered to `planned` (attempts kept):
    /// their child processes are gone, so the state was a lie.
    pub(super) fn open(
        campaign_dir: &Path,
        campaign_id: &str,
        job_ids: &[String],
        budget_usd: Option<f64>,
        job_budget_usd: Option<f64>,
    ) -> Result<Self> {
        let path = campaign_dir.join("queue.json");
        let events_path = campaign_dir.join("events.jsonl");
        let mut doc = load_or_new_doc(&path, campaign_id)?;
        doc.budget_usd = budget_usd;
        doc.job_budget_usd = job_budget_usd;
        for job_id in job_ids {
            doc.jobs.entry(job_id.clone()).or_insert_with(|| QueueJob {
                state: "planned".to_string(),
                ..QueueJob::default()
            });
        }
        let recovered = recover_stale_running_jobs(&mut doc);
        // Queues written before the dispatch counter existed have run ids
        // minted from `attempts`; start the counter there so the next
        // dispatch cannot re-mint an already-used run id.
        for job in doc.jobs.values_mut() {
            job.dispatches = job.dispatches.max(job.attempts);
        }
        let store = Self {
            path,
            events_path,
            doc,
        };
        store.save()?;
        // Post-mortem timeline: recoveries must be visible in events.jsonl,
        // not just silently flipped in queue.json — a dispatcher that died
        // without a dispatch-end otherwise leaves an unexplained gap.
        for job_id in recovered {
            let run_id = store.job(&job_id).and_then(|job| job.run_id.clone());
            store.append_event(
                "recovered-stale-running",
                Some(&job_id),
                json!({ "runId": run_id, "reason": "recovered from dead dispatcher" }),
            )?;
        }
        Ok(store)
    }

    pub(super) fn job(&self, job_id: &str) -> Option<&QueueJob> {
        self.doc.jobs.get(job_id)
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
        let body = serde_json::to_vec_pretty(&doc).context("Could not serialize queue")?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, body).with_context(|| format!("Could not write {}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("Could not publish {}", self.path.display()))
    }
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
        "parked" => job.reason.as_deref() != Some("prepare-failed"),
        _ => false,
    }
}

fn recover_stale_running_jobs(doc: &mut QueueDoc) -> Vec<String> {
    let mut recovered = Vec::new();
    for (job_id, job) in doc.jobs.iter_mut() {
        if job.state == "running" {
            job.state = "planned".to_string();
            job.reason = Some("recovered from dead dispatcher".to_string());
            recovered.push(job_id.clone());
        }
    }
    recovered
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
        let mut store = QueueStore::open(dir, "camp", &ids, None, None).unwrap();
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

        let store =
            QueueStore::open(tmp.path(), "camp", &["job-a".to_string()], None, None).unwrap();

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
                })
                .unwrap();
            // Simulated SIGKILL: no terminal transition is written.
        }

        let store =
            QueueStore::open(tmp.path(), "camp", &["job-a".to_string()], None, None).unwrap();

        let job = store.job("job-a").unwrap();
        assert_eq!(job.state, "planned");
        assert_eq!(
            job.reason.as_deref(),
            Some("recovered from dead dispatcher")
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
