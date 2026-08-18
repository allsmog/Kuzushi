//! One campaign job = one bounded `kuzushi run` child process.
//!
//! Children run through the shared scan cancellation registry so a per-job
//! timeout (or dispatcher shutdown) kills the whole tree. Unix uses a guarded
//! process group with a parent-death lifeline; Windows uses a kill-on-close Job
//! Object. A scanner subprocess must never outlive its campaign job.

use super::budget::{BudgetEvidenceDecision, BudgetEvidenceGuard, LiveSpendPoller};
use super::policy::{budget_exhausted, JobOutcome};
use anyhow::{Context, Result};
use kuzushi_core::scan::{PreparedProcessGroup, RegisteredChild, ScanCancellation};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

pub(super) struct ChildSpec {
    pub(super) binary: PathBuf,
    pub(super) target: PathBuf,
    pub(super) tool: String,
    pub(super) input_json: String,
    pub(super) run_id: String,
    pub(super) log_path: PathBuf,
    pub(super) timeout: Duration,
    /// Per-job USD ceiling; while the child runs, its live traced spend is
    /// polled and crossing the ceiling kills the process group.
    pub(super) job_budget_usd: Option<f64>,
}

/// How often a budgeted child's live trace is re-summed. Coarse on purpose:
/// one model call costs cents to dollars, so second-scale polling bounds the
/// overshoot to roughly one in-flight call.
const BUDGET_POLL: Duration = Duration::from_secs(2);
const CHILD_STATUS_POLL: Duration = Duration::from_millis(50);

pub(super) struct ChildReport {
    pub(super) outcome: JobOutcome,
    pub(super) exit_code: Option<i32>,
    /// Tail of the child's combined output for rate-limit sniffing.
    pub(super) output_tail: String,
    /// Last strictly authenticated lifecycle spend. This is a lower bound when
    /// the child was killed before terminal settlement.
    pub(super) observed_spend_usd: f64,
}

struct SupervisionReport {
    outcome: JobOutcome,
    exit_code: Option<i32>,
    observed_spend_usd: f64,
}

/// Spawn, bound, and reap one job child. Cancellation (dispatcher shutdown)
/// and timeout both kill the child's process group, then still await the
/// child so no zombie survives the dispatcher.
pub(super) async fn run_child(
    spec: &ChildSpec,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<ChildReport> {
    let log = std::fs::File::create(&spec.log_path)
        .with_context(|| format!("Could not create {}", spec.log_path.display()))?;
    let (mut command, group) = child_command(spec, log)?;
    let child = command
        .spawn()
        .with_context(|| format!("Could not spawn {}", spec.binary.display()))?;
    let cancellation = ScanCancellation::default();
    let child = cancellation
        .register_prepared_child(child, group)
        .context("Could not supervise campaign job child")?;
    let supervised = supervise_child(&child, spec, shutdown).await?;
    Ok(ChildReport {
        outcome: supervised.outcome,
        exit_code: supervised.exit_code,
        output_tail: log_tail(&spec.log_path),
        observed_spend_usd: supervised.observed_spend_usd,
    })
}

async fn supervise_child(
    child: &RegisteredChild,
    spec: &ChildSpec,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<SupervisionReport> {
    let timeout = tokio::time::sleep(spec.timeout);
    tokio::pin!(timeout);
    let mut spend = LiveSpendPoller::new(&spec.target, &spec.run_id);
    let mut guard = BudgetEvidenceGuard::default();
    let mut spend_poll = tokio::time::interval(BUDGET_POLL);
    spend_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut status_poll = tokio::time::interval(CHILD_STATUS_POLL);
    loop {
        tokio::select! {
            _ = status_poll.tick() => {
                if let Some(status) = child.try_wait().context("Could not poll job child")? {
                    return Ok(exited_child(status.code(), spec, &mut spend, &mut guard));
                }
            }
            _ = &mut timeout => {
                return terminal_stop(child, JobOutcome::TimedOut, spec, &mut spend, &mut guard);
            }
            _ = shutdown.changed() => {
                return terminal_stop(child, JobOutcome::Interrupted, spec, &mut spend, &mut guard);
            }
            _ = spend_poll.tick(), if spec.job_budget_usd.is_some() => {
                if let Some(report) = budget_stop(child, spec, &mut spend, &mut guard)? {
                    return Ok(report);
                }
            }
        }
    }
}

fn exited_child(
    code: Option<i32>,
    spec: &ChildSpec,
    spend_poller: &mut LiveSpendPoller,
    evidence_guard: &mut BudgetEvidenceGuard,
) -> SupervisionReport {
    terminal_report(
        JobOutcome::from_exit_code(code),
        code,
        spec,
        spend_poller,
        evidence_guard,
    )
}

fn terminal_stop(
    child: &RegisteredChild,
    outcome: JobOutcome,
    spec: &ChildSpec,
    spend_poller: &mut LiveSpendPoller,
    evidence_guard: &mut BudgetEvidenceGuard,
) -> Result<SupervisionReport> {
    let report = terminal_report(outcome, None, spec, spend_poller, evidence_guard);
    stop_child(child, report.outcome, report.observed_spend_usd)
}

fn terminal_report(
    outcome: JobOutcome,
    exit_code: Option<i32>,
    spec: &ChildSpec,
    spend_poller: &mut LiveSpendPoller,
    evidence_guard: &mut BudgetEvidenceGuard,
) -> SupervisionReport {
    let poll = spend_poller.poll();
    let decision = match spec.job_budget_usd {
        Some(_) => evidence_guard.observe(poll),
        None => BudgetEvidenceDecision::Continue {
            spent_usd: poll.spent_usd(),
        },
    };
    match decision {
        BudgetEvidenceDecision::Continue { spent_usd } => SupervisionReport {
            outcome,
            exit_code,
            observed_spend_usd: spent_usd,
        },
        BudgetEvidenceDecision::Stop { spent_usd, reason } => {
            report_evidence_loss(spec, spent_usd, reason.label());
            SupervisionReport {
                outcome: JobOutcome::BudgetEvidenceUnavailable,
                exit_code,
                observed_spend_usd: spent_usd,
            }
        }
    }
}

fn budget_stop(
    child: &RegisteredChild,
    spec: &ChildSpec,
    spend_poller: &mut LiveSpendPoller,
    evidence_guard: &mut BudgetEvidenceGuard,
) -> Result<Option<SupervisionReport>> {
    match evidence_guard.observe(spend_poller.poll()) {
        BudgetEvidenceDecision::Continue { spent_usd }
            if budget_exhausted(spent_usd, spec.job_budget_usd) =>
        {
            eprintln!(
                "campaign: job run {} crossed its ${:.2} job budget (live spend ${spent_usd:.2}) — stopping it",
                spec.run_id,
                spec.job_budget_usd.unwrap_or_default(),
            );
            stop_child(child, JobOutcome::OverBudget, spent_usd).map(Some)
        }
        BudgetEvidenceDecision::Continue { .. } => Ok(None),
        BudgetEvidenceDecision::Stop { spent_usd, reason } => {
            report_evidence_loss(spec, spent_usd, reason.label());
            stop_child(child, JobOutcome::BudgetEvidenceUnavailable, spent_usd).map(Some)
        }
    }
}

fn report_evidence_loss(spec: &ChildSpec, spent_usd: f64, reason: &str) {
    eprintln!(
        "campaign: job run {} lost live budget evidence after ${spent_usd:.2} observed ({reason})",
        spec.run_id,
    );
}

fn stop_child(
    child: &RegisteredChild,
    outcome: JobOutcome,
    observed_spend_usd: f64,
) -> Result<SupervisionReport> {
    child
        .kill_and_wait()
        .context("Could not stop campaign job child")?;
    Ok(SupervisionReport {
        outcome,
        exit_code: None,
        observed_spend_usd,
    })
}

fn child_command(
    spec: &ChildSpec,
    log: std::fs::File,
) -> Result<(std::process::Command, PreparedProcessGroup)> {
    let log_err = log.try_clone().context("Could not clone job log handle")?;
    let mut command = std::process::Command::new(&spec.binary);
    command
        .arg("--plain")
        .arg("--target")
        .arg(&spec.target)
        .arg("run")
        .arg(&spec.tool)
        .arg("--input")
        .arg(&spec.input_json)
        .arg("--run-id")
        .arg(&spec.run_id)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    let group = PreparedProcessGroup::configure(&mut command)
        .context("Could not prepare the job process group guard")?;
    Ok((command, group))
}

const LOG_TAIL_BYTES: u64 = 16 * 1024;

fn log_tail(path: &Path) -> String {
    let Ok(bytes) = std::fs::read(path) else {
        return String::new();
    };
    let skip = bytes.len().saturating_sub(LOG_TAIL_BYTES as usize);
    String::from_utf8_lossy(&bytes[skip..]).to_string()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn spec(dir: &Path, binary: PathBuf, run_id: &str, job_budget_usd: Option<f64>) -> ChildSpec {
        ChildSpec {
            binary,
            target: dir.to_path_buf(),
            tool: "noop:tool".to_string(),
            input_json: "{}".to_string(),
            run_id: run_id.to_string(),
            log_path: dir.join(format!("{run_id}.log")),
            timeout: Duration::from_secs(30),
            job_budget_usd,
        }
    }

    /// A stand-in child binary that ignores the `kuzushi run` argv contract.
    fn fake_child(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn write_over_cap_lifecycle(target: &Path, run_id: &str, usd: f64) {
        use kuzushi_core::run_lifecycle::{RunCallId, RunItemId, RunItemWriter};
        let writer = RunItemWriter::open(target, run_id, None).unwrap();
        let item_id = RunItemId::new();
        let call_id = RunCallId::new();
        write_model_start(&writer, item_id, call_id);
        write_model_finish(&writer, item_id, call_id, usd);
    }

    fn write_model_start(
        writer: &kuzushi_core::run_lifecycle::RunItemWriter,
        item_id: kuzushi_core::run_lifecycle::RunItemId,
        call_id: kuzushi_core::run_lifecycle::RunCallId,
    ) {
        use kuzushi_core::run_lifecycle::*;
        let item = RunItemV1::ModelCallStarted {
            provider: SafeText::operator_visible("test"),
            model: SafeText::operator_visible("test:model"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"campaign"),
        };
        writer
            .emit_and_flush(
                RunItemRecord::new(item_id, RunItemSource::Runtime, item).with_call(call_id),
            )
            .unwrap();
    }

    fn write_model_finish(
        writer: &kuzushi_core::run_lifecycle::RunItemWriter,
        item_id: kuzushi_core::run_lifecycle::RunItemId,
        call_id: kuzushi_core::run_lifecycle::RunCallId,
        usd: f64,
    ) {
        use kuzushi_core::run_lifecycle::*;
        let cost = kuzushi_core::runtime::RuntimeCostReport::known(
            kuzushi_core::runtime::RuntimeCost::from_usd(usd, "campaign test").unwrap(),
        );
        let item = RunItemV1::ModelCallFinished {
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
            failure: None,
        };
        writer
            .emit_and_flush(
                RunItemRecord::new(item_id, RunItemSource::Runtime, item).with_call(call_id),
            )
            .unwrap();
    }

    fn write_malformed_lifecycle(target: &Path, run_id: &str) {
        let path = kuzushi_core::run_artifacts::run_artifact_path(target, run_id, "items.jsonl");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"{not-json}\n").unwrap();
    }

    #[test]
    fn log_tail_keeps_exactly_the_last_sixteen_kibibytes() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("campaign.log");
        let prefix = vec![b'x'; 2_048];
        let expected_tail = vec![b'y'; 16_384];
        std::fs::write(&path, [prefix, expected_tail.clone()].concat()).unwrap();

        let tail = log_tail(&path);

        assert_eq!(tail.as_bytes(), expected_tail);
    }

    #[test]
    fn terminal_refresh_preserves_unavailable_budget_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        write_malformed_lifecycle(tmp.path(), "terminal-corrupt");
        let child_spec = spec(
            tmp.path(),
            tmp.path().join("unused"),
            "terminal-corrupt",
            Some(5.0),
        );

        for (outcome, exit_code) in [
            (JobOutcome::Completed, Some(0)),
            (JobOutcome::TimedOut, None),
        ] {
            let mut poller = LiveSpendPoller::new(tmp.path(), "terminal-corrupt");
            let mut guard = BudgetEvidenceGuard::default();
            let report = terminal_report(outcome, exit_code, &child_spec, &mut poller, &mut guard);
            assert_eq!(report.outcome, JobOutcome::BudgetEvidenceUnavailable);
            assert_eq!(report.exit_code, exit_code);
            assert_eq!(report.observed_spend_usd, 0.0);
        }
    }

    #[tokio::test]
    async fn a_running_child_over_its_job_budget_is_killed_and_reported_over_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let binary = fake_child(tmp.path(), "sleeper", "sleep 30");
        write_over_cap_lifecycle(tmp.path(), "burning", 9.9);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let started = std::time::Instant::now();
        let report = run_child(&spec(tmp.path(), binary, "burning", Some(5.0)), rx)
            .await
            .unwrap();
        assert_eq!(report.outcome, JobOutcome::OverBudget);
        assert_eq!(report.exit_code, None);
        assert!((report.observed_spend_usd - 9.9).abs() < 1e-12);
        assert!(started.elapsed() < Duration::from_secs(20));
    }

    #[tokio::test]
    async fn durable_budget_evidence_corruption_kills_and_reaps_the_child() {
        let tmp = tempfile::tempdir().unwrap();
        let binary = fake_child(tmp.path(), "corrupt-sleeper", "sleep 30");
        write_malformed_lifecycle(tmp.path(), "corrupt");
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let started = std::time::Instant::now();
        let report = run_child(&spec(tmp.path(), binary, "corrupt", Some(5.0)), rx)
            .await
            .unwrap();
        assert_eq!(report.outcome, JobOutcome::BudgetEvidenceUnavailable);
        assert_eq!(report.exit_code, None);
        assert_eq!(report.observed_spend_usd, 0.0);
        assert!(started.elapsed() < Duration::from_secs(20));
    }

    #[tokio::test]
    async fn an_unbudgeted_child_never_enforces_the_job_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let binary = fake_child(tmp.path(), "clean-exit", "exit 0");
        write_over_cap_lifecycle(tmp.path(), "uncapped", 99.0);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let report = run_child(&spec(tmp.path(), binary, "uncapped", None), rx)
            .await
            .unwrap();
        assert_eq!(report.outcome, JobOutcome::Completed);
        assert_eq!(report.exit_code, Some(0));
        assert!((report.observed_spend_usd - 99.0).abs() < 1e-12);
    }

    /// A completed job must not leave background grandchildren behind: the
    /// guard group is SIGKILLed when the job's report is folded.
    #[tokio::test]
    async fn job_grandchildren_die_when_the_job_completes() {
        let tmp = tempfile::tempdir().unwrap();
        let grand_pid_path = tmp.path().join("grand.pid");
        let binary = fake_child(
            tmp.path(),
            "forker",
            &format!("sleep 60 & echo $! > {}", grand_pid_path.display()),
        );
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let report = run_child(&spec(tmp.path(), binary, "forking", None), rx)
            .await
            .unwrap();
        assert_eq!(report.outcome, JobOutcome::Completed);

        let grand_pid: i32 = std::fs::read_to_string(&grand_pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let alive = std::fs::read_to_string(format!("/proc/{grand_pid}/stat"))
                .map(|stat| !stat.contains(") Z ") && !stat.contains(") X "))
                .unwrap_or(false);
            if !alive {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "grandchild {grand_pid} survived job completion"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[tokio::test]
    async fn a_budgeted_child_under_its_cap_runs_to_completion() {
        let tmp = tempfile::tempdir().unwrap();
        let binary = fake_child(tmp.path(), "cheap", "exit 0");
        write_over_cap_lifecycle(tmp.path(), "cheap-run", 0.5);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let report = run_child(&spec(tmp.path(), binary, "cheap-run", Some(5.0)), rx)
            .await
            .unwrap();
        assert_eq!(report.outcome, JobOutcome::Completed);
        assert!((report.observed_spend_usd - 0.5).abs() < 1e-12);
    }
}
