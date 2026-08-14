//! One campaign job = one bounded `kuzushi run` child process.
//!
//! Children run through the shared scan cancellation registry so a per-job
//! timeout (or dispatcher shutdown) kills the whole tree. Unix uses a guarded
//! process group with a parent-death lifeline; Windows uses a kill-on-close Job
//! Object. A scanner subprocess must never outlive its campaign job.

use super::budget::LiveSpendPoller;
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
    let outcome = supervise_child(&child, spec, shutdown).await?;
    Ok(ChildReport {
        outcome: outcome.0,
        exit_code: outcome.1,
        output_tail: log_tail(&spec.log_path),
    })
}

async fn supervise_child(
    child: &RegisteredChild,
    spec: &ChildSpec,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(JobOutcome, Option<i32>)> {
    let timeout = tokio::time::sleep(spec.timeout);
    tokio::pin!(timeout);
    let mut spend_poller = LiveSpendPoller::new(&spec.target, &spec.run_id);
    let mut spend_poll = tokio::time::interval(BUDGET_POLL);
    spend_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut status_poll = tokio::time::interval(CHILD_STATUS_POLL);
    loop {
        tokio::select! {
            _ = status_poll.tick() => {
                if let Some(status) = child.try_wait().context("Could not poll job child")? {
                    let code = status.code();
                    return Ok((JobOutcome::from_exit_code(code), code));
                }
            }
            _ = &mut timeout => {
                return stop_child(child, JobOutcome::TimedOut);
            }
            _ = shutdown.changed() => {
                return stop_child(child, JobOutcome::Interrupted);
            }
            _ = spend_poll.tick(), if spec.job_budget_usd.is_some() => {
                let spent = spend_poller.poll();
                if budget_exhausted(spent, spec.job_budget_usd) {
                    eprintln!(
                        "campaign: job run {} crossed its ${:.2} job budget (live spend ${spent:.2}) — stopping it",
                        spec.run_id,
                        spec.job_budget_usd.unwrap_or_default(),
                    );
                    return stop_child(child, JobOutcome::OverBudget);
                }
            }
        }
    }
}

fn stop_child(child: &RegisteredChild, outcome: JobOutcome) -> Result<(JobOutcome, Option<i32>)> {
    child
        .kill_and_wait()
        .context("Could not stop campaign job child")?;
    Ok((outcome, None))
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
        // The first poll tick fires immediately — the kill must not wait
        // out the sleeping child or the per-job timeout.
        assert!(started.elapsed() < Duration::from_secs(20));
    }

    #[tokio::test]
    async fn an_unbudgeted_child_never_polls_and_completes_on_its_exit_code() {
        let tmp = tempfile::tempdir().unwrap();
        let binary = fake_child(tmp.path(), "clean-exit", "exit 0");
        // Lifecycle spend far over any cap must be ignored when no cap is set.
        write_over_cap_lifecycle(tmp.path(), "uncapped", 99.0);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let report = run_child(&spec(tmp.path(), binary, "uncapped", None), rx)
            .await
            .unwrap();
        assert_eq!(report.outcome, JobOutcome::Completed);
        assert_eq!(report.exit_code, Some(0));
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
    }
}
