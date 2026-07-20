//! One campaign job = one bounded `kuzushi run` child process.
//!
//! Children run in their own process group so a per-job timeout (or a
//! dispatcher shutdown) can kill the whole tree — a scanner subprocess must
//! never outlive its job. Because group membership detaches children from
//! the terminal's Ctrl+C, the dispatcher forwards shutdown kills explicitly.

use super::budget::live_run_spend_usd;
use super::policy::{budget_exhausted, JobOutcome};
use anyhow::{Context, Result};
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
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<ChildReport> {
    let log = std::fs::File::create(&spec.log_path)
        .with_context(|| format!("Could not create {}", spec.log_path.display()))?;
    let mut child = child_command(spec, log)?
        .spawn()
        .with_context(|| format!("Could not spawn {}", spec.binary.display()))?;
    let group_pid = child.id();
    let timeout = tokio::time::sleep(spec.timeout);
    tokio::pin!(timeout);
    let mut poll = tokio::time::interval(BUDGET_POLL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let outcome = loop {
        tokio::select! {
            status = child.wait() => {
                let code = status.context("Could not reap job child")?.code();
                break (JobOutcome::from_exit_code(code), code);
            }
            _ = &mut timeout => {
                kill_process_group(group_pid).await;
                let _ = child.wait().await;
                break (JobOutcome::TimedOut, None);
            }
            _ = shutdown.changed() => {
                kill_process_group(group_pid).await;
                let _ = child.wait().await;
                break (JobOutcome::Interrupted, None);
            }
            _ = poll.tick(), if spec.job_budget_usd.is_some() => {
                let spent = live_run_spend_usd(&spec.target, &spec.run_id);
                if budget_exhausted(spent, spec.job_budget_usd) {
                    eprintln!(
                        "campaign: job run {} crossed its ${:.2} job budget (live spend ${spent:.2}) — stopping it",
                        spec.run_id,
                        spec.job_budget_usd.unwrap_or_default(),
                    );
                    kill_process_group(group_pid).await;
                    let _ = child.wait().await;
                    break (JobOutcome::OverBudget, None);
                }
            }
        }
    };
    Ok(ChildReport {
        outcome: outcome.0,
        exit_code: outcome.1,
        output_tail: log_tail(&spec.log_path),
    })
}

fn child_command(spec: &ChildSpec, log: std::fs::File) -> Result<tokio::process::Command> {
    let log_err = log.try_clone().context("Could not clone job log handle")?;
    let mut command = tokio::process::Command::new(&spec.binary);
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
        .stderr(Stdio::from(log_err))
        .process_group(0)
        .kill_on_drop(true);
    Ok(command)
}

/// SIGKILL the child's whole process group (`pgid == child pid` because of
/// `process_group(0)`). Uses /bin/kill so we need no signal-crate dependency.
async fn kill_process_group(pid: Option<u32>) {
    let Some(pid) = pid else {
        return;
    };
    let _ = tokio::process::Command::new("kill")
        .arg("-9")
        .arg("--")
        .arg(format!("-{pid}"))
        .status()
        .await;
}

const LOG_TAIL_BYTES: u64 = 16 * 1024;

fn log_tail(path: &Path) -> String {
    let Ok(bytes) = std::fs::read(path) else {
        return String::new();
    };
    let skip = bytes.len().saturating_sub(LOG_TAIL_BYTES as usize);
    String::from_utf8_lossy(&bytes[skip..]).to_string()
}

#[cfg(test)]
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

    fn write_over_cap_trace(target: &Path, run_id: &str, usd: f64) {
        let path = kuzushi_core::run_artifacts::run_artifact_path(target, run_id, "trace.jsonl");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            path,
            format!(
                r#"{{"n":1,"kind":"reasoning","label":"model","latency_ms":1,"cost_usd":{usd},"model":"m","provider":"p","prompt_hash":"h"}}"#
            ),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn a_running_child_over_its_job_budget_is_killed_and_reported_over_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let binary = fake_child(tmp.path(), "sleeper", "sleep 30");
        write_over_cap_trace(tmp.path(), "burning", 9.9);
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
        // A trace far over any cap must be ignored when no cap is set.
        write_over_cap_trace(tmp.path(), "uncapped", 99.0);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let report = run_child(&spec(tmp.path(), binary, "uncapped", None), rx)
            .await
            .unwrap();
        assert_eq!(report.outcome, JobOutcome::Completed);
        assert_eq!(report.exit_code, Some(0));
    }

    #[tokio::test]
    async fn a_budgeted_child_under_its_cap_runs_to_completion() {
        let tmp = tempfile::tempdir().unwrap();
        let binary = fake_child(tmp.path(), "cheap", "exit 0");
        write_over_cap_trace(tmp.path(), "cheap-run", 0.5);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let report = run_child(&spec(tmp.path(), binary, "cheap-run", Some(5.0)), rx)
            .await
            .unwrap();
        assert_eq!(report.outcome, JobOutcome::Completed);
    }
}
