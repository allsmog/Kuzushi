use anyhow::{bail, Context, Result};
use kuzushi_core::{list_run_summaries, run_dir, RunSummary, WorkspaceTarget};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

const DAY_SECONDS: u64 = 86_400;

pub(crate) fn runs_prune_command(
    target: Option<PathBuf>,
    older_than_days: Option<u64>,
    keep_last: Option<usize>,
    dry_run: bool,
    json: bool,
) -> Result<()> {
    let workspace = WorkspaceTarget::new(target.unwrap_or_else(|| PathBuf::from(".")))?;
    let runs = list_run_summaries(workspace.root())?;
    let plan = runs_prune_plan(&runs, older_than_days, keep_last, now_unix_for_prune())?;
    let report = apply_runs_prune(workspace.root(), &plan, dry_run)?;
    print!(
        "{}",
        runs_prune_output(workspace.root(), &report, dry_run, json)?
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunsPrunePlan {
    pub(crate) run_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunsPruneReport {
    target: String,
    dry_run: bool,
    selected: Vec<String>,
    deleted: Vec<String>,
}

pub(crate) fn runs_prune_plan(
    runs: &[RunSummary],
    older_than_days: Option<u64>,
    keep_last: Option<usize>,
    now_unix: u64,
) -> Result<RunsPrunePlan> {
    if older_than_days.is_none() && keep_last.is_none() {
        bail!("runs prune requires --older-than-days or --keep-last");
    }
    let keep_ids = newest_run_ids(runs, keep_last);
    let cutoff = older_than_days.map(|days| now_unix.saturating_sub(days * DAY_SECONDS));
    let run_ids = runs
        .iter()
        .filter(|run| !keep_ids.contains(&run.run_id))
        .filter(|run| cutoff.is_none_or(|cutoff| run.started_at_unix < cutoff))
        .map(|run| run.run_id.clone())
        .collect();
    Ok(RunsPrunePlan { run_ids })
}

fn newest_run_ids(runs: &[RunSummary], keep_last: Option<usize>) -> HashSet<String> {
    let Some(keep_last) = keep_last else {
        return HashSet::new();
    };
    let mut newest = runs.to_vec();
    newest.sort_by(|left, right| {
        right
            .started_at_unix
            .cmp(&left.started_at_unix)
            .then_with(|| right.run_id.cmp(&left.run_id))
    });
    newest
        .into_iter()
        .take(keep_last)
        .map(|run| run.run_id)
        .collect()
}

fn apply_runs_prune(target: &Path, plan: &RunsPrunePlan, dry_run: bool) -> Result<RunsPruneReport> {
    let mut deleted = Vec::new();
    for run_id in &plan.run_ids {
        let dir = safe_run_dir(target, run_id)?;
        if !dry_run && dir.exists() {
            fs::remove_dir_all(&dir)
                .with_context(|| format!("Could not delete {}", dir.display()))?;
            deleted.push(run_id.clone());
        }
    }
    if !dry_run {
        repair_latest_after_prune(target)?;
    }
    Ok(RunsPruneReport {
        target: target.display().to_string(),
        dry_run,
        selected: plan.run_ids.clone(),
        deleted,
    })
}

fn safe_run_dir(target: &Path, run_id: &str) -> Result<PathBuf> {
    if run_id.is_empty()
        || run_id == "."
        || run_id == ".."
        || run_id.contains('/')
        || run_id.contains('\\')
    {
        bail!("refusing to prune unsafe run id {run_id:?}");
    }
    Ok(run_dir(target, run_id))
}

fn repair_latest_after_prune(target: &Path) -> Result<()> {
    let Some(newest) = list_run_summaries(target)?
        .first()
        .map(|run| run.run_id.clone())
    else {
        let _ = fs::remove_file(target.join(".kuzushi/latest"));
        return Ok(());
    };
    fs::write(target.join(".kuzushi/latest"), format!("{newest}\n"))
        .with_context(|| "Could not update .kuzushi/latest")
}

fn runs_prune_output(
    target: &Path,
    report: &RunsPruneReport,
    dry_run: bool,
    json: bool,
) -> Result<String> {
    if json {
        return Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&serde_json::json!({
                "target": report.target,
                "dryRun": report.dry_run,
                "selected": report.selected,
                "deleted": report.deleted,
            }))?
        ));
    }
    Ok(runs_prune_plain(target, report, dry_run))
}

fn runs_prune_plain(target: &Path, report: &RunsPruneReport, dry_run: bool) -> String {
    let action = if dry_run { "would delete" } else { "deleted" };
    let displayed_run_ids = if dry_run {
        &report.selected
    } else {
        &report.deleted
    };
    let mut lines = vec![
        "Run artifact prune".to_string(),
        format!("Target: {}", target.display()),
        format!("{action}: {}", displayed_run_ids.len()),
    ];
    lines.extend(displayed_run_ids.iter().map(|run_id| format!("  {run_id}")));
    if displayed_run_ids.is_empty() {
        lines.push("No matching run artifacts.".to_string());
    }
    format!("{}\n", lines.join("\n"))
}

fn now_unix_for_prune() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
