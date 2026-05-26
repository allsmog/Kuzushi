use crate::command::RunsCommand;
use crate::presentation::{runs_list_output, runs_show_output, runs_trace_output};
use anyhow::{bail, Context, Result};
use kuzushi_core::run_artifacts::canonical_run_artifact_spec;
use kuzushi_core::{
    list_run_summaries, load_run_summary, run_artifact_path, runs_root, RunSummary, WorkspaceTarget,
};
use std::fs;
use std::path::PathBuf;

use super::runs_diff::runs_diff_command;
use super::runs_prune::runs_prune_command;

#[rustfmt::skip]
pub(crate) fn runs_command(command: RunsCommand, global_target: Option<PathBuf>) -> Result<()> {
    match command {
        RunsCommand::List { target, status, json } => {
            runs_list_command(target.or(global_target), status, json)
        }
        RunsCommand::Show { run_id, target, json } => {
            runs_show_command(target.or(global_target), &run_id, json)
        }
        RunsCommand::Trace { run_id, target, json } => {
            runs_trace_command(target.or(global_target), &run_id, json)
        }
        RunsCommand::Diff { base_run_id, compare_run_id, target, json } => {
            runs_diff_command(target.or(global_target), &base_run_id, &compare_run_id, json)
        }
        RunsCommand::Prune { target, older_than_days, keep_last, dry_run, json } => {
            runs_prune_command(target.or(global_target), older_than_days, keep_last, dry_run, json)
        }
    }
}

pub(crate) fn runs_list_command(
    target: Option<PathBuf>,
    status: Vec<String>,
    json: bool,
) -> Result<()> {
    let workspace = WorkspaceTarget::new(target.unwrap_or_else(|| PathBuf::from(".")))?;
    let runs = list_run_summaries(workspace.root())?;
    let filtered = filter_runs_by_status(runs, &status)?;
    print!("{}", runs_list_output(&workspace, &filtered, json)?);
    Ok(())
}

pub(crate) fn filter_runs_by_status(
    runs: Vec<RunSummary>,
    status: &[String],
) -> Result<Vec<RunSummary>> {
    let filters = normalize_status_filters(status)?;
    if filters.is_empty() {
        return Ok(runs);
    }
    Ok(runs
        .into_iter()
        .filter(|run| filters.iter().any(|status| status == &run.status))
        .collect())
}

fn normalize_status_filters(status: &[String]) -> Result<Vec<String>> {
    status
        .iter()
        .map(|status| normalize_run_status(status))
        .collect()
}

fn normalize_run_status(status: &str) -> Result<String> {
    let normalized = status.trim().to_ascii_lowercase();
    if run_status_allowed(&normalized) {
        return Ok(normalized);
    }
    bail!("unknown run status {status:?}; expected running, completed, failed, interrupted, partial, or skipped")
}

fn run_status_allowed(status: &str) -> bool {
    matches!(
        status,
        "running" | "completed" | "failed" | "interrupted" | "partial" | "skipped"
    )
}

pub(crate) fn runs_show_command(target: Option<PathBuf>, run_id: &str, json: bool) -> Result<()> {
    let workspace = WorkspaceTarget::new(target.unwrap_or_else(|| PathBuf::from(".")))?;
    let summary = load_run_summary(workspace.root(), run_id).with_context(|| {
        format!(
            "no run summary found for {run_id:?} under {}",
            runs_root(workspace.root()).display()
        )
    })?;
    print!("{}", runs_show_output(&summary, json)?);
    Ok(())
}

pub(crate) fn runs_trace_command(target: Option<PathBuf>, run_id: &str, json: bool) -> Result<()> {
    let workspace = WorkspaceTarget::new(target.unwrap_or_else(|| PathBuf::from(".")))?;
    let trace_path = run_trace_path(&workspace, run_id);
    let body = fs::read_to_string(&trace_path)
        .with_context(|| format!("Could not read {}", trace_path.display()))?;
    print!("{}", runs_trace_output(&trace_path, &body, json)?);
    Ok(())
}

pub(crate) fn run_trace_path(workspace: &WorkspaceTarget, run_id: &str) -> PathBuf {
    run_artifact_path(workspace.root(), run_id, run_trace_artifact_leaf())
}

fn run_trace_artifact_leaf() -> &'static str {
    canonical_run_artifact_spec("trace.jsonl")
        .expect("trace artifact must be in shared canonical spec")
        .leaf
}
