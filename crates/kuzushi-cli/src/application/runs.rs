use crate::command::RunsCommand;
use crate::presentation::{runs_list_output, runs_show_output, runs_trace_output};
use crate::support::require_cli_target;
use anyhow::{bail, Context, Result};
use kuzushi_core::run_artifacts::canonical_run_artifact_spec;
use kuzushi_core::{
    list_run_summaries, load_run_summary, read_run_artifact_text, runs_root, RunSummary,
    WorkspaceTarget,
};
use std::path::PathBuf;

use super::runs_diff::runs_diff_command;
use super::runs_prune::runs_prune_command;

#[rustfmt::skip]
pub(crate) fn runs_command(command: RunsCommand, global_target: Option<PathBuf>) -> Result<()> {
    match command {
        RunsCommand::List { target, status, json } => {
            runs_list_command(require_cli_target("runs list", target, global_target)?, status, json)
        }
        RunsCommand::Show { run_id, target, json } => {
            runs_show_command(require_cli_target("runs show", target, global_target)?, &run_id, json)
        }
        RunsCommand::Trace { run_id, target, json } => {
            runs_trace_command(require_cli_target("runs trace", target, global_target)?, &run_id, json)
        }
        RunsCommand::Replay { run_id, target, json } => {
            runs_replay_command(require_cli_target("runs replay", target, global_target)?, &run_id, json)
        }
        RunsCommand::Diff { base_run_id, compare_run_id, target, json } => {
            runs_diff_command(require_cli_target("runs diff", target, global_target)?, &base_run_id, &compare_run_id, json)
        }
        RunsCommand::Prune { target, older_than_days, keep_last, dry_run, json } => {
            runs_prune_command(require_cli_target("runs prune", target, global_target)?, older_than_days, keep_last, dry_run, json)
        }
    }
}

pub(crate) fn runs_replay_command(target: PathBuf, run_id: &str, json: bool) -> Result<()> {
    let workspace = WorkspaceTarget::new(target)?;
    let read = kuzushi_core::run_lifecycle::load_run_projection(workspace.root(), run_id)?;
    if json {
        println!("{}", crate::presentation::runs_replay_json(&read)?);
    } else {
        print!("{}", crate::presentation::runs_replay_plain(&read));
    }
    Ok(())
}

pub(crate) fn runs_list_command(target: PathBuf, status: Vec<String>, json: bool) -> Result<()> {
    let workspace = WorkspaceTarget::new(target)?;
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
        .filter(|run| run_matches_status_filter(run, &filters))
        .collect())
}

fn run_matches_status_filter(run: &RunSummary, filters: &[String]) -> bool {
    let status = normalized_status_text(&run.status);
    filters.iter().any(|filter| filter == &status)
}

fn normalize_status_filters(status: &[String]) -> Result<Vec<String>> {
    status
        .iter()
        .map(|status| normalize_run_status(status))
        .collect()
}

fn normalize_run_status(status: &str) -> Result<String> {
    let normalized = normalized_status_text(status);
    if run_status_allowed(&normalized) {
        return Ok(normalized);
    }
    bail!("unknown run status {status:?}; expected running, completed, failed, canceled, interrupted, partial, or skipped")
}

fn normalized_status_text(status: &str) -> String {
    status.trim().to_ascii_lowercase()
}

fn run_status_allowed(status: &str) -> bool {
    matches!(
        status,
        "running" | "completed" | "failed" | "canceled" | "interrupted" | "partial" | "skipped"
    )
}

pub(crate) fn runs_show_command(target: PathBuf, run_id: &str, json: bool) -> Result<()> {
    let workspace = WorkspaceTarget::new(target)?;
    let summary = load_run_summary(workspace.root(), run_id).with_context(|| {
        format!(
            "no run summary found for {run_id:?} under {}",
            runs_root(workspace.root()).display()
        )
    })?;
    print!("{}", runs_show_output(&summary, json)?);
    Ok(())
}

pub(crate) fn runs_trace_command(target: PathBuf, run_id: &str, json: bool) -> Result<()> {
    let workspace = WorkspaceTarget::new(target)?;
    let (trace_path, body) =
        read_run_artifact_text(workspace.root(), run_id, run_trace_artifact_leaf())
            .require("Run trace")?;
    print!("{}", runs_trace_output(&trace_path, &body, json)?);
    Ok(())
}

fn run_trace_artifact_leaf() -> &'static str {
    canonical_run_artifact_spec("trace.jsonl")
        .expect("trace artifact must be in shared canonical spec")
        .leaf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canceled_status_filter_is_canonical_and_distinct_from_interrupted() {
        let canceled = RunSummary::running("run-c", "tool", None, "target").canceled("operator");
        let interrupted =
            RunSummary::running("run-i", "tool", None, "target").interrupted("watchdog");

        let filtered =
            filter_runs_by_status(vec![canceled, interrupted], &[" CANCELED ".to_string()])
                .unwrap();

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].run_id, "run-c");
        assert_eq!(filtered[0].status, "canceled");
    }

    #[test]
    fn trace_rejects_run_id_traversal() {
        let target = tempfile::tempdir().unwrap();

        let error =
            runs_trace_command(target.path().to_path_buf(), "../outside", false).unwrap_err();

        assert!(error.to_string().contains("unsafe"));
    }

    #[cfg(unix)]
    #[test]
    fn trace_rejects_symlinked_run_directory() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("trace.jsonl"), "outside").unwrap();
        let runs = kuzushi_core::runs_root(target.path());
        std::fs::create_dir_all(&runs).unwrap();
        symlink(outside.path(), runs.join("run-link")).unwrap();

        let error = runs_trace_command(target.path().to_path_buf(), "run-link", false).unwrap_err();

        assert!(error.to_string().contains("unsafe"));
        assert_eq!(
            std::fs::read_to_string(outside.path().join("trace.jsonl")).unwrap(),
            "outside"
        );
    }
}
