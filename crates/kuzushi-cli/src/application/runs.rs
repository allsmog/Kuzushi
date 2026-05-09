use crate::command::RunsCommand;
use crate::presentation::{runs_list_output, runs_show_output, runs_trace_output};
use anyhow::{Context, Result};
use kuzushi_core::{list_run_summaries, load_run_summary, WorkspaceTarget};
use std::fs;
use std::path::PathBuf;

pub(crate) fn runs_command(command: RunsCommand, global_target: Option<PathBuf>) -> Result<()> {
    match command {
        RunsCommand::List { target, json } => runs_list_command(target.or(global_target), json),
        RunsCommand::Show {
            run_id,
            target,
            json,
        } => runs_show_command(target.or(global_target), &run_id, json),
        RunsCommand::Trace {
            run_id,
            target,
            json,
        } => runs_trace_command(target.or(global_target), &run_id, json),
    }
}

pub(crate) fn runs_list_command(target: Option<PathBuf>, json: bool) -> Result<()> {
    let workspace = WorkspaceTarget::new(target.unwrap_or_else(|| PathBuf::from(".")))?;
    let runs = list_run_summaries(workspace.root())?;
    print!("{}", runs_list_output(&workspace, &runs, json)?);
    Ok(())
}

pub(crate) fn runs_show_command(target: Option<PathBuf>, run_id: &str, json: bool) -> Result<()> {
    let workspace = WorkspaceTarget::new(target.unwrap_or_else(|| PathBuf::from(".")))?;
    let summary = load_run_summary(workspace.root(), run_id).with_context(|| {
        format!(
            "no run summary found for {run_id:?} under {}",
            workspace.root().join(".kuzushi/runs").display()
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
    workspace
        .root()
        .join(".kuzushi")
        .join("runs")
        .join(run_id)
        .join("trace.jsonl")
}
