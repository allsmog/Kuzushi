use anyhow::{Context, Result};
use kuzushi_core::{runs_root, RunSummary, WorkspaceTarget};
use std::time::Duration;

use super::scan_ci::format_duration;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunsReplayRow {
    key: Option<kuzushi_core::run_lifecycle::RunCellKey>,
    text: String,
}

pub(crate) fn runs_replay_plain(read: &kuzushi_core::run_lifecycle::RunProjectionRead) -> String {
    let presentation = kuzushi_core::run_lifecycle::present_run(read);
    let rows = runs_replay_rows(&presentation);
    rows.into_iter()
        .map(|row| {
            let _source_key = row.key;
            row.text
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn runs_replay_json(
    read: &kuzushi_core::run_lifecycle::RunProjectionRead,
) -> Result<String> {
    serde_json::to_string_pretty(read).context("serialize typed run replay")
}

fn runs_replay_rows(
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
) -> Vec<RunsReplayRow> {
    let mut rows = presentation
        .overview_lines()
        .into_iter()
        .map(unkeyed_replay_row)
        .collect::<Vec<_>>();
    append_presentation_sections(&mut rows, presentation);
    append_presentation_timeline(&mut rows, presentation);
    rows.push(unkeyed_replay_row(String::new()));
    rows
}

fn append_presentation_sections(
    rows: &mut Vec<RunsReplayRow>,
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
) {
    let mut active_section = None;
    for row in presentation.summary_text_rows() {
        if row.section != active_section {
            if let Some(section) = row.section.as_ref() {
                rows.push(unkeyed_replay_row(section.label().to_string()));
            }
            active_section = row.section.clone();
        }
        rows.push(keyed_replay_row(row));
    }
}

fn append_presentation_timeline(
    rows: &mut Vec<RunsReplayRow>,
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
) {
    if presentation.timeline.is_empty() {
        return;
    }
    rows.push(unkeyed_replay_row("TIMELINE".to_string()));
    rows.extend(
        presentation
            .timeline_text_rows()
            .into_iter()
            .map(keyed_replay_row),
    );
}

fn keyed_replay_row(row: kuzushi_core::run_lifecycle::RunPresentationTextRowV1) -> RunsReplayRow {
    RunsReplayRow {
        key: Some(row.key),
        text: row.text,
    }
}

fn unkeyed_replay_row(text: String) -> RunsReplayRow {
    RunsReplayRow { key: None, text }
}

pub(crate) fn runs_list_output(
    workspace: &WorkspaceTarget,
    runs: &[RunSummary],
    json: bool,
) -> Result<String> {
    if json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(runs)?));
    }
    Ok(runs_list_plain(workspace, runs))
}

pub(crate) fn runs_list_plain(workspace: &WorkspaceTarget, runs: &[RunSummary]) -> String {
    if runs.is_empty() {
        return format!(
            "no run artifacts found at {}\nNext: kuzushi scan {}\n",
            runs_root(workspace.root()).display(),
            workspace.root().display()
        );
    }

    let mut lines = vec![
        "Run artifacts".to_string(),
        format!("Target: {}", workspace.root().display()),
    ];
    lines.extend(runs.iter().map(run_list_row));
    lines.push(format!(
        "Next: kuzushi runs show <runId> --target {}",
        workspace.root().display()
    ));
    format!("{}\n", lines.join("\n"))
}

pub(crate) fn run_list_row(run: &RunSummary) -> String {
    let tool = run.tool.as_deref().unwrap_or(run.kind.as_str());
    let findings = run
        .findings
        .map(|count| count.to_string())
        .unwrap_or_else(|| "-".to_string());
    let duration = run_duration_label(run).unwrap_or_else(|| "-".to_string());
    format!(
        "{}  {:<9} {:<24} duration={} findings={} target={}",
        run.run_id, run.status, tool, duration, findings, run.target
    )
}

pub(crate) fn runs_show_output(summary: &RunSummary, json: bool) -> Result<String> {
    if json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(summary)?));
    }
    Ok(run_summary_plain(summary))
}

pub(crate) fn runs_trace_output(
    read: &kuzushi_core::run_lifecycle::RunProjectionRead,
    json: bool,
) -> Result<String> {
    if json {
        return Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&read.projection.timeline)?
        ));
    }
    Ok(runs_trace_plain(read))
}

pub(crate) fn runs_trace_plain(read: &kuzushi_core::run_lifecycle::RunProjectionRead) -> String {
    let presentation = kuzushi_core::run_lifecycle::present_run(read);
    let run_id = read
        .projection
        .run_id
        .as_ref()
        .map(|run_id| run_id.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let mut lines = vec![format!("Run trace · {run_id}"), "TIMELINE".to_string()];
    let timeline = presentation.timeline_text_rows();
    if timeline.is_empty() {
        lines.push("No lifecycle activity recorded".to_string());
    } else {
        lines.extend(timeline.into_iter().map(|row| row.text));
    }
    lines.push(String::new());
    lines.join("\n")
}

pub(crate) fn run_summary_plain(summary: &RunSummary) -> String {
    let mut lines = run_summary_header(summary);
    push_run_summary_tool(&mut lines, summary);
    lines.push(format!("Target: {}", summary.target));
    push_run_summary_duration(&mut lines, summary);
    push_run_summary_findings(&mut lines, summary);
    push_run_summary_cost(&mut lines, summary);
    push_run_summary_error(&mut lines, summary);
    push_run_summary_artifacts(&mut lines, summary);
    lines.push(format!("Next: kuzushi runs trace {}", summary.run_id));
    format!("{}\n", lines.join("\n"))
}

fn run_summary_header(summary: &RunSummary) -> Vec<String> {
    vec![
        format!("Run {}", summary.run_id),
        format!("Status: {}", summary.status),
        format!("Kind: {}", summary.kind),
    ]
}

fn push_run_summary_tool(lines: &mut Vec<String>, summary: &RunSummary) {
    if let Some(tool) = &summary.tool {
        lines.push(format!("Tool: {tool}"));
    }
}

fn push_run_summary_duration(lines: &mut Vec<String>, summary: &RunSummary) {
    if let Some(duration) = run_duration_label(summary) {
        lines.push(format!("Duration: {duration}"));
    }
}

fn push_run_summary_findings(lines: &mut Vec<String>, summary: &RunSummary) {
    if let Some(findings) = summary.findings {
        lines.push(format!("Findings: {findings}"));
    }
}

fn push_run_summary_cost(lines: &mut Vec<String>, summary: &RunSummary) {
    if let Some(cost) = summary.cost_usd {
        lines.push(format!("Cost USD: {cost:.4}"));
    } else if let Some(observed) = summary
        .provider_spend_unresolved
        .then_some(summary.observed_cost_usd)
        .flatten()
    {
        lines.push(format!(
            "Observed cost USD: {observed:.4} (provider spend unresolved)"
        ));
    }
}

fn push_run_summary_error(lines: &mut Vec<String>, summary: &RunSummary) {
    if let Some(error) = &summary.error {
        lines.push(format!("Error: {error}"));
    }
}

fn push_run_summary_artifacts(lines: &mut Vec<String>, summary: &RunSummary) {
    if !summary.artifacts.is_empty() {
        lines.push("Artifacts:".to_string());
        for artifact in &summary.artifacts {
            lines.push(format!("  {}: {}", artifact.label, artifact.path));
        }
    }
}

fn run_duration_label(summary: &RunSummary) -> Option<String> {
    summary_elapsed(summary).map(format_duration)
}

fn summary_elapsed(summary: &RunSummary) -> Option<Duration> {
    let completed = summary.completed_at_unix?;
    completed
        .checked_sub(summary.started_at_unix)
        .map(Duration::from_secs)
}

#[cfg(test)]
#[path = "runs_output/tests.rs"]
mod tests;
