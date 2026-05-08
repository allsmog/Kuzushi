use anyhow::{Context, Result};
use kuzushi_core::{RunSummary, WorkspaceTarget};
use std::path::Path;

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
            workspace.root().join(".kuzushi/runs").display(),
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
    format!(
        "{}  {:<9} {:<24} findings={} target={}",
        run.run_id, run.status, tool, findings, run.target
    )
}

pub(crate) fn runs_show_output(summary: &RunSummary, json: bool) -> Result<String> {
    if json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(summary)?));
    }
    Ok(run_summary_plain(summary))
}

pub(crate) fn runs_trace_output(trace_path: &Path, body: &str, json: bool) -> Result<String> {
    if json {
        let steps = parse_trace_json_lines(trace_path, body)?;
        return Ok(format!("{}\n", serde_json::to_string_pretty(&steps)?));
    }
    Ok(runs_trace_plain(trace_path, body)?)
}

pub(crate) fn parse_trace_json_lines(
    trace_path: &Path,
    body: &str,
) -> Result<Vec<serde_json::Value>> {
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("Could not parse {}", trace_path.display()))
}

pub(crate) fn runs_trace_plain(trace_path: &Path, body: &str) -> Result<String> {
    let steps = parse_trace_json_lines(trace_path, body)?;
    if steps.is_empty() {
        return Ok(String::new());
    }
    let mut lines = Vec::with_capacity(steps.len());
    for step in &steps {
        lines.push(format_trace_step_row(step));
    }
    lines.push(String::new());
    Ok(lines.join("\n"))
}

fn format_trace_step_row(step: &serde_json::Value) -> String {
    let n = step.get("n").and_then(serde_json::Value::as_u64).unwrap_or(0);
    let kind = step
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("step");
    let label = step
        .get("label")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("(no label)");
    let module_verb = match (
        step.get("module_id").and_then(serde_json::Value::as_str),
        step.get("verb").and_then(serde_json::Value::as_str),
    ) {
        (Some(module), Some(verb)) => format!("[{module}:{verb}]"),
        (Some(module), None) => format!("[{module}]"),
        _ => "[-]".to_string(),
    };
    let parent = step
        .get("parent_step")
        .and_then(serde_json::Value::as_u64)
        .map(|p| format!(" parent={p}"))
        .unwrap_or_default();
    let latency = step
        .get("latency_ms")
        .and_then(serde_json::Value::as_u64)
        .map(|ms| format!(" {ms}ms"))
        .unwrap_or_default();
    let cost = step
        .get("cost_usd")
        .and_then(serde_json::Value::as_f64)
        .map(|c| format!(" ${c:.4}"))
        .unwrap_or_default();
    let severity = step
        .get("severity")
        .and_then(serde_json::Value::as_str)
        .map(|s| format!(" sev={s}"))
        .unwrap_or_default();
    format!(
        "{n:>3}  {kind:<10}  {module_verb:<26}  {label}{parent}{latency}{cost}{severity}"
    )
}

pub(crate) fn run_summary_plain(summary: &RunSummary) -> String {
    let mut lines = vec![
        format!("Run {}", summary.run_id),
        format!("Status: {}", summary.status),
        format!("Kind: {}", summary.kind),
    ];
    if let Some(tool) = &summary.tool {
        lines.push(format!("Tool: {tool}"));
    }
    lines.push(format!("Target: {}", summary.target));
    if let Some(findings) = summary.findings {
        lines.push(format!("Findings: {findings}"));
    }
    if let Some(cost) = summary.cost_usd {
        lines.push(format!("Cost USD: {cost:.4}"));
    }
    if let Some(error) = &summary.error {
        lines.push(format!("Error: {error}"));
    }
    if !summary.artifacts.is_empty() {
        lines.push("Artifacts:".to_string());
        for artifact in &summary.artifacts {
            lines.push(format!("  {}: {}", artifact.label, artifact.path));
        }
    }
    lines.push(format!("Next: kuzushi runs trace {}", summary.run_id));
    format!("{}\n", lines.join("\n"))
}
