use super::prelude::*;
use super::*;

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

pub(crate) fn runs_show_output(summary: &RunSummary, json: bool) -> Result<String> {
    if json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(summary)?));
    }
    Ok(run_summary_plain(summary))
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

pub(crate) fn runs_trace_output(trace_path: &Path, body: &str, json: bool) -> Result<String> {
    if json {
        let steps = parse_trace_json_lines(trace_path, body)?;
        return Ok(format!("{}\n", serde_json::to_string_pretty(&steps)?));
    }
    Ok(body.to_string())
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
