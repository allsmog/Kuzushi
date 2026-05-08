use super::prelude::*;
use super::*;

pub(crate) fn finish_cli_tool_run(
    target: &Path,
    run_id: &str,
    tool: &str,
    output: &serde_json::Value,
) {
    let result_artifact =
        write_run_artifact_json(target, run_id, "result.json", "result", output).ok();
    let mut summary = RunSummary::running(
        run_id.to_string(),
        "run",
        Some(tool.to_string()),
        target.display().to_string(),
    )
    .complete()
    .with_findings(run_output_findings_count(output))
    .with_cost(run_output_cost_usd(output));
    if let Some(artifact) = result_artifact {
        summary = summary.with_artifact(artifact);
    }
    let _ = append_run_trace_step(
        target,
        run_id,
        &RunTraceStep::new(2, "tool", format!("{tool} complete"))
            .with_cost_usd(run_output_cost_usd(output)),
    );
    let _ = write_run_summary(target, &summary);
}

pub(crate) fn fail_cli_tool_run(target: &Path, run_id: &str, tool: &str, error: &str) {
    let summary = RunSummary::running(
        run_id.to_string(),
        "run",
        Some(tool.to_string()),
        target.display().to_string(),
    )
    .failed(error.to_string());
    let _ = append_run_trace_step(
        target,
        run_id,
        &RunTraceStep::new(2, "tool", format!("{tool} failed")),
    );
    let _ = write_run_summary(target, &summary);
}

pub(crate) fn run_output_findings_count(output: &serde_json::Value) -> Option<u64> {
    output
        .pointer("/data/findingsCount")
        .or_else(|| output.get("findingsCount"))
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            output
                .pointer("/data/findings")
                .and_then(serde_json::Value::as_array)
                .map(|findings| findings.len() as u64)
        })
}

pub(crate) fn run_output_cost_usd(output: &serde_json::Value) -> Option<f64> {
    output
        .get("costUsd")
        .and_then(serde_json::Value::as_f64)
        .or_else(|| {
            output
                .pointer("/data/costUsd")
                .and_then(serde_json::Value::as_f64)
        })
        .filter(|cost| cost.is_finite() && *cost >= 0.0)
}

pub(crate) fn reject_shell_only_run_dot(tool: &str) -> Result<()> {
    if tool == "." {
        anyhow::bail!(
            "`kuzushi run .` is shell-only because the terminal command has no focused module. Use `kuzushi shell`, then `use <module>` and `run .`; from a terminal run an explicit tool such as `kuzushi --target . run context:build --input '{{}}'`."
        );
    }
    Ok(())
}

pub(crate) fn run_tool_workspace(
    tool: &str,
    target: Option<&Path>,
) -> Result<Option<WorkspaceTarget>> {
    match target {
        Some(target) => Ok(Some(WorkspaceTarget::new(target)?)),
        None if tool_defaults_to_workspace(tool) => Ok(Some(WorkspaceTarget::new(".")?)),
        None => Ok(None),
    }
}

pub(crate) const WORKSPACE_TOOL_PREFIXES: &[&str] = &[
    "findings:",
    "context:",
    "recon:",
    "vendor-assessment:",
    "chrome-rce:",
    "vuln-scout:",
    "tob:",
    "shinsa:",
    "prompt-armor:",
    "x-ray:",
    "threat-model:",
    "randori:",
    "variant:",
    "ndiff:",
    "systems-hunt:",
];
