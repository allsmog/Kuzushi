use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::workspace::{
    active_workspace_required_message, export_workspace_findings, workspace_status_for_target,
    WorkspaceExportFormat,
};

use super::input::{resolve_input_path, string_input_any};
use super::ToolExecutionContext;

pub(in crate::modules) fn workspace_status_output(ctx: &ToolExecutionContext<'_>) -> String {
    let status = workspace_status_for_target(ctx.workspace.map(|workspace| workspace.root()), None);
    match (&status.root, &status.state_dir, &status.findings_db) {
        (Some(root), Some(state_dir), Some(findings_db)) => format!(
            "workspace status\n  Root:      {}\n  State:     {}\n  Findings:  {}",
            root.display(),
            state_dir.display(),
            findings_db.display()
        ),
        _ => format!("workspace status unavailable: {}", status.status),
    }
}

pub(in crate::modules) fn export_workspace_findings_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx.workspace.context(active_workspace_required_message(
        "workspace:export-findings",
    ))?;
    let output = string_input_any(&input, &["output", "path"])
        .context("workspace:export-findings requires output=<path>. Next: run workspace:export-findings {\"output\":\"findings.json\"}")?;
    let output_path = resolve_input_path(workspace.root(), &output);
    let format = string_input_any(&input, &["format"])
        .map(|value| WorkspaceExportFormat::from_input(&value))
        .transpose()?;
    let report = export_workspace_findings(workspace, &output_path, format)?;
    let output = format!(
        "workspace:export-findings wrote {} finding(s) to {} ({})",
        report.count,
        report.output_path.display(),
        report.format.as_str()
    );
    let data = json!({
        "outputPath": report.output_path.display().to_string(),
        "format": report.format,
        "count": report.count,
    });
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        data,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::findings::{Finding, FindingStore, Severity};
    use crate::workspace::WorkspaceTarget;
    use tempfile::tempdir;

    fn workspace_tool_context<'a>(
        config: &'a V2Config,
        workspace: &'a WorkspaceTarget,
    ) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config,
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
        }
    }

    fn seed_workspace_finding(workspace: &WorkspaceTarget) {
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        store
            .insert_finding("run-1", &sample_workspace_finding())
            .unwrap();
    }

    fn sample_workspace_finding() -> Finding {
        Finding::new_tool(
            "fixture",
            "fixture/sql",
            "src/app.ts",
            3,
            None,
            Severity::High,
            "request data reaches SQL",
        )
    }

    #[test]
    fn renders_status_for_active_workspace() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = workspace_tool_context(&config, &workspace);

        let output = workspace_status_output(&ctx);

        assert!(output.contains("workspace status"));
        assert!(output.contains(&workspace.root().display().to_string()));
    }

    #[test]
    fn exports_workspace_findings_to_requested_path() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        seed_workspace_finding(&workspace);
        let config = V2Config::default();
        let ctx = workspace_tool_context(&config, &workspace);

        let result =
            export_workspace_findings_tool(json!({"output": "exports/findings.json"}), &ctx)
                .unwrap();

        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result.pointer("/status").and_then(Value::as_str),
            Some("completed")
        );
        assert!(workspace.root().join("exports/findings.json").exists());
    }
}
