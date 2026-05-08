use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::workspace::{export_workspace_findings, WorkspaceExportFormat};

use super::input::{resolve_input_path, string_input_any};
use super::ToolExecutionContext;

pub(in crate::modules) fn workspace_status_output(ctx: &ToolExecutionContext<'_>) -> String {
    match ctx.workspace {
        Some(workspace) => format!(
            "workspace status\n  Root:      {}\n  State:     {}\n  Findings:  {}",
            workspace.root().display(),
            workspace.state_dir().display(),
            workspace.findings_db_path().display()
        ),
        None => "workspace status unavailable: no active workspace. Next: pass --target <repo> or start the shell with --target .".to_string(),
    }
}

pub(in crate::modules) fn export_workspace_findings_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("workspace:export-findings requires an active workspace target")?;
    let output = string_input_any(&input, &["output", "path"])
        .context("workspace:export-findings requires output=<path>. Next: run workspace:export-findings {\"output\":\"findings.json\"}")?;
    let output_path = resolve_input_path(workspace.root(), &output);
    let format = string_input_any(&input, &["format"])
        .map(|value| WorkspaceExportFormat::from_input(&value))
        .transpose()?;
    let report = export_workspace_findings(workspace, &output_path, format)?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "workspace:export-findings wrote {} finding(s) to {} ({})",
            report.count,
            report.output_path.display(),
            report.format.as_str()
        ),
        "data": {
            "outputPath": report.output_path.display().to_string(),
            "format": report.format,
            "count": report.count,
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::findings::{Finding, FindingStore, Severity};
    use crate::workspace::WorkspaceTarget;
    use tempfile::tempdir;

    #[test]
    fn renders_status_for_active_workspace() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
        };

        let output = workspace_status_output(&ctx);

        assert!(output.contains("workspace status"));
        assert!(output.contains(&workspace.root().display().to_string()));
    }

    #[test]
    fn exports_workspace_findings_to_requested_path() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        store
            .insert_finding(
                "run-1",
                &Finding::new_tool(
                    "fixture",
                    "fixture/sql",
                    "src/app.ts",
                    3,
                    None,
                    Severity::High,
                    "request data reaches SQL",
                ),
            )
            .unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
        };

        let result =
            export_workspace_findings_tool(json!({"output": "exports/findings.json"}), &ctx)
                .unwrap();

        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert!(workspace.root().join("exports/findings.json").exists());
    }
}
