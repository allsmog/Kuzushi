use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use crate::workspace::{
    active_workspace_required_message, export_workspace_findings_with_options,
    workspace_status_for_target, WorkspaceExportCompleteness, WorkspaceExportFormat,
    WorkspaceExportOptions, WorkspaceFindingsExport,
};

use super::input::{read_bool_any, resolve_input_path, string_input_any};
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
    let request = workspace_export_tool_request(&input, workspace.root())?;
    let report =
        export_workspace_findings_with_options(workspace, &request.output_path, request.options)?;
    let output = workspace_export_tool_message(&report, request.completeness, request.allow_empty);
    let data = workspace_export_tool_data(&report, request.completeness, request.allow_empty);
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        data,
    ))
}

struct WorkspaceExportToolRequest {
    output_path: PathBuf,
    options: WorkspaceExportOptions,
    completeness: WorkspaceExportCompleteness,
    allow_empty: bool,
}

fn workspace_export_tool_request(input: &Value, root: &Path) -> Result<WorkspaceExportToolRequest> {
    let output = string_input_any(&input, &["output", "path"])
        .context("workspace:export-findings requires output=<path>. Next: run workspace:export-findings {\"output\":\"findings.json\"}")?;
    let output_path = resolve_input_path(root, &output);
    let format = string_input_any(&input, &["format"])
        .map(|value| WorkspaceExportFormat::from_input(&value))
        .transpose()?;
    let completeness = string_input_any(&input, &["completeness", "reviewCompleteness"])
        .map(|value| WorkspaceExportCompleteness::from_input(&value))
        .transpose()?
        .unwrap_or_default();
    let allow_empty = read_bool_any(&input, &["allowEmpty", "allow_empty"])?.unwrap_or(false);
    let options = WorkspaceExportOptions::new(format)
        .with_completeness(completeness)
        .with_allow_empty(allow_empty);
    Ok(WorkspaceExportToolRequest {
        output_path,
        options,
        completeness,
        allow_empty,
    })
}

fn workspace_export_tool_message(
    report: &WorkspaceFindingsExport,
    completeness: WorkspaceExportCompleteness,
    allow_empty: bool,
) -> String {
    format!(
        "workspace:export-findings wrote {} finding(s) to {} ({}, completeness:{}, allowEmpty:{})",
        report.count,
        report.output_path.display(),
        report.format.as_str(),
        completeness.as_str(),
        allow_empty
    )
}

fn workspace_export_tool_data(
    report: &WorkspaceFindingsExport,
    completeness: WorkspaceExportCompleteness,
    allow_empty: bool,
) -> Value {
    json!({
        "outputPath": report.output_path.display().to_string(),
        "format": report.format,
        "completeness": completeness.as_str(),
        "allowEmpty": allow_empty,
        "count": report.count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::findings::{Finding, FindingStore, Severity, TriageOutcome, TriageVerdict};
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
cancellation: None,
authorization: Default::default(),
        }
    }

    fn seed_workspace_finding(workspace: &WorkspaceTarget) {
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-1", workspace.root(), "completed")
            .unwrap();
        store
            .insert_finding("run-1", &sample_workspace_finding())
            .unwrap();
    }

    fn seed_complete_and_open_findings(workspace: &WorkspaceTarget) {
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-1", workspace.root(), "completed")
            .unwrap();
        let confirmed_id = store
            .insert_finding("run-1", &sample_workspace_finding())
            .unwrap();
        store
            .insert_finding("run-1", &open_workspace_finding())
            .unwrap();
        save_confirmed_triage(&store, confirmed_id);
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

    fn open_workspace_finding() -> Finding {
        Finding::new_tool(
            "fixture",
            "fixture/open",
            "src/open.ts",
            7,
            None,
            Severity::Medium,
            "needs review",
        )
    }

    fn save_confirmed_triage(store: &FindingStore, finding_id: i64) {
        store
            .record_auto_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "operator confirmed".to_string(),
                    cost_usd: 0.0,
                },
            )
            .unwrap();
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

    #[test]
    fn exports_workspace_findings_with_completeness_filter() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        seed_complete_and_open_findings(&workspace);
        let config = V2Config::default();
        let ctx = workspace_tool_context(&config, &workspace);

        let result = export_workspace_findings_tool(
            json!({
                "output": "exports/complete.json",
                "format": "json",
                "completeness": "complete"
            }),
            &ctx,
        )
        .unwrap();

        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result.pointer("/data/completeness").and_then(Value::as_str),
            Some("complete")
        );
        let output = workspace.root().join("exports/complete.json");
        let body: Value = serde_json::from_str(&std::fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(body["completeness"], "complete");
        assert_eq!(body["findings"][0]["ruleId"], "fixture/sql");
    }

    #[test]
    fn export_workspace_findings_tool_requires_allow_empty_for_empty_selection() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = workspace_tool_context(&config, &workspace);

        let error = export_workspace_findings_tool(
            json!({
                "output": "exports/empty.json",
                "format": "json"
            }),
            &ctx,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("selected 0 findings"));
        assert!(!workspace.root().join("exports").exists());

        let result = export_workspace_findings_tool(
            json!({
                "output": "exports/empty.json",
                "format": "json",
                "allowEmpty": true
            }),
            &ctx,
        )
        .unwrap();

        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            result.pointer("/data/allowEmpty").and_then(Value::as_bool),
            Some(true)
        );
        assert!(workspace.root().join("exports/empty.json").exists());
    }
}
