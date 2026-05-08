use super::prelude::*;
use super::*;

pub(in crate::modules) fn persist_tool_findings(
    tool_slug: &str,
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<GenericPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };
    workspace.ensure_state_dir()?;
    let run_id = format!("{tool_slug}-{}", Uuid::new_v4());
    store.insert_scan_run(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;
    Ok(Some(GenericPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}

pub(in crate::modules) fn render_generic_findings_output(
    tool_name: &str,
    target: &Path,
    findings: &[Finding],
    persisted: &Option<GenericPersistedRun>,
) -> String {
    let mut lines = vec![format!(
        "{tool_name} complete for {}\n  Findings: {}",
        target.display(),
        findings.len()
    )];
    if let Some(persisted) = persisted {
        lines.push(format!(
            "  Persisted run: {} ({})",
            persisted.run_id, persisted.findings_db
        ));
    }
    if !findings.is_empty() {
        lines.push(String::new());
        lines.push("Top findings:".to_string());
        for finding in findings.iter().take(10) {
            lines.push(format!(
                "  - {} - {} - {}:{}",
                finding.severity.as_str(),
                finding.rule_id,
                finding.file_path,
                finding.start_line
            ));
        }
    }
    lines.join("\n")
}
