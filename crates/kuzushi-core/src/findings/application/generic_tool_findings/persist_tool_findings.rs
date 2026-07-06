use super::*;

pub(crate) fn persist_tool_findings(
    tool_slug: &str,
    target: &Path,
    findings: &[Finding],
    workspace: Option<&WorkspaceTarget>,
    store: Option<&FindingStore>,
) -> Result<Option<GenericPersistedRun>> {
    let (Some(workspace), Some(store)) = (workspace, store) else {
        return Ok(None);
    };
    workspace.ensure_state_dir()?;
    let run_id = format!("{tool_slug}-{}", Uuid::new_v4());
    store.record_run_started(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.record_run_finished(&run_id, "completed", findings.len())?;
    Ok(Some(GenericPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}

pub(crate) fn render_generic_findings_output(
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
