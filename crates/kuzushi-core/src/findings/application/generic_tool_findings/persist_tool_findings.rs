use super::*;

pub(crate) fn persist_tool_findings(
    run_id: String,
    target: &Path,
    findings: &[Finding],
    workspace: Option<&WorkspaceTarget>,
    store: Option<&FindingStore>,
) -> Result<Option<GenericPersistedRun>> {
    let (Some(workspace), Some(store)) = (workspace, store) else {
        return Ok(None);
    };
    workspace.ensure_state_dir()?;
    store.with_run_lifecycle(&run_id, target, || {
        for finding in findings {
            store.insert_finding(&run_id, finding)?;
        }
        Ok(((), findings.len()))
    })?;
    Ok(Some(GenericPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn findings_use_the_canonical_execution_run_id() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        workspace.ensure_state_dir().unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let finding = Finding::new_tool(
            "secret-scan",
            "secret-scan/test",
            "src/config.rs",
            1,
            None,
            Severity::High,
            "test finding",
        );

        let persisted = persist_tool_findings(
            "run-canonical".to_string(),
            target.path(),
            &[finding],
            Some(&workspace),
            Some(&store),
        )
        .unwrap()
        .unwrap();

        assert_eq!(persisted.run_id, "run-canonical");
        assert_eq!(
            store
                .list_findings_for_scan_id("run-canonical")
                .unwrap()
                .len(),
            1
        );
    }
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
