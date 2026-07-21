use super::*;

pub(crate) fn persist_agentic_sast_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<AgenticSastPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };
    workspace.ensure_state_dir()?;
    let run_id = ctx.finding_run_id();
    let (findings_added, findings_updated) = store.fingerprint_delta(findings)?;
    store.with_run_lifecycle(&run_id, target, || {
        for finding in findings {
            store.insert_finding(&run_id, finding)?;
        }
        Ok(((), findings.len()))
    })?;

    Ok(Some(AgenticSastPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
        findings_added,
        findings_updated,
    }))
}
