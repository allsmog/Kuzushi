use super::*;

pub(in crate::capabilities::taint_iris_next) fn persist_taint_iris_next_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<TaintIrisNextPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };
    workspace.ensure_state_dir()?;
    let run_id = Uuid::new_v4().to_string();
    store.record_run_started(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.record_run_finished(&run_id, "completed", findings.len())?;
    Ok(Some(TaintIrisNextPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}
