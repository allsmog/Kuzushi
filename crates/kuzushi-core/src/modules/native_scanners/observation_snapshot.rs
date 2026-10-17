//! Publish committed observations for readers without inventing coverage.
use super::*;

pub(super) fn publish(ctx: &ToolExecutionContext<'_>, run: &str) -> Result<()> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(());
    };
    let findings = store.list_findings_for_scan_id(run)?;
    crate::run_artifacts::write_run_artifact_json(
        workspace.root(),
        run,
        "findings.json",
        "discovery observations",
        &json!(findings),
    )?;
    Ok(())
}
