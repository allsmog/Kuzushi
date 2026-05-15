use super::*;

pub(in crate::modules) fn write_sast_summary(
    workspace: &WorkspaceTarget,
    run_id: &str,
    artifacts: &SastRunArtifacts,
    result: &Value,
) -> Result<crate::run_artifacts::RunArtifact> {
    crate::run_artifacts::write_run_artifact_json(
        workspace.root(),
        run_id,
        SAST_SUMMARY_FILE,
        "sast summary",
        result,
    )
    .with_context(|| format!("Could not write {}", artifacts.sast_summary.display()))
}

pub(in crate::modules) fn write_sast_run_metadata(
    workspace: &WorkspaceTarget,
    run_id: &str,
    findings_count: usize,
    summary_artifact: crate::run_artifacts::RunArtifact,
    result: &Value,
) -> Result<()> {
    let summary = scan_run_artifacts(workspace, run_id, summary_artifact, result)
        .into_iter()
        .fold(
            crate::run_artifacts::RunSummary::running(
                run_id.to_string(),
                "scan",
                Some("sast:scan".to_string()),
                workspace.root().display().to_string(),
            )
            .complete()
            .with_findings(Some(findings_count as u64)),
            crate::run_artifacts::RunSummary::with_artifact,
        );
    crate::run_artifacts::write_run_summary(workspace.root(), &summary)?;
    Ok(())
}

fn scan_run_artifacts(
    workspace: &WorkspaceTarget,
    run_id: &str,
    summary_artifact: crate::run_artifacts::RunArtifact,
    result: &Value,
) -> Vec<crate::run_artifacts::RunArtifact> {
    let mut artifacts = vec![summary_artifact];
    artifacts.extend(crate::run_artifacts::record_canonical_snapshot_artifacts(
        workspace.root(),
        run_id,
        result,
    ));
    artifacts
}
