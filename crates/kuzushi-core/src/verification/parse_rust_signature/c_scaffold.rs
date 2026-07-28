use super::*;

pub(in crate::verification) async fn scaffold_c_project(
    finding: &Finding,
    _compiler: CCompiler,
    workspace_root: &Path,
) -> Result<ScaffoldedProject> {
    let payload = synth_payload_from_finding(finding);
    scaffold_c_project_with_payload(finding, _compiler, workspace_root, &payload).await
}

pub(in crate::verification) async fn scaffold_c_project_with_payload(
    finding: &Finding,
    _compiler: CCompiler,
    workspace_root: &Path,
    payload: &[u8],
) -> Result<ScaffoldedProject> {
    let tempdir = tempfile::tempdir().context("could not create C harness temp dir")?;
    let root = tempdir.path().to_path_buf();
    let trigger = build_c_trigger_with_payload(finding, workspace_root, payload)?;
    tokio::fs::write(root.join("trigger.c"), &trigger.trigger_c).await?;
    tokio::fs::write(root.join("target.c"), &trigger.target_c).await?;
    if let Some(suspect) = &trigger.suspect_source {
        tokio::fs::write(root.join("suspect_source.c"), suspect).await?;
    }
    Ok(ScaffoldedProject {
        path: root,
        fidelity: trigger.fidelity,
        payload: trigger.payload,
        provenance: None,
        _tempdir: tempdir,
    })
}
