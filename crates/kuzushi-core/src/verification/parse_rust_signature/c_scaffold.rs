use super::*;

pub(in crate::verification) async fn scaffold_c_project(
    finding: &Finding,
    _compiler: CCompiler,
) -> Result<ScaffoldedProject> {
    let tempdir = tempfile::tempdir().context("could not create C harness temp dir")?;
    let root = tempdir.path().to_path_buf();
    let trigger = build_c_trigger(finding);
    tokio::fs::write(root.join("trigger.c"), &trigger.trigger_c).await?;
    tokio::fs::write(root.join("target.c"), &trigger.target_c).await?;
    if let Some(suspect) = &trigger.suspect_source {
        tokio::fs::write(root.join("suspect_source.c"), suspect).await?;
    }
    Ok(ScaffoldedProject {
        path: root,
        _tempdir: tempdir,
    })
}
