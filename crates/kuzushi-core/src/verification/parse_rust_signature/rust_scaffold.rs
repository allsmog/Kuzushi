use super::*;

#[derive(Debug, Clone)]
pub(in crate::verification) struct RustTriggerSource {
    pub(in crate::verification) cargo_toml: String,
    pub(in crate::verification) lib_rs: String,
    pub(in crate::verification) trigger_test: String,
    /// Full source of the suspect file when readable. Copied into
    /// `src/suspect.rs` so the harness's `pub mod suspect;` can
    /// resolve into it. `None` when `build_rust_trigger` decided not
    /// to wire a sink call.
    pub(in crate::verification) suspect_source: Option<String>,
    pub(in crate::verification) fidelity: HarnessFidelity,
    pub(in crate::verification) payload: Vec<u8>,
}

pub(in crate::verification) async fn scaffold_rust_project(
    src: &RustTriggerSource,
) -> Result<ScaffoldedProject> {
    let tempdir = tempfile::tempdir().context("could not create harness temp dir")?;
    let root = tempdir.path().to_path_buf();
    tokio::fs::create_dir_all(root.join("src")).await?;
    tokio::fs::create_dir_all(root.join("tests")).await?;
    tokio::fs::write(root.join("Cargo.toml"), &src.cargo_toml).await?;
    tokio::fs::write(root.join("src").join("lib.rs"), &src.lib_rs).await?;
    if let Some(suspect) = &src.suspect_source {
        tokio::fs::write(root.join("src").join("suspect.rs"), suspect).await?;
    }
    tokio::fs::write(root.join("tests").join("trigger.rs"), &src.trigger_test).await?;
    Ok(ScaffoldedProject {
        path: root,
        fidelity: src.fidelity,
        payload: src.payload.clone(),
        provenance: None,
        _tempdir: tempdir,
    })
}
