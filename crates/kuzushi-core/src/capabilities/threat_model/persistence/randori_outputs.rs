use super::super::*;

pub(crate) fn preflight_randori_outputs(flavor: BuildFlavor, input: &BuildInput) -> Result<()> {
    if !matches!(flavor, BuildFlavor::RandoriPasta) {
        return Ok(());
    }
    for name in ["normalized-threat-model.json", "THREAT_MODEL.md"] {
        let path = preflight_output_artifact_path(input.workspace_root(), &input.output_dir, name)?;
        preflight_draft_file(&path, name, input.preserve_user_edits)?;
    }
    Ok(())
}

fn preflight_draft_file(path: &Path, name: &str, preserve: bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_file(),
                "Draft output is not a regular file: {}",
                path.display()
            );
            anyhow::ensure!(!preserve,
                "Draft preserved: {name}. Choose a new outputDir or explicitly set preserveUserEdits=false. Path: {}", path.display());
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("Could not inspect draft {}", path.display()))
        }
    }
}
