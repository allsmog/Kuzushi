use super::*;
use crate::WorkspaceTarget;

const THREAT_MODEL_FILE: &str = "threat-model.json";
const MAX_THREAT_MODEL_JSON_BYTES: usize = 16 * 1024 * 1024;

pub fn persistent_threat_model_path(root: &Path) -> PathBuf {
    crate::workspace::workspace_state_root(root).join(THREAT_MODEL_FILE)
}

pub fn load_persistent_threat_model(root: &Path) -> Option<Value> {
    try_load_persistent_threat_model(root).ok().flatten()
}

pub fn try_load_persistent_threat_model(root: &Path) -> Result<Option<Value>> {
    let path = checked_persistent_threat_model_path(root)?;
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("Could not inspect threat model {}", path.display())),
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            let body = crate::bounded_file::read_utf8_text_within(
                root,
                &path,
                MAX_THREAT_MODEL_JSON_BYTES,
            )
            .with_context(|| format!("Could not read threat model {}", path.display()))?;
            serde_json::from_str(&body)
                .with_context(|| format!("Threat model {} is malformed", path.display()))
                .map(Some)
        }
        Ok(_) => anyhow::bail!("Threat model {} is not a regular file", path.display()),
    }
}

pub fn save_persistent_threat_model(root: &Path, document: &Value, force: bool) -> Result<bool> {
    crate::workspace::ensure_workspace_descendant_dir(
        root,
        Path::new(crate::workspace::KUZUSHI_STATE_DIR),
    )?;
    let path = checked_persistent_threat_model_path(root)?;
    if should_preserve_persistent_threat_model(&path, force)? {
        return Ok(false);
    }
    write_persistent_threat_model(&path, document)?;
    Ok(true)
}

fn should_preserve_persistent_threat_model(path: &Path, force: bool) -> Result<bool> {
    if force {
        return Ok(false);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            persistent_threat_model_user_edited(path)
        }
        Ok(_) => anyhow::bail!(
            "Existing threat model {} is not a regular file; refusing to overwrite it",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("Could not inspect existing threat model {}", path.display())),
    }
}

fn persistent_threat_model_user_edited(path: &Path) -> Result<bool> {
    let read = crate::bounded_file::read_utf8_text_prefix(path, MAX_THREAT_MODEL_JSON_BYTES)
        .with_context(|| format!("Could not read existing threat model {}", path.display()))?;
    anyhow::ensure!(
        !read.truncated,
        "Existing threat model {} exceeds the {} byte limit; refusing to overwrite it",
        path.display(),
        MAX_THREAT_MODEL_JSON_BYTES
    );
    let existing: Value = serde_json::from_str(&read.text).with_context(|| {
        format!(
            "Existing threat model {} is malformed; refusing to overwrite it",
            path.display()
        )
    })?;
    Ok(existing
        .get("userEdited")
        .and_then(Value::as_bool)
        .unwrap_or(false))
}

fn write_persistent_threat_model(path: &Path, document: &Value) -> Result<()> {
    write_json_atomic(path, document)
}

pub(crate) fn write_normalized_artifact(
    root: &Path,
    output_dir: &str,
    document: &Value,
) -> Result<PathBuf> {
    let path = checked_normalized_artifact_path(root, output_dir)?;
    write_json_atomic(&path, document)?;
    Ok(path)
}

/// Write a named staged-pipeline artifact (research.json, coverage.json,
/// gapfill.json) next to the normalized artifact, under the same
/// workspace-containment checks.
pub(crate) fn write_stage_artifact(
    root: &Path,
    output_dir: &str,
    file_name: &str,
    value: &Value,
) -> Result<PathBuf> {
    let path = checked_output_artifact_path(root, output_dir, file_name)?;
    write_json_atomic(&path, value)?;
    Ok(path)
}

pub(crate) fn read_json_optional(path: &Path) -> Option<Value> {
    let read = crate::bounded_file::read_utf8_text_prefix(path, MAX_THREAT_MODEL_JSON_BYTES).ok()?;
    if read.truncated {
        return None;
    }
    serde_json::from_str::<Value>(&read.text).ok()
}

fn checked_persistent_threat_model_path(root: &Path) -> Result<PathBuf> {
    let path = persistent_threat_model_path(root);
    let relative = path
        .strip_prefix(root)
        .context("Persistent threat model path escaped the workspace")?;
    crate::workspace::validated_workspace_descendant(root, relative)
}

fn checked_normalized_artifact_path(root: &Path, output_dir: &str) -> Result<PathBuf> {
    checked_output_artifact_path(root, output_dir, "normalized-threat-model.json")
}

fn checked_output_artifact_path(
    root: &Path,
    output_dir: &str,
    file_name: &str,
) -> Result<PathBuf> {
    let workspace = WorkspaceTarget::new(root)?;
    let directory = resolve_output_dir(workspace.root(), output_dir);
    let relative = directory.strip_prefix(workspace.root()).with_context(|| {
        format!(
            "Threat-model output directory {} must stay inside workspace {}",
            directory.display(),
            workspace.root().display()
        )
    })?;
    let artifact = relative.join(file_name);
    ensure_artifact_parent(workspace.root(), &artifact)?;
    crate::workspace::validated_workspace_descendant(workspace.root(), artifact)
}

fn ensure_artifact_parent(root: &Path, artifact: &Path) -> Result<()> {
    let Some(parent) = artifact.parent().filter(|path| !path.as_os_str().is_empty()) else {
        return Ok(());
    };
    crate::workspace::ensure_workspace_descendant_dir(root, parent)?;
    Ok(())
}

fn write_json_atomic(path: &Path, document: &Value) -> Result<()> {
    let body = format!("{}\n", serde_json::to_string_pretty(document)?);
    crate::fs_atomic::write_atomic(path, &body)
        .with_context(|| format!("Could not write {}", path.display()))
}

pub(crate) fn resolve_output_dir(root: &Path, output_dir: &str) -> PathBuf {
    let path = PathBuf::from(output_dir);
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

pub(crate) fn resolve_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    match read_string(input, &["target"]) {
        Some(target) => resolve_explicit_target(PathBuf::from(target), ctx),
        None => resolve_context_target(ctx),
    }
}

fn resolve_explicit_target(candidate: PathBuf, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if candidate.is_absolute() {
        return Ok(candidate);
    }
    Ok(required_target_dir(ctx)?.join(candidate))
}

fn resolve_context_target(ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    match ctx.workspace {
        Some(workspace) => Ok(workspace.root().to_path_buf()),
        None => anyhow::bail!("threat-model requires an explicit active workspace"),
    }
}

fn required_target_dir<'a>(ctx: &'a ToolExecutionContext<'_>) -> Result<&'a Path> {
    ctx.workspace
        .map(WorkspaceTarget::root)
        .context("threat-model requires an explicit active workspace")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_threat_model_path_uses_workspace_state_root() {
        let root = Path::new("/repo");
        let state_root = crate::workspace::workspace_state_root(root);

        assert_eq!(
            persistent_threat_model_path(root),
            state_root.join(THREAT_MODEL_FILE)
        );
    }

    #[test]
    fn loading_missing_threat_model_does_not_create_workspace_state() {
        let workspace = tempfile::tempdir().unwrap();

        assert!(try_load_persistent_threat_model(workspace.path())
            .unwrap()
            .is_none());
        assert!(!workspace.path().join(".kuzushi").exists());
    }

    #[cfg(unix)]
    #[test]
    fn persistent_writer_does_not_follow_workspace_symlink() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), "sentinel").unwrap();
        fs::create_dir(workspace.path().join(".kuzushi")).unwrap();
        symlink(
            outside.path(),
            workspace.path().join(".kuzushi/threat-model.json"),
        )
        .unwrap();

        assert!(save_persistent_threat_model(workspace.path(), &json!({"safe": true}), true)
            .is_err());
        assert_eq!(fs::read_to_string(outside.path()).unwrap(), "sentinel");
        assert!(load_persistent_threat_model(workspace.path()).is_none());
    }

    #[test]
    fn persistent_writer_preserves_malformed_existing_document_by_default() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join(".kuzushi")).unwrap();
        let path = persistent_threat_model_path(workspace.path());
        fs::write(&path, "operator notes that are not valid JSON").unwrap();

        let error = save_persistent_threat_model(workspace.path(), &json!({"safe": true}), false)
            .unwrap_err();

        assert!(error.to_string().contains("malformed"));
        assert_eq!(
            fs::read_to_string(path).unwrap(),
            "operator notes that are not valid JSON"
        );
    }

    #[cfg(unix)]
    #[test]
    fn normalized_writer_does_not_follow_workspace_symlink() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), "sentinel").unwrap();
        let output = workspace.path().join(".kuzushi/tm-artifacts");
        fs::create_dir_all(&output).unwrap();
        symlink(outside.path(), output.join("normalized-threat-model.json")).unwrap();

        assert!(write_normalized_artifact(
            workspace.path(),
            ".kuzushi/tm-artifacts",
            &json!({"safe": true}),
        )
        .is_err());
        assert_eq!(fs::read_to_string(outside.path()).unwrap(), "sentinel");
    }
}
