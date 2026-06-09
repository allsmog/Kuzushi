use super::*;

const THREAT_MODEL_FILE: &str = "threat-model.json";

pub fn persistent_threat_model_path(root: &Path) -> PathBuf {
    crate::workspace::workspace_state_root(root).join(THREAT_MODEL_FILE)
}

pub fn load_persistent_threat_model(root: &Path) -> Option<Value> {
    let path = persistent_threat_model_path(root);
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn save_persistent_threat_model(root: &Path, document: &Value, force: bool) -> Result<bool> {
    let path = persistent_threat_model_path(root);
    if should_preserve_persistent_threat_model(&path, force) {
        return Ok(false);
    }
    write_persistent_threat_model(&path, document)?;
    Ok(true)
}

fn should_preserve_persistent_threat_model(path: &Path, force: bool) -> bool {
    !force && path.exists() && persistent_threat_model_user_edited(path)
}

fn persistent_threat_model_user_edited(path: &Path) -> bool {
    read_json_optional(path)
        .and_then(|existing| {
            existing
                .get("userEdited")
                .and_then(Value::as_bool)})
        .unwrap_or(false)
}

fn write_persistent_threat_model(path: &Path, document: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(document)?),
    )
    .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(())
}

pub(crate) fn write_normalized_artifact(
    root: &Path,
    output_dir: &str,
    document: &Value,
) -> Result<PathBuf> {
    let dir = resolve_output_dir(root, output_dir);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let path = dir.join("normalized-threat-model.json");
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(document)?),
    )
    .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

pub(crate) fn read_json_optional(path: &Path) -> Option<Value> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str::<Value>(&raw).ok()
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
        Some(target) => resolve_explicit_target(PathBuf::from(target)),
        None => resolve_context_target(ctx),
    }
}

fn resolve_explicit_target(candidate: PathBuf) -> Result<PathBuf> {
    if candidate.is_absolute() {
        return Ok(candidate);
    }
    Ok(current_target_dir()?.join(candidate))
}

fn resolve_context_target(ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    match ctx.workspace {
        Some(workspace) => Ok(workspace.root().to_path_buf()),
        None => current_target_dir(),
    }
}

fn current_target_dir() -> Result<PathBuf> {
    std::env::current_dir().context("Could not resolve current directory")
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
}
