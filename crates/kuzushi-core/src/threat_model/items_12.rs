use super::prelude::*;
use super::*;

pub fn load_persistent_threat_model(root: &Path) -> Option<Value> {
    let path = root.join(".kuzushi").join("threat-model.json");
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn save_persistent_threat_model(root: &Path, document: &Value, force: bool) -> Result<bool> {
    let path = root.join(".kuzushi").join("threat-model.json");
    if !force && path.exists() {
        if let Some(existing) = read_json_optional(&path) {
            if existing
                .get("userEdited")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Ok(false);
            }
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(document)?),
    )
    .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(true)
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
    if let Some(target) = read_string(input, &["target"]) {
        let candidate = PathBuf::from(target);
        let path = if candidate.is_absolute() {
            candidate
        } else {
            std::env::current_dir()
                .context("Could not resolve current directory")?
                .join(candidate)
        };
        return Ok(path);
    }
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    std::env::current_dir().context("Could not resolve current directory")
}

pub(crate) fn read_stages(input: &Value, tool_name: &str) -> Result<Vec<String>> {
    let Some(raw) = input.get("stages") else {
        return Ok(VALID_STAGES.iter().map(|stage| stage.to_string()).collect());
    };
    let Value::Array(items) = raw else {
        anyhow::bail!("{tool_name} stages must be an array of stage ids");
    };
    let mut stages = Vec::new();
    let mut unknown = Vec::new();
    for item in items {
        let Some(stage) = item
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            anyhow::bail!("{tool_name} stages entries must be strings");
        };
        if VALID_STAGES.contains(&stage) {
            stages.push(stage.to_string());
        } else {
            unknown.push(stage.to_string());
        }
    }
    if !unknown.is_empty() {
        anyhow::bail!(
            "{tool_name} unknown stage(s): {}. Valid: s1, s2, s3, s4.",
            unknown.join(", ")
        );
    }
    if stages.is_empty() {
        Ok(VALID_STAGES.iter().map(|stage| stage.to_string()).collect())
    } else {
        Ok(stages)
    }
}
