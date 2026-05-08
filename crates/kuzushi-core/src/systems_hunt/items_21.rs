use super::prelude::*;
use super::*;

pub(crate) fn positive_usize(input: &Value, keys: &[&str], default: usize) -> Result<usize> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            let Some(number) = value.as_u64() else {
                anyhow::bail!("systems-hunt {key} must be a positive integer");
            };
            if number == 0 {
                anyhow::bail!("systems-hunt {key} must be a positive integer");
            }
            return Ok(number as usize);
        }
    }
    Ok(default)
}

pub(crate) fn optional_nonempty_string(input: &Value, key: &str) -> Result<Option<String>> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    let Some(value) = value.as_str() else {
        anyhow::bail!("systems-hunt {key} must be a string");
    };
    let value = value.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.to_string()))
    }
}

pub(crate) fn artifact_root(target: &Path, raw: &str) -> Result<PathBuf> {
    let normalized = raw
        .trim()
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_string();
    let relative = if normalized.is_empty() {
        ".kuzushi/systems-hunt"
    } else {
        normalized.as_str()
    };
    let path = Path::new(relative);
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        anyhow::bail!("systems-hunt artifactDir must stay inside the repository root: {relative}");
    }
    Ok(target.join(path))
}

pub(crate) fn write_artifact(root: &Path, fingerprint: &str, artifact: &Value) -> Result<PathBuf> {
    fs::create_dir_all(root).with_context(|| format!("Could not create {}", root.display()))?;
    let path = root.join(format!("{fingerprint}.json"));
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(artifact)?),
    )
    .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

pub(crate) fn resolve_codeql_db_path(target: &Path) -> Option<PathBuf> {
    [target.join(".kuzushi/codeql-db"), target.join(".codeql/db")]
        .into_iter()
        .find(|path| path.exists())
}

pub(crate) fn path_relative_to(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/")
}

pub(crate) fn normalize_relative_path(value: String) -> String {
    let path = Path::new(value.trim());
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str().map(ToString::to_string),
            Component::CurDir => None,
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub(crate) fn format_inventory(inventory: &[(String, String)]) -> String {
    inventory
        .iter()
        .map(|(path, body)| format!("## {path}\n```text\n{}\n```", body.trim()))
        .collect::<Vec<_>>()
        .join("\n\n")
}

pub(crate) fn parse_severity(value: String) -> Severity {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "error" | "high" => Severity::High,
        "warning" | "medium" => Severity::Medium,
        "info" | "low" => Severity::Low,
        _ => Severity::Medium,
    }
}

pub(crate) fn string_field(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string()
}
