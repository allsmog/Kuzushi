use super::*;

pub(crate) fn read_manifest_summary(root: &Path) -> Result<String> {
    let mut lines = Vec::new();
    for name in ["package.json", "Cargo.toml", "pyproject.toml", "go.mod"] {
        let path = root.join(name);
        if !path.exists() {
            continue;
        }
        let raw = crate::bounded_file::read_utf8_text_within(root, &path, 256 * 1024)
            .with_context(|| format!("Could not read manifest {}", path.display()))?;
        let snippet = raw
            .lines()
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
            .chars()
            .take(2000)
            .collect::<String>();
        lines.push(format!("--- {name} ---\n{snippet}"));
    }
    if lines.is_empty() {
        Ok("(no recognized manifests)".to_string())
    } else {
        Ok(lines.join("\n\n"))
    }
}

pub(crate) fn should_skip_path(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".kuzushi"
            | ".next"
            | ".turbo"
            | "coverage"
            | "dist"
            | "native"
            | "node_modules"
            | "target"
    )
}

pub(crate) fn records(raw: Option<&Value>) -> Vec<&Map<String, Value>> {
    raw.and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default()
}

pub(crate) fn records_or_record_collections(raw: Option<&Value>) -> Vec<&Map<String, Value>> {
    match raw {
        Some(Value::Array(_)) => records(raw),
        Some(Value::Object(map)) => map
            .values()
            .flat_map(|value| records(Some(value)))
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    }
}

pub(crate) fn str_field(record: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        record
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

pub(crate) fn string_array_field(record: &Map<String, Value>, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .find_map(|key| record.get(*key))
        .map(string_array)
        .unwrap_or_default()
}

pub(crate) fn string_array(value: &Value) -> Vec<String> {
    match value {
        Value::String(value) if !value.trim().is_empty() => vec![value.trim().to_string()],
        Value::Array(items) => items
            .iter()
            .filter_map(|item| match item {
                Value::String(value) => Some(value.trim().to_string()),
                Value::Number(value) => Some(value.to_string()),
                _ => None,
            })
            .filter(|value| !value.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn number_field(record: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        record
            .get(*key)
            .and_then(Value::as_u64)
            .or_else(|| {
                record
                    .get(*key)
                    .and_then(Value::as_i64)
                    .map(|value| value.max(1) as u64)
            })
            .or_else(|| {
                record
                    .get(*key)
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<u64>().ok())
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn manifest_summary_rejects_symlink_outside_target_without_exposing_content() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let outside = temp.path().join("outside-package.json");
        fs::create_dir_all(&target).unwrap();
        fs::write(&outside, r#"{"name":"OUTSIDE_MANIFEST_TOKEN"}"#).unwrap();
        symlink(&outside, target.join("package.json")).unwrap();

        let error = read_manifest_summary(&target).unwrap_err();

        assert!(!error.to_string().contains("OUTSIDE_MANIFEST_TOKEN"));
    }
}
