use super::*;

pub(in crate::modules) fn taint_iris_next_context_languages(
    context: Option<&Value>,
) -> Vec<String> {
    context
        .and_then(|value| value.pointer("/repoContext/languages"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(normalize_taint_next_language)
                .filter(|language| !language.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

pub(in crate::modules) fn taint_iris_next_context_keywords(
    context: Option<&Value>,
    target: &Path,
) -> Result<String> {
    let mut parts = Vec::new();
    if let Some(context) = context {
        if let Some(repo_context) = context.get("repoContext") {
            parts.push(repo_context.to_string());
        }
    }
    for file in [
        "package.json",
        "Cargo.toml",
        "pyproject.toml",
        "go.mod",
        "pom.xml",
    ] {
        let path = target.join(file);
        if let Ok(raw) = fs::read_to_string(path) {
            parts.push(raw);
        }
    }
    Ok(parts.join("\n").to_ascii_lowercase())
}

pub(in crate::modules) fn collect_taint_iris_next_cwes(value: Option<&Value>) -> BTreeSet<String> {
    let mut cwes = BTreeSet::new();
    if let Some(value) = value {
        collect_taint_iris_next_cwes_inner(value, &mut cwes);
    }
    cwes
}

pub(in crate::modules) fn collect_taint_iris_next_cwes_inner(
    value: &Value,
    cwes: &mut BTreeSet<String>,
) {
    match value {
        Value::String(text) => {
            for token in text.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-') {
                let normalized = normalize_taint_next_cwe(token);
                if normalized.starts_with("CWE-") {
                    cwes.insert(normalized);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_taint_iris_next_cwes_inner(item, cwes);
            }
        }
        Value::Object(object) => {
            for value in object.values() {
                collect_taint_iris_next_cwes_inner(value, cwes);
            }
        }
        _ => {}
    }
}
