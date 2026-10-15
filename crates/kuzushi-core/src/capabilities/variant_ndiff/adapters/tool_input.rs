use super::*;

pub(crate) fn optional_variant_reasoning(input: &Value) -> Option<String> {
    read_object_value(input.as_object()?, &["thinkingLevel", "thinking_level"])
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

pub(crate) fn findings_schema() -> Value {
    json!({
        "type": "object",
        "required": ["variants"],
        "additionalProperties": true,
        "properties": {
            "variants": {"type": "array", "items": {"type": "object"}},
            "findings": {"type": "array", "items": {"type": "object"}}
        }
    })
}

pub(crate) fn resolve_tool_target(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PathBuf> {
    match input.get("target").and_then(Value::as_str) {
        Some(target) => resolve_explicit_tool_target(target, ctx),
        None => resolve_context_tool_target(ctx),
    }
}

fn resolve_explicit_tool_target(target: &str, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        anyhow::bail!("variant target may not be blank")
    }
    resolve_tool_target_candidate(PathBuf::from(trimmed), ctx)
}

fn resolve_tool_target_candidate(
    candidate: PathBuf,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PathBuf> {
    if candidate.is_absolute() {
        return Ok(candidate);
    }
    let workspace = ctx
        .workspace
        .context("variant hunt requires an explicit active workspace")?;
    Ok(workspace.root().join(candidate))
}

fn resolve_context_tool_target(ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    match ctx.workspace {
        Some(workspace) => Ok(workspace.root().to_path_buf()),
        None => anyhow::bail!("variant hunt requires an explicit active workspace"),
    }
}

pub(crate) fn positive_usize_input(input: &Value, key: &str, default: usize, max: usize) -> usize {
    input
        .get(key)
        .and_then(|value| match value {
            Value::Number(number) => number.as_u64().map(|value| value as usize),
            Value::String(text) => text.parse::<usize>().ok(),
            _ => None,
        })
        .filter(|value| *value > 0)
        .unwrap_or(default)
        .min(max)
}

pub(crate) fn vendor_paths_from_input(input: &Value) -> Vec<String> {
    input
        .get("vendorPaths")
        .or_else(|| input.get("vendor_paths"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| {
            DEFAULT_VENDOR_PATHS
                .iter()
                .map(|path| (*path).to_string())
                .collect()
        })
}

pub(crate) fn normalize_file_path(root: &Path, file_path: &str) -> String {
    let candidate = PathBuf::from(file_path.trim());
    if candidate.is_absolute() {
        return candidate
            .strip_prefix(root)
            .unwrap_or(&candidate)
            .display()
            .to_string();
    }
    file_path.trim().to_string()
}

pub(crate) fn severity_from_agent(value: &str) -> Severity {
    Severity::from_scanner_label(value)
}

pub(crate) fn read_object_value<'a>(
    object: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}
