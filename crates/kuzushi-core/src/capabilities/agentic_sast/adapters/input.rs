use super::*;

impl AgenticSastInput {
    pub(crate) fn from_tool_input(input: &Value) -> Result<Self> {
        let max_findings = agentic_sast_max_findings(input)?;
        let passes = agentic_sast_passes(input)?;
        let severity = string_list_input(input, &["severity"])?.unwrap_or_else(|| {
            vec![
                "ERROR".to_string(),
                "WARNING".to_string(),
                "INFO".to_string(),
            ]
        });
        let exclude_patterns =
            string_list_input(input, &["excludePatterns", "exclude_patterns"])?.unwrap_or_default();

        Ok(Self {
            max_findings,
            passes,
            severity,
            exclude_patterns,
        })
    }
}

fn agentic_sast_max_findings(input: &Value) -> Result<usize> {
    bounded_positive_usize_input(
        input
            .get("maxFindings")
            .or_else(|| input.get("max_findings")),
        40,
        200,
        "agentic-sast:scan maxFindings must be a positive integer",
    )
}

fn agentic_sast_passes(input: &Value) -> Result<usize> {
    let passes = bounded_positive_usize_input(
        input.get("passes"),
        1,
        2,
        "agentic-sast:scan passes must be 1 or 2",
    )?;
    anyhow::ensure!(
        matches!(passes, 1 | 2),
        "agentic-sast:scan passes must be 1 or 2"
    );
    Ok(passes)
}

fn bounded_positive_usize_input(
    value: Option<&Value>,
    default: usize,
    max: usize,
    error: &'static str,
) -> Result<usize> {
    let Some(value) = value else {
        return Ok(default);
    };
    parse_positive_usize(value, error).map(|value| value.min(max))
}

fn parse_positive_usize(value: &Value, error: &'static str) -> Result<usize> {
    let parsed = match value {
        Value::Number(number) => number.as_u64().map(|value| value as usize),
        Value::String(value) => value.parse::<usize>().ok(),
        _ => None,
    };
    parsed.filter(|value| *value > 0).context(error)
}

pub(crate) fn resolve_tool_target(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PathBuf> {
    if let Some(target) = input.get("target").and_then(Value::as_str) {
        return resolve_input_target(target);
    }
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    current_dir()
}

fn resolve_input_target(target: &str) -> Result<PathBuf> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return current_dir();
    }
    let candidate = PathBuf::from(trimmed);
    resolve_candidate_target(candidate)
}

fn resolve_candidate_target(candidate: PathBuf) -> Result<PathBuf> {
    if candidate.is_absolute() {
        Ok(candidate)
    } else {
        Ok(current_dir()?.join(candidate))
    }
}

fn current_dir() -> Result<PathBuf> {
    std::env::current_dir().context("Could not resolve current directory")
}

fn string_list_input(input: &Value, keys: &[&str]) -> Result<Option<Vec<String>>> {
    let Some(raw) = keys.iter().find_map(|key| input.get(*key)) else {
        return Ok(None);
    };
    string_list_value(raw).map(Some)
}

fn string_list_value(raw: &Value) -> Result<Vec<String>> {
    if let Some(value) = raw.as_str() {
        return Ok(csv_string_values(value));
    }
    if let Some(items) = raw.as_array() {
        return string_array_values(items);
    }
    anyhow::bail!("agentic-sast:scan list inputs must be a string or string array")
}

fn csv_string_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn string_array_values(items: &[Value]) -> Result<Vec<String>> {
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .context("agentic-sast:scan list inputs must contain only non-empty strings")
        })
        .collect()
}

pub(crate) fn optional_nonempty_string(input: &Value, key: &str) -> Result<Option<String>> {
    input
        .get(key)
        .map(|value| optional_nonempty_string_value(value, key))
        .transpose()
        .map(Option::flatten)
}

fn optional_nonempty_string_value(value: &Value, key: &str) -> Result<Option<String>> {
    let Some(value) = value.as_str() else {
        anyhow::bail!("agentic-sast:scan {key} must be a string");
    };
    Ok(Some(value.trim().to_string()).filter(|value| !value.is_empty()))
}
