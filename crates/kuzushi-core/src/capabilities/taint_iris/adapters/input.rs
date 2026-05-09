use super::*;

impl TaintIrisInput {
    pub(crate) fn from_tool_input(input: &Value, cwd: &Path) -> Result<Self> {
        let prompt_override = optional_nonempty_string(input, "TAINT_IRIS_PROMPT")?
            .map(|value| {
                crate::options::resolve_prompt_override_for_key(&value, cwd, "TAINT_IRIS_PROMPT")
            })
            .transpose()?;
        Ok(Self {
            max_cwes: positive_usize_input(
                input,
                &["maxCwes", "max_cwes"],
                "taint-iris:hunt maxCwes",
            )?,
            max_findings: positive_usize_input(
                input,
                &["maxFindings", "max_findings"],
                "taint-iris:hunt maxFindings",
            )?
            .unwrap_or(50)
            .min(250),
            prompt_override,
            max_budget_usd: positive_f64_input(
                input,
                &["maxBudgetUsd", "max_budget_usd"],
                "taint-iris:hunt maxBudgetUsd",
            )?,
        })
    }
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

pub(crate) fn optional_nonempty_string(input: &Value, key: &str) -> Result<Option<String>> {
    match input.get(key) {
        Some(Value::String(value)) => Ok(Some(value.trim().to_string()).filter(|s| !s.is_empty())),
        Some(_) => anyhow::bail!("triage:run {key} must be a string"),
        None => Ok(None),
    }
}

fn positive_usize_input(input: &Value, keys: &[&str], label: &str) -> Result<Option<usize>> {
    keys.iter()
        .find_map(|key| input.get(*key))
        .map(|value| parse_positive_usize(value, label))
        .transpose()
}

fn parse_positive_usize(value: &Value, label: &str) -> Result<usize> {
    match value {
        Value::Number(number) => parse_positive_u64(number.as_u64(), label),
        Value::String(value) => parse_positive_usize_string(value, label),
        _ => anyhow::bail!("{label} must be a positive integer"),
    }
}

fn parse_positive_u64(value: Option<u64>, label: &str) -> Result<usize> {
    let parsed = value.with_context(|| format!("{label} must be a positive integer"))?;
    require_nonzero_usize(parsed as usize, label)
}

fn parse_positive_usize_string(value: &str, label: &str) -> Result<usize> {
    let parsed = value
        .trim()
        .parse::<usize>()
        .with_context(|| format!("{label} must be a positive integer"))?;
    require_nonzero_usize(parsed, label)
}

fn require_nonzero_usize(value: usize, label: &str) -> Result<usize> {
    if value == 0 {
        anyhow::bail!("{label} must be a positive integer");
    }
    Ok(value)
}

fn positive_f64_input(input: &Value, keys: &[&str], label: &str) -> Result<Option<f64>> {
    keys.iter()
        .find_map(|key| input.get(*key))
        .map(|value| parse_positive_f64(value, label))
        .transpose()
}

fn parse_positive_f64(value: &Value, label: &str) -> Result<f64> {
    let parsed = parse_f64_value(value, label)?;
    require_positive_f64(parsed, label)
}

fn parse_f64_value(value: &Value, label: &str) -> Result<f64> {
    if let Some(parsed) = value.as_f64() {
        return Ok(parsed);
    }
    parse_f64_string(
        value
            .as_str()
            .with_context(|| format!("{label} must be a positive number"))?,
        label,
    )
}

fn parse_f64_string(value: &str, label: &str) -> Result<f64> {
    value
        .trim()
        .parse::<f64>()
        .with_context(|| format!("{label} must be a positive number"))
}

fn require_positive_f64(value: f64, label: &str) -> Result<f64> {
    if !value.is_finite() || value <= 0.0 {
        anyhow::bail!("{label} must be a positive number");
    }
    Ok(value)
}
