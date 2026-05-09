use super::*;

pub(crate) fn parse_run_input(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<XRayRunInput> {
    let target = resolve_target(input, ctx)?;
    let repo_name = repo_name(&target);
    let model = crate::runtime::resolve_explicit_model(
        "x-ray:run",
        optional_string(input, "model")?,
        ctx.config.model.as_deref(),
    )?;
    let effort = optional_string(input, "effort")?;
    let max_budget_usd = input
        .get("maxBudgetUsd")
        .or_else(|| input.get("max_budget_usd"))
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value >= 0.0);
    let kb_context = ctx.artifact_knowledge_context(
        &target,
        "x-ray architecture entry points invariants attack surface threat model context",
        5,
    );

    Ok(XRayRunInput {
        target,
        repo_name,
        model,
        effort,
        max_budget_usd,
        kb_context,
    })
}

pub(crate) fn resolve_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(target) = optional_string(input, "target")? {
        return canonicalize_dir(Path::new(&target));
    }

    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }

    canonicalize_dir(Path::new("."))
}

pub(crate) fn canonicalize_dir(path: &Path) -> Result<PathBuf> {
    let root = fs::canonicalize(path)
        .with_context(|| format!("Could not resolve target {}", path.display()))?;
    if !root.is_dir() {
        anyhow::bail!("Target must be a directory: {}", root.display());
    }
    Ok(root)
}

pub(crate) fn optional_string(input: &Value, key: &str) -> Result<Option<String>> {
    match input.get(key) {
        Some(Value::String(value)) => Ok(Some(value.trim().to_string()).filter(|s| !s.is_empty())),
        Some(_) => anyhow::bail!("x-ray:run {key} must be a string"),
        None => Ok(None),
    }
}
