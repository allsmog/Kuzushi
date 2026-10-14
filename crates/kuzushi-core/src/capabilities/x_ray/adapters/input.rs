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
    let system_prompt = resolve_system_prompt(input, &target)?;
    let effort = optional_string(input, "effort")?;
    let max_budget_usd = max_budget_usd(input)?;
    let kb_context = ctx.artifact_knowledge_context(
        &target,
        "x-ray architecture entry points invariants attack surface threat model context",
        5,
    );

    Ok(XRayRunInput {
        target,
        repo_name,
        model,
        system_prompt,
        effort,
        max_budget_usd,
        kb_context,
    })
}

fn resolve_system_prompt(input: &Value, target: &Path) -> Result<String> {
    let default_prompt = x_ray_system_prompt();
    let prompt = optional_string(input, "X_RAY_PROMPT")?
        .map(|value| {
            crate::options::resolve_prepared_prompt_override_for_key(
                &value,
                target,
                "X_RAY_PROMPT",
                &default_prompt,
            )
        })
        .transpose()?
        .unwrap_or(default_prompt);
    Ok(prompt)
}

fn max_budget_usd(input: &Value) -> Result<Option<f64>> {
    let Some(value) = input
        .get("maxBudgetUsd")
        .or_else(|| input.get("max_budget_usd"))
    else {
        return Ok(None);
    };
    let value = value
        .as_f64()
        .context("x-ray:run maxBudgetUsd must be a finite positive number")?;
    anyhow::ensure!(
        value.is_finite() && value > 0.0,
        "x-ray:run maxBudgetUsd must be a finite positive number"
    );
    Ok(Some(value))
}

pub(crate) fn resolve_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(target) = optional_string(input, "target")? {
        return canonicalize_dir(Path::new(&target));
    }

    let workspace = ctx
        .workspace
        .context("x-ray tool requires an explicit target or active workspace")?;
    Ok(workspace.root().to_path_buf())
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
