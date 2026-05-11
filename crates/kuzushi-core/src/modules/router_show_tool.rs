use super::*;

pub(crate) fn router_show_tool(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    use crate::agent_router::{AgentRole, AgentRouter};
    use crate::config::ConfigPaths;

    // Load models.toml if present. Best-effort — missing file = empty router.
    let target = ctx
        .workspace
        .map(|workspace| workspace.root().to_path_buf());
    let router = ConfigPaths::from_target(target.as_deref())
        .ok()
        .and_then(|paths| AgentRouter::load(&paths).ok())
        .unwrap_or_default();

    let mut roles = Vec::with_capacity(AgentRole::all().len());
    for role in AgentRole::all() {
        let key = role.option_store_key();
        // Operator override merged via effective_tool_input lives in `input`.
        let option_override = input
            .as_object()
            .and_then(|obj| obj.get(&key))
            .and_then(Value::as_str)
            .map(str::to_string);

        let toml_route = router.route(*role).cloned();

        let effective = option_override
            .clone()
            .or_else(|| toml_route.as_ref().map(|r| r.primary.clone()))
            .or_else(|| router.default_model().map(str::to_string))
            .or_else(|| ctx.config.model.clone());

        roles.push(json!({
            "role": role.as_key(),
            "optionKey": key,
            "operatorOverride": option_override,
            "tomlPrimary": toml_route.as_ref().map(|r| r.primary.clone()),
            "tomlFallbacks": toml_route.as_ref().map(|r| r.fallbacks.clone()).unwrap_or_default(),
            "effective": effective,
        }));
    }

    Ok(json!({
        "ok": true,
        "configModel": ctx.config.model,
        "tomlDefaultModel": router.default_model(),
        "roles": roles,
    }))
}

pub(crate) fn run_full_mode_hunt_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    use crate::capabilities::full_mode_multi::{report_to_tool_json, run as run_full_mode_multi};

    let cfg = full_mode_config_from_input(&input, ctx)?;
    if cfg.dry_run {
        return full_mode_dry_run_response(&cfg, ctx);
    }

    let runtime = required_full_mode_runtime(runtime)?;
    let routed = full_mode_routed_runtime(runtime, ctx)?;
    let limiter = full_mode_spend_limiter(ctx)?;
    let report = run_full_mode_multi(&routed, limiter.as_ref(), &cfg)?;
    persist_full_mode_report(ctx, &report)?;
    Ok(report_to_tool_json(&report))
}

pub(crate) fn full_mode_config_from_input(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<crate::capabilities::full_mode_multi::FullModeConfig> {
    Ok(crate::capabilities::full_mode_multi::FullModeConfig {
        workspace_root: resolve_tool_target(input, ctx)?,
        max_tokens_per_chunk: full_mode_max_tokens(input),
        deposit_usd_per_chunk: full_mode_deposit(input),
        include_extensions: Vec::new(),
        language: full_mode_language(input)?,
        dry_run: full_mode_dry_run(input),
        scope_files: full_mode_scope_files(input, ctx)?,
        failed_chunk_ids: full_mode_failed_chunk_ids(input)?,
    })
}

pub(crate) fn full_mode_language(
    input: &Value,
) -> Result<crate::capabilities::full_mode_multi::FullModeLanguage> {
    match input
        .get("language")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("c") | None => Ok(crate::capabilities::full_mode_multi::FullModeLanguage::C),
        Some("unknown") => Ok(crate::capabilities::full_mode_multi::FullModeLanguage::Unknown),
        Some(other) => anyhow::bail!("full-mode:hunt: unknown language {other:?}"),
    }
}

pub(crate) fn full_mode_max_tokens(input: &Value) -> usize {
    input
        .get("maxTokensPerChunk")
        .and_then(Value::as_u64)
        .map(|v| v as usize)
        .unwrap_or(12_000)
}

pub(crate) fn full_mode_deposit(input: &Value) -> f64 {
    input
        .get("depositUsdPerChunk")
        .and_then(Value::as_f64)
        .unwrap_or(2.0)
}

pub(crate) fn full_mode_failed_chunk_ids(input: &Value) -> Result<Option<Vec<u32>>> {
    let Some(raw) = input.get("failedChunkIds") else {
        return Ok(None);
    };
    let mut ids = match raw {
        Value::String(csv) => csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(parse_failed_chunk_id)
            .collect::<Result<Vec<_>>>()?,
        Value::Array(values) => values.iter().map(parse_failed_chunk_id_value).collect::<Result<Vec<_>>>()?,
        other => anyhow::bail!(
            "full-mode:hunt failedChunkIds must be a comma-separated string or array, got {other}"
        ),
    };
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ids))
    }
}

fn parse_failed_chunk_id(raw: &str) -> Result<u32> {
    raw.parse::<u32>()
        .map_err(|_| anyhow::anyhow!("full-mode:hunt failedChunkIds has non-integer value {raw:?}"))
}

fn parse_failed_chunk_id_value(value: &Value) -> Result<u32> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| anyhow::anyhow!("full-mode:hunt failedChunkIds has out-of-range value {number}")),
        Value::String(raw) => parse_failed_chunk_id(raw.trim()),
        other => anyhow::bail!("full-mode:hunt failedChunkIds has invalid array value {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::full_mode_failed_chunk_ids;
    use serde_json::json;

    #[test]
    fn parses_csv_failed_chunk_ids() {
        let input = json!({"failedChunkIds": "3, 7, 7, 11"});
        assert_eq!(
            full_mode_failed_chunk_ids(&input).expect("csv parse should succeed"),
            Some(vec![3, 7, 11])
        );
    }

    #[test]
    fn parses_array_failed_chunk_ids() {
        let input = json!({"failedChunkIds": [11, "3", 7, "7"]});
        assert_eq!(
            full_mode_failed_chunk_ids(&input).expect("array parse should succeed"),
            Some(vec![3, 7, 11])
        );
    }
}
