use super::*;

pub(crate) fn full_mode_dry_run(input: &Value) -> bool {
    input
        .get("dryRun")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(crate) fn full_mode_scope_files(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<Vec<std::path::PathBuf>>> {
    let Some(path) = full_mode_scope_path(input, ctx) else {
        return Ok(None);
    };
    read_full_mode_scope_file(&path)
}

pub(crate) fn full_mode_scope_path(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Option<std::path::PathBuf> {
    input
        .get("scopeFile")
        .and_then(Value::as_str)
        .map(std::path::PathBuf::from)
        .or_else(|| full_mode_since_scope_path(ctx))
}

pub(crate) fn full_mode_since_scope_path(
    ctx: &ToolExecutionContext<'_>,
) -> Option<std::path::PathBuf> {
    ctx.workspace.map(|w| {
        w.findings_db_path()
            .with_file_name("since.txt")
            .to_path_buf()
    })
}

pub(crate) fn read_full_mode_scope_file(
    path: &std::path::Path,
) -> Result<Option<Vec<std::path::PathBuf>>> {
    if !path.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("could not read scope file {}", path.display()))?;
    Ok(non_empty_full_mode_scope_files(full_mode_scope_lines(
        &body,
    )))
}

pub(crate) fn full_mode_scope_lines(body: &str) -> Vec<std::path::PathBuf> {
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(std::path::PathBuf::from)
        .collect()
}

pub(crate) fn non_empty_full_mode_scope_files(
    scope_files: Vec<std::path::PathBuf>,
) -> Option<Vec<std::path::PathBuf>> {
    if scope_files.is_empty() {
        None
    } else {
        Some(scope_files)
    }
}

pub(crate) fn full_mode_dry_run_response(
    cfg: &crate::capabilities::full_mode_multi::FullModeConfig,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let plan = crate::capabilities::full_mode_multi::plan(cfg)?;
    let model_hint = ctx.config.model.as_deref();
    let cost = crate::full_mode_cost_summary(&plan, model_hint);
    Ok(json!({
        "ok": true,
        "data": {
            "findings": [],
            "plan": plan,
            "chunksDispatched": 0,
            "chunksFailed": 0,
            "costUsd": 0.0,
            "dryRun": true,
        },
        "summary": {
            "chunks": cost.chunks,
            "files": cost.files,
            "totalTokens": cost.total_tokens,
            "estUsdLow": cost.usd_low,
            "estUsdHigh": cost.usd_high,
            "dryRun": true,
        },
    }))
}

pub(crate) fn required_full_mode_runtime(
    runtime: Option<&dyn AgentRuntime>,
) -> Result<&dyn AgentRuntime> {
    runtime
        .ok_or_else(|| anyhow::anyhow!("full-mode:hunt requires an agent runtime; none configured"))
}

pub(crate) fn full_mode_routed_runtime(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
) -> Result<crate::agent_router::RoutedRuntime> {
    use crate::agent_router::{AgentRouter, RoutedRuntime};
    use std::sync::Arc;

    let router = Arc::new(AgentRouter::load(&full_mode_config_paths(ctx))?);
    let inner_arc: Arc<dyn AgentRuntime> = unsafe_clone_runtime_ref(runtime);
    Ok(RoutedRuntime::new(
        inner_arc,
        router,
        ctx.config.model.clone(),
    ))
}
