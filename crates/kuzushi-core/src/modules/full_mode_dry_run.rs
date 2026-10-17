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
    if input.get("scopeFile").is_some() {
        let path = full_mode_scope_path(input, ctx)
            .context("scopeFile requires an active repository path")?;
        return read_full_mode_scope_file(&path);
    }
    if let Some(paths) = full_mode_input_paths(input)? {
        return Ok(Some(paths));
    }
    read_implicit_full_mode_scope(ctx)
}

fn read_implicit_full_mode_scope(
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<Vec<std::path::PathBuf>>> {
    let Some(path) = full_mode_since_scope_path(ctx) else {
        return Ok(None);
    };
    if let Err(error) = std::fs::symlink_metadata(&path) {
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error.into());
    }
    read_full_mode_scope_file(&path)
}

fn full_mode_input_paths(input: &Value) -> Result<Option<Vec<std::path::PathBuf>>> {
    let Some(paths) = string_list_input(input, &["paths", "includePaths", "include_paths"])? else {
        return Ok(None);
    };
    anyhow::ensure!(
        !paths.is_empty(),
        "source paths are empty; select files before planning work"
    );
    let paths = paths
        .into_iter()
        .map(std::path::PathBuf::from)
        .collect::<Vec<_>>();
    Ok(Some(paths))
}

pub(crate) fn full_mode_scope_path(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Option<std::path::PathBuf> {
    input
        .get("scopeFile")
        .and_then(Value::as_str)
        .map(|raw| resolve_scope_file_against_workspace(raw, ctx))
        .or_else(|| full_mode_since_scope_path(ctx))
}

/// The `scopeFile` option is documented as "repo-relative" but the value
/// arrives as a raw string. If it's already absolute we honour it as-is; if
/// it's relative we resolve it against the workspace root so the meaning
/// matches the help text regardless of which cwd the caller happens to be
/// in (TUI, `kuzushi run`, or scan worker). Without this, the same option
/// silently scans every file when invoked from a different cwd.
fn resolve_scope_file_against_workspace(
    raw: &str,
    ctx: &ToolExecutionContext<'_>,
) -> std::path::PathBuf {
    let path = std::path::PathBuf::from(raw);
    if path.is_absolute() {
        return path;
    }
    relative_scope_file_path(path, ctx)
}

fn relative_scope_file_path(
    path: std::path::PathBuf,
    ctx: &ToolExecutionContext<'_>,
) -> std::path::PathBuf {
    ctx.workspace
        .map(|workspace| workspace.root().join(&path))
        .unwrap_or(path)
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
        anyhow::bail!(
            "scopeFile {} does not exist; check spelling or pass an absolute path",
            path.display()
        );
    }
    let body = crate::bounded_file::read_utf8_text(path, 4 * 1024 * 1024)
        .with_context(|| format!("could not read scope file {}", path.display()))?;
    let paths = full_mode_scope_lines(&body);
    anyhow::ensure!(
        !paths.is_empty(),
        "scopeFile is empty; select repository files before planning work"
    );
    Ok(Some(paths))
}

pub(crate) fn full_mode_scope_lines(body: &str) -> Vec<std::path::PathBuf> {
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(std::path::PathBuf::from)
        .collect()
}

pub(crate) fn full_mode_dry_run_response(
    cfg: &crate::capabilities::full_mode_multi::FullModeConfig,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let plan = with_full_mode_planning_observer(ctx, |progress, canceled| {
        crate::capabilities::full_mode_multi::plan_with_observer(cfg, progress, canceled)
    })?;
    let selected =
        crate::capabilities::full_mode_multi::selected_plan(&plan, cfg.failed_chunk_ids.as_deref());
    let model_hint = ctx.config.model.as_deref();
    let cost = crate::full_mode_cost_summary(&selected, model_hint);
    let geometry = format!(
        "full-mode:hunt planned {} chunk{} over {} file{}",
        cost.chunks,
        if cost.chunks == 1 { "" } else { "s" },
        cost.files,
        if cost.files == 1 { "" } else { "s" }
    );
    let summary =
        crate::capabilities::full_mode_multi::partial_planning_summary(&plan).unwrap_or(geometry);
    let output = full_mode_planning_detail(&summary, cfg, &cost, &plan);
    let data = full_mode_planning_data(cfg, &plan, &selected, &cost);
    let mut result = crate::module_result::completed_output_result(summary, output, data);
    if plan
        .coverage
        .as_ref()
        .is_some_and(|coverage| coverage.is_partial())
    {
        result["status"] = json!("partial");
    }
    result["costUsd"] = json!(0.0);
    Ok(result)
}

pub(crate) fn with_full_mode_planning_observer<T>(
    ctx: &ToolExecutionContext<'_>,
    operation: impl FnOnce(&mut dyn FnMut(usize), &dyn Fn() -> bool) -> Result<T>,
) -> Result<T> {
    let mut heartbeat = crate::progress::HeartbeatGate::new(std::time::Duration::from_secs(1));
    let mut progress = |entries| {
        if heartbeat.ready() {
            if let Some(trace) = ctx.trace {
                let _ = trace
                    .step(
                        "tool-progress",
                        "full-mode:hunt",
                        format!(
                            "bounded inventory/source planning · {entries} entries in current step"
                        ),
                    )
                    .emit();
            }
        }
    };
    operation(&mut progress, &|| ctx.is_cancelled())
}

fn full_mode_planning_data(
    cfg: &crate::capabilities::full_mode_multi::FullModeConfig,
    plan: &crate::capabilities::full_mode_multi::FullModePlan,
    selected: &crate::capabilities::full_mode_multi::FullModePlan,
    cost: &crate::capabilities::full_mode_multi::CostSummary,
) -> Value {
    json!({
        "findings": [],
        "plan": plan,
        "chunksDispatched": 0,
        "chunksFailed": 0,
        "costUsd": 0.0,
        "dryRun": true,
        "scanExecuted": false,
        "reuseCachedChunks": cfg.reuse_cached_chunks,
        "selection": {"chunkIds": selected.chunks.iter().map(|chunk| chunk.id).collect::<Vec<_>>(), "chunks":cost.chunks, "files":cost.files},
        "estimateBasis":"legacy-token-heuristic",
        "strictDollarCeiling":false,
        "summary": {
            "chunks": cost.chunks,
            "files": cost.files,
            "totalTokens": cost.total_tokens,
            "estUsdLow": cost.usd_low,
            "estUsdHigh": cost.usd_high,
            "dryRun": true,
        },
    })
}

fn full_mode_planning_detail(
    summary: &str,
    cfg: &crate::capabilities::full_mode_multi::FullModeConfig,
    cost: &crate::capabilities::full_mode_multi::CostSummary,
    plan: &crate::capabilities::full_mode_multi::FullModePlan,
) -> String {
    let cache = if cfg.reuse_cached_chunks {
        "enabled; identical chunks may replay earlier results"
    } else {
        "disabled; independent discovery uses fresh requests"
    };
    let coverage = crate::capabilities::full_mode_multi::planning_coverage_detail(plan);
    format!("{summary}\nPlanning only: no scan executed and no findings established.\n{coverage}\nSelected chunks: {}. Source windows: {}. Approximate input tokens: {}.\nCache reuse: {cache}.\nDollar estimate: uncertain. Legacy token bands do not bound charges.\nScan execution and provider allowance require separate approval; internal turns and repairs consume that allowance.", cost.chunks, cost.files, cost.total_tokens)
}

pub(crate) fn required_full_mode_runtime(
    runtime: Option<&dyn AgentRuntime>,
) -> Result<&dyn AgentRuntime> {
    runtime.ok_or_else(|| {
        anyhow::anyhow!(crate::runtime::missing_agent_runtime_message(
            "full-mode:hunt"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::full_mode_input_paths;
    use serde_json::json;
    use std::path::PathBuf;

    #[test]
    fn changed_file_paths_scope_full_mode_without_a_sidecar_file() {
        let paths = full_mode_input_paths(&json!({
            "paths": ["src/auth.rs", "src/db.rs"]
        }))
        .unwrap();

        assert_eq!(
            paths,
            Some(vec![
                PathBuf::from("src/auth.rs"),
                PathBuf::from("src/db.rs")
            ])
        );
    }
}

pub(crate) fn full_mode_routed_runtime<'a>(
    runtime: &'a dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
) -> Result<crate::agent_router::RoutedRuntime<'a>> {
    routed_runtime_for_tool_context(runtime, ctx, None)
}
