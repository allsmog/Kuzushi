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
        // Operator-provided `scopeFile` paths that don't exist used to
        // silently degrade to "scan everything," which was confusing when
        // someone misspelled the path or pointed the TUI at the wrong
        // cwd. Fail loudly so the operator sees the typo before paying
        // for an unwanted whole-codebase scan. The `since.txt` default
        // path is excluded — we still allow it to be absent without
        // raising, since most operators never produce a since.txt.
        let looks_like_since_default =
            path.file_name().and_then(std::ffi::OsStr::to_str) == Some("since.txt");
        if looks_like_since_default {
            return Ok(None);
        }
        anyhow::bail!(
            "scopeFile {} does not exist; check spelling or pass an absolute path",
            path.display()
        );
    }
    let body = crate::bounded_file::read_utf8_text(path, 4 * 1024 * 1024)
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
    let summary = format!(
        "full-mode:hunt planned {} chunk{} over {} file{}",
        cost.chunks,
        if cost.chunks == 1 { "" } else { "s" },
        cost.files,
        if cost.files == 1 { "" } else { "s" }
    );
    let data = json!({
        "findings": [],
        "plan": plan,
        "chunksDispatched": 0,
        "chunksFailed": 0,
        "costUsd": 0.0,
        "dryRun": true,
        "summary": {
            "chunks": cost.chunks,
            "files": cost.files,
            "totalTokens": cost.total_tokens,
            "estUsdLow": cost.usd_low,
            "estUsdHigh": cost.usd_high,
            "dryRun": true,
        },
    });
    let mut result = crate::module_result::completed_output_result(summary.clone(), summary, data);
    result["costUsd"] = json!(0.0);
    Ok(result)
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

pub(crate) fn full_mode_routed_runtime<'a>(
    runtime: &'a dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
) -> Result<crate::agent_router::RoutedRuntime<'a>> {
    routed_runtime_for_tool_context(runtime, ctx, None)
}
