use super::scan_gate::{apply_scan_gate_policy, ScanGatePolicy};
use super::scan_prepare::{
    prepare_scan_command, prepare_scan_command_with_requested_input, PreparedScanCommand, SCAN_TOOL,
};
use crate::command::ScanModeArg;
use crate::presentation::{emit_scan_ci_start, emit_scan_output, scan_result_or_report_ci_error};
use anyhow::{Context, Result};
use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::run_artifacts::{
    record_tool_run_failed, record_tool_run_started_with_reproducibility, ToolRunRecord,
};
use kuzushi_core::{
    config_hash, load_config_for_target, tool_wants_runtime, AgentRuntime, FindingStore,
    ModuleRegistry, ToolOptionStore, TraceHandle, WorkspaceTarget,
};
use kuzushi_openai::LangGraphRuntime;
use std::path::{Path, PathBuf};

pub(crate) async fn scan_command(
    target: PathBuf,
    mode: Option<ScanModeArg>,
    tasks: Vec<String>,
    triage: Option<bool>,
    json: bool,
    ci: bool,
    budget: Option<String>,
    since: Option<String>,
    include_worktree: bool,
    gate: ScanGatePolicy,
) -> Result<()> {
    if is_apk_file(&target) {
        return scan_apk_command(target, json, ci, gate).await;
    }
    execute_prepared_scan(
        prepare_scan_command(
            &target,
            mode,
            &tasks,
            triage,
            budget.as_deref(),
            since.as_deref(),
            include_worktree,
            json,
            ci,
        )?,
        &target,
        &tasks,
        json,
        ci,
        gate,
    )
}

pub(crate) async fn scan_command_with_requested_input(
    target: PathBuf,
    input: serde_json::Value,
    task_labels: Vec<String>,
    json: bool,
    ci: bool,
    gate: ScanGatePolicy,
) -> Result<()> {
    execute_prepared_scan(
        prepare_scan_command_with_requested_input(&target, input, json, ci)?,
        &target,
        &task_labels,
        json,
        ci,
        gate,
    )
}

fn execute_prepared_scan(
    prepared: PreparedScanCommand,
    target: &PathBuf,
    tasks: &[String],
    json: bool,
    ci: bool,
    gate: ScanGatePolicy,
) -> Result<()> {
    let PreparedScanCommand {
        workspace,
        config,
        store,
        registry,
        input,
        runtime,
        run_id,
    } = prepared;
    let trace = scan_trace(&workspace, &run_id);
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: Some(&trace),
    };

    let started = std::time::Instant::now();
    emit_scan_ci_start(ci, started, &target, &config, &tasks);
    reconcile_suppressions_before_scan(&store, &workspace)?;

    let result = execute_scan_tool(ScanToolExecution {
        registry: &registry,
        input,
        ctx: &ctx,
        runtime: runtime.as_ref(),
        workspace: &workspace,
        run_id: &run_id,
        config: &config,
    });
    let elapsed = started.elapsed();
    let result = scan_result_or_report_ci_error(result, ci, started, elapsed)?;
    emit_scan_output(&workspace, &result, json, ci, started, elapsed)?;
    apply_scan_gate_policy(&workspace, &store, scan_gate_id(&result, &run_id), &gate)
}

fn scan_trace(workspace: &WorkspaceTarget, run_id: &str) -> TraceHandle {
    TraceHandle::jsonl(workspace.root(), run_id)
}

/// Reconcile suppression rules against the current clock before the scan so a
/// workspace with lapsed suppressions begins by reopening them. A failure here
/// is a hard error: the `--fail-on` gate must never honor a suppression that
/// could not be re-evaluated, so we refuse to run the scan on stale state
/// rather than silently passing a lapsed suppression.
fn reconcile_suppressions_before_scan(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
) -> Result<()> {
    let sweep =
        kuzushi_core::suppressions::run_suppression_sweep(store, workspace, "system:scan-start")
            .context("suppression sweep failed at scan start; refusing to gate on stale state")?;
    if !sweep.summary.is_noop() {
        eprintln!(
            "suppressions: {} added, {} reopened by expiry, {} reopened by rule removal",
            sweep.summary.added, sweep.summary.expired, sweep.summary.removed
        );
    }
    Ok(())
}

/// Findings persist under the scan tool's own run id (`data.runId`), which can
/// differ from the CLI-minted run id; prefer the tool's, fall back to ours.
fn scan_gate_id<'a>(result: &'a serde_json::Value, fallback: &'a str) -> &'a str {
    result
        .pointer("/data/runId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(fallback)
}

struct ScanToolExecution<'a> {
    registry: &'a ModuleRegistry,
    input: serde_json::Value,
    ctx: &'a ToolExecutionContext<'a>,
    runtime: Option<&'a LangGraphRuntime>,
    workspace: &'a WorkspaceTarget,
    run_id: &'a str,
    config: &'a kuzushi_core::V2Config,
}

fn execute_scan_tool(execution: ScanToolExecution<'_>) -> Result<serde_json::Value> {
    let failure_input = execution.input.clone();
    let result = execution.registry.dispatch_prepared_tool_with_runtime(
        SCAN_TOOL,
        execution.input,
        execution.ctx,
        execution
            .runtime
            .map(|runtime| runtime as &dyn AgentRuntime),
    );
    record_failed_scan_execution(
        &result,
        ScanExecutionFailureRecord {
            workspace: execution.workspace,
            registry: execution.registry,
            run_id: execution.run_id,
            input: &failure_input,
            config: execution.config,
        },
    );
    result
}

struct ScanExecutionFailureRecord<'a> {
    workspace: &'a WorkspaceTarget,
    registry: &'a ModuleRegistry,
    run_id: &'a str,
    input: &'a serde_json::Value,
    config: &'a kuzushi_core::V2Config,
}

fn record_failed_scan_execution(
    result: &Result<serde_json::Value>,
    record: ScanExecutionFailureRecord<'_>,
) {
    let Err(error) = result else {
        return;
    };
    let tool_run = ToolRunRecord::new(record.workspace.root(), record.run_id, "scan", SCAN_TOOL);
    record_tool_run_started_with_reproducibility(
        tool_run,
        record.input,
        record.config.model.clone(),
        config_hash(record.config).ok(),
        record.registry.loaded_module_specifiers(),
    );
    record_tool_run_failed(tool_run, &error.to_string());
}

pub(crate) fn apply_scan_since_scope(
    workspace: &WorkspaceTarget,
    since: Option<&str>,
    include_worktree: bool,
    json: bool,
    ci: bool,
) -> Result<()> {
    let Some(since_ref) = since else {
        return Ok(());
    };
    let scope = kuzushi_core::git_diff_files(workspace.root(), since_ref, include_worktree)
        .with_context(|| format!("--since {since_ref:?} failed"))?;
    let scope_file = workspace.findings_db_path().with_file_name("since.txt");
    std::fs::write(&scope_file, scan_scope_body(&scope.files))
        .with_context(|| format!("could not write {}", scope_file.display()))?;
    emit_scan_scope_line(&scope.files, since_ref, include_worktree, json, ci);
    Ok(())
}

pub(crate) fn scan_scope_body(files: &[PathBuf]) -> String {
    files
        .iter()
        .filter_map(|p| {
            let rendered = p.display().to_string();
            // A path containing `\n` or `\r` would inject extra entries in
            // the scope file consumed by downstream engines (since.txt is
            // line-delimited). Git accepts such paths in working-tree
            // entries, so a hostile target repo could craft one to bypass
            // scope. Drop instead of escape — legitimate filenames have
            // no embedded newlines.
            if rendered.contains('\n') || rendered.contains('\r') {
                eprintln!(
                    "scan-scope: dropping path with embedded newline/CR: {:?}",
                    rendered
                );
                return None;
            }
            Some(format!("{rendered}\n"))
        })
        .collect()
}

pub(crate) fn emit_scan_scope_line(
    files: &[PathBuf],
    since_ref: &str,
    include_worktree: bool,
    json: bool,
    ci: bool,
) {
    if !json && !ci {
        eprintln!(
            "scope: {} files since {} {}",
            files.len(),
            since_ref,
            scan_worktree_suffix(include_worktree)
        );
    }
}

pub(crate) fn scan_worktree_suffix(include_worktree: bool) -> &'static str {
    if include_worktree {
        "(+worktree)"
    } else {
        ""
    }
}

fn is_apk_file(target: &Path) -> bool {
    if !target.is_file() {
        return false;
    }
    target
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("apk"))
        .unwrap_or(false)
}

async fn scan_apk_command(apk: PathBuf, json: bool, ci: bool, gate: ScanGatePolicy) -> Result<()> {
    let workspace_dir = apk
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let workspace = WorkspaceTarget::new(&workspace_dir)?;
    let config = load_config_for_target(Some(workspace.root()))?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let registry = ModuleRegistry::with_v2_builtins();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
    };
    let input = registry.prepare_tool_input_for_dispatch(
        "android-apk:scan",
        apk_scan_tool_input(&apk, &workspace_dir),
        &ctx,
        None,
    )?;
    let started = std::time::Instant::now();
    emit_scan_ci_start(ci, started, &apk, &config, &Vec::new());
    let result =
        registry.dispatch_prepared_tool_with_runtime("android-apk:scan", input, &ctx, None);
    let elapsed = started.elapsed();
    let result = scan_result_or_report_ci_error(result, ci, started, elapsed)?;
    emit_scan_output(&workspace, &result, json, ci, started, elapsed)?;
    apply_scan_gate_policy(&workspace, &store, scan_gate_id(&result, ""), &gate)
}

fn apk_scan_tool_input(apk: &Path, workspace: &Path) -> serde_json::Value {
    serde_json::json!({
        "apk": apk.display().to_string(),
        "target": workspace.display().to_string(),
        "decompiler": "both",
    })
}

pub(crate) fn scan_tool_input(
    mode: Option<ScanModeArg>,
    tasks: &[String],
    triage: Option<bool>,
) -> serde_json::Value {
    let mut input = serde_json::Map::new();
    if let Some(mode) = mode {
        input.insert("mode".to_string(), serde_json::json!(mode.as_input_value()));
    }
    if !tasks.is_empty() {
        input.insert("taskMode".to_string(), serde_json::json!("manual"));
        input.insert("tasks".to_string(), serde_json::json!(tasks));
    }
    if let Some(triage) = triage {
        input.insert("triage".to_string(), serde_json::json!(triage));
    }
    serde_json::Value::Object(input)
}

pub(crate) fn scan_option_store(workspace: &WorkspaceTarget) -> Result<ToolOptionStore> {
    let paths = kuzushi_core::ConfigPaths::from_target(Some(workspace.root()))?;
    ToolOptionStore::load_persistent(
        &paths.global_options_path(),
        paths.project_options_path().as_deref(),
    )
}

pub(crate) fn scan_runtime(
    config: &kuzushi_core::V2Config,
    input: &serde_json::Value,
) -> Result<Option<LangGraphRuntime>> {
    if tool_wants_runtime(SCAN_TOOL, input, config) {
        Ok(Some(LangGraphRuntime::from_config(
            config,
            std::env::current_dir()?,
        )?))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::scan_scope_body;
    use std::path::PathBuf;

    #[test]
    fn scope_body_drops_paths_with_embedded_newline() {
        let files = vec![
            PathBuf::from("src/lib.rs"),
            PathBuf::from("evil\n[+0.0s] exit: 0"),
            PathBuf::from("src/main.rs"),
        ];
        let body = scan_scope_body(&files);
        assert!(body.contains("src/lib.rs"));
        assert!(body.contains("src/main.rs"));
        assert!(
            !body.contains("evil"),
            "newline-bearing path must be dropped, got: {body:?}"
        );
        // The body itself only contains the two safe entries plus terminators
        let lines: Vec<_> = body.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn scope_body_drops_paths_with_carriage_return() {
        let files = vec![PathBuf::from("safe.rs"), PathBuf::from("evil\rgotcha")];
        let body = scan_scope_body(&files);
        assert!(body.contains("safe.rs"));
        assert!(!body.contains("gotcha"));
    }
}
