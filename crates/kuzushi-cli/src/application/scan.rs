use crate::command::ScanModeArg;
use crate::presentation::{emit_scan_ci_start, emit_scan_output, scan_result_or_report_ci_error};
use crate::scan_budget::apply_scan_budget_caps;
use crate::wants_sast_runtime::wants_sast_runtime;
use anyhow::{Context, Result};
use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::{
    load_config_for_target, AgentRuntime, FindingStore, ModuleRegistry, WorkspaceTarget,
};
use kuzushi_openai::PiAgentCoreRuntime;
use std::path::PathBuf;

pub(crate) async fn scan_command(
    target: PathBuf,
    mode: ScanModeArg,
    tasks: Vec<String>,
    triage: bool,
    json: bool,
    ci: bool,
    budget: Option<String>,
    since: Option<String>,
    include_worktree: bool,
) -> Result<()> {
    let workspace = WorkspaceTarget::new(&target)?;
    let config = load_config_for_target(Some(workspace.root()))?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let registry = ModuleRegistry::with_v2_builtins();

    apply_scan_since_scope(&workspace, since.as_deref(), include_worktree, json, ci)?;
    apply_scan_budget_caps(&workspace, budget.as_deref(), json, ci)?;
    let input = scan_tool_input(mode, &tasks, triage);
    let runtime = scan_runtime(&config, &input)?;
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
    };

    let started = std::time::Instant::now();
    emit_scan_ci_start(ci, started, &target, &config, &tasks);

    let result = registry.execute_tool_with_runtime(
        "sast:scan",
        input,
        &ctx,
        runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime),
    );
    let elapsed = started.elapsed();
    let result = scan_result_or_report_ci_error(result, ci, started, elapsed)?;
    emit_scan_output(&workspace, &result, json, ci, started, elapsed)
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
    files.iter().map(|p| format!("{}\n", p.display())).collect()
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

pub(crate) fn scan_tool_input(
    mode: ScanModeArg,
    tasks: &[String],
    triage: bool,
) -> serde_json::Value {
    serde_json::json!({
        "mode": mode.as_input_value(),
        "taskMode": scan_task_mode(tasks),
        "tasks": tasks,
        "triage": triage,
    })
}

pub(crate) fn scan_task_mode(tasks: &[String]) -> &'static str {
    if tasks.is_empty() {
        "auto"
    } else {
        "manual"
    }
}

pub(crate) fn scan_runtime(
    config: &kuzushi_core::V2Config,
    input: &serde_json::Value,
) -> Result<Option<PiAgentCoreRuntime>> {
    if wants_sast_runtime(input) {
        Ok(Some(PiAgentCoreRuntime::from_config(
            config,
            std::env::current_dir()?,
        )?))
    } else {
        Ok(None)
    }
}
