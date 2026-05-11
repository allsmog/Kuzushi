use crate::command::ScanModeArg;
use crate::presentation::{emit_scan_ci_start, emit_scan_output, scan_result_or_report_ci_error};
use crate::scan_budget::apply_scan_budget_caps;
use anyhow::{Context, Result};
use kuzushi_core::modules::wants_sast_runtime;
use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::{
    load_config_for_target, AgentRuntime, FindingStore, ModuleRegistry, ToolOptionStore,
    WorkspaceTarget,
};
use kuzushi_openai::PiAgentCoreRuntime;
use std::path::PathBuf;

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
) -> Result<()> {
    let workspace = WorkspaceTarget::new(&target)?;
    let config = load_config_for_target(Some(workspace.root()))?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let registry = ModuleRegistry::with_v2_builtins();

    apply_scan_since_scope(&workspace, since.as_deref(), include_worktree, json, ci)?;
    apply_scan_budget_caps(
        &workspace,
        budget.as_deref(),
        config.operator.spend_hard_ceiling_usd,
        json,
        ci,
    )?;
    let option_store = scan_option_store(&workspace)?;
    let input = registry.prepare_tool_input(
        "sast:scan",
        scan_tool_input(mode, &tasks, triage),
        Some(&option_store),
    )?;
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
