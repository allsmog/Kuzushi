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
) -> Result<()> {
    if is_apk_file(&target) {
        return scan_apk_command(target, json, ci).await;
    }
    scan_source_tree_command(ScanArgs {
        target,
        mode,
        tasks,
        triage,
        json,
        ci,
        budget,
        since,
        include_worktree,
    })
    .await
}

async fn scan_source_tree_command(args: ScanArgs) -> Result<()> {
    let workspace = WorkspaceTarget::new(&args.target)?;
    let config = load_config_for_target(Some(workspace.root()))?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let registry = ModuleRegistry::with_v2_builtins();
    apply_pre_scan_policy(&workspace, &config, &args)?;
    let input = build_sast_scan_input(&workspace, &registry, args.mode, &args.tasks, args.triage)?;
    let runtime = scan_runtime(&config, &input)?;
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
    };
    run_and_emit_sast_scan(&registry, input, &ctx, runtime.as_ref(), &workspace, &args, &config)
}

pub(crate) struct ScanArgs {
    pub(crate) target: PathBuf,
    pub(crate) mode: Option<ScanModeArg>,
    pub(crate) tasks: Vec<String>,
    pub(crate) triage: Option<bool>,
    pub(crate) json: bool,
    pub(crate) ci: bool,
    pub(crate) budget: Option<String>,
    pub(crate) since: Option<String>,
    pub(crate) include_worktree: bool,
}

fn apply_pre_scan_policy(
    workspace: &WorkspaceTarget,
    config: &kuzushi_core::V2Config,
    args: &ScanArgs,
) -> Result<()> {
    apply_scan_since_scope(
        workspace,
        args.since.as_deref(),
        args.include_worktree,
        args.json,
        args.ci,
    )?;
    apply_scan_budget_caps(
        workspace,
        args.budget.as_deref(),
        config.operator.spend_hard_ceiling_usd,
        args.json,
        args.ci,
    )
}


fn build_sast_scan_input(
    workspace: &WorkspaceTarget,
    registry: &ModuleRegistry,
    mode: Option<ScanModeArg>,
    tasks: &[String],
    triage: Option<bool>,
) -> Result<serde_json::Value> {
    let option_store = scan_option_store(workspace)?;
    registry.prepare_tool_input(
        "sast:scan",
        scan_tool_input(mode, tasks, triage),
        Some(&option_store),
    )
}

fn run_and_emit_sast_scan(
    registry: &ModuleRegistry,
    input: serde_json::Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&PiAgentCoreRuntime>,
    workspace: &WorkspaceTarget,
    args: &ScanArgs,
    config: &kuzushi_core::V2Config,
) -> Result<()> {
    let started = std::time::Instant::now();
    emit_scan_ci_start(args.ci, started, &args.target, config, &args.tasks);
    let result = registry.execute_tool_with_runtime(
        "sast:scan",
        input,
        ctx,
        runtime.map(|runtime| runtime as &dyn AgentRuntime),
    );
    let elapsed = started.elapsed();
    let result = scan_result_or_report_ci_error(result, args.ci, started, elapsed)?;
    emit_scan_output(workspace, &result, args.json, args.ci, started, elapsed)
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

async fn scan_apk_command(apk: PathBuf, json: bool, ci: bool) -> Result<()> {
    let workspace_dir = apk
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let workspace = WorkspaceTarget::new(&workspace_dir)?;
    let config = load_config_for_target(Some(workspace.root()))?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let registry = ModuleRegistry::with_v2_builtins();
    let input = registry.prepare_tool_input(
        "android-apk:scan",
        apk_scan_tool_input(&apk, &workspace_dir),
        None,
    )?;
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
    };
    let started = std::time::Instant::now();
    emit_scan_ci_start(ci, started, &apk, &config, &Vec::new());
    let result =
        registry.execute_tool_with_runtime("android-apk:scan", input, &ctx, None);
    let elapsed = started.elapsed();
    let result = scan_result_or_report_ci_error(result, ci, started, elapsed)?;
    emit_scan_output(&workspace, &result, json, ci, started, elapsed)
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
