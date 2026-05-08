use super::prelude::*;
use super::*;

pub(crate) fn load_pr_comment_input(
    workspace: &WorkspaceTarget,
    repo: Option<String>,
    run_url: Option<String>,
    top_n: usize,
    changed_files: Vec<String>,
    run_id: Option<String>,
    model: Option<String>,
    git_sha: Option<String>,
) -> Result<PrCommentInput> {
    let store = FindingStore::open(workspace.findings_db_path())?;
    let report = store.list_findings_filtered(&FindingListFilter::default())?;
    Ok(PrCommentInput {
        repo_name: repo.or_else(|| {
            workspace
                .root()
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string)
        }),
        findings: report.findings,
        cost_usd: 0.0,
        elapsed: None,
        run_url,
        top_n: Some(top_n),
        kuzushi_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        model,
        git_sha,
        run_id,
        changed_files,
    })
}

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
