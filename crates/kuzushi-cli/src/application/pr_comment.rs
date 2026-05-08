use anyhow::Result;
use kuzushi_core::{
    build_pr_comment, FindingListFilter, FindingStore, PrCommentInput, WorkspaceTarget,
};
use std::path::PathBuf;

pub(crate) fn pr_comment_command(
    target: Option<PathBuf>,
    repo: Option<String>,
    run_url: Option<String>,
    top_n: usize,
    changed_files: Vec<String>,
    run_id: Option<String>,
    model: Option<String>,
    git_sha: Option<String>,
) -> Result<()> {
    let target = target.unwrap_or_else(|| PathBuf::from("."));
    let workspace = WorkspaceTarget::new(target)?;
    let input = load_pr_comment_input(
        &workspace,
        repo,
        run_url,
        top_n,
        changed_files,
        run_id,
        model,
        git_sha,
    )?;
    println!("{}", build_pr_comment(&input));
    Ok(())
}

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
