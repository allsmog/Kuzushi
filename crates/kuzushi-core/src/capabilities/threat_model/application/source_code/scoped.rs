use super::*;
use crate::workspace::AcceptedScanScopeSelection;
use std::collections::BTreeSet;

pub(crate) fn collect_scoped_source(
    input: &BuildInput,
    scope: &AcceptedScanScopeSelection,
    ctx: &ToolExecutionContext<'_>,
) -> Result<CodeSource> {
    anyhow::ensure!(
        input.max_source_bytes >= 1024,
        "File-group context requires maxSourceBytes >= 1024"
    );
    ensure_not_cancelled(ctx)?;
    let tree_hash = current_tree_hash(input.workspace_root())?;
    let selected = scoped_selection(input, scope);
    let mut report = new_report(input, tree_hash, &selected);
    report.policy = "accepted-group-source-code-v1";
    collect_selected_files(input, &selected.files, &mut report, ctx)?;
    authenticate_tree(
        Some(&report.tree_hash),
        &current_tree_hash(input.workspace_root())?,
    )?;
    finish_report(report, input.max_source_bytes)
}

fn scoped_selection(input: &BuildInput, scope: &AcceptedScanScopeSelection) -> model::Selection {
    let paths = scope
        .discovery_files
        .iter()
        .chain(&scope.context_files)
        .collect::<BTreeSet<_>>();
    let files = paths
        .iter()
        .take(input.context_limit.min(2_000))
        .map(|path| candidate(path))
        .collect();
    model::Selection {
        scope_path: format!("accepted-group:{}", scope.reference.scope_id),
        eligible: paths.len(),
        files,
    }
}

fn candidate(path: &str) -> Candidate {
    Candidate {
        path: path.into(),
        citation_path: path.into(),
        language: crate::workspace::inventory::language_for_path(Path::new(path))
            .unwrap_or("Text")
            .into(),
        anchors: Vec::new(),
    }
}
