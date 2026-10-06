use super::*;
use std::collections::BTreeSet;

pub fn resolve_accepted_scan_scope_selection(
    ctx: &ToolExecutionContext<'_>,
    reference: &ScanScopeRef,
) -> Result<AcceptedScanScopeSelection> {
    let review = load_accepted_scan_scope_proposal(ctx, &reference.proposal)?;
    let scope = review
        .record
        .draft
        .scopes
        .iter()
        .chain(review.record.draft.shared_scope.iter())
        .find(|scope| scope.id == reference.scope_id)
        .context("selected scope is not in the accepted revision")?;
    let members = review
        .coverage
        .discovery_members
        .get(&scope.id)
        .context("selected scope is context only or has no discovery membership")?;
    anyhow::ensure!(members.total > 0, "selected scope has no discovery files");
    let workspace = ctx
        .workspace
        .context("scope membership requires an active target")?;
    let inventory = persistence::load_inventory(workspace, &review.record.inventory_hash)?;
    let files = discovery_files(&review.record.draft, scope, &inventory)?;
    anyhow::ensure!(
        files.len() == members.total,
        "scope membership count changed while reading its immutable inventory"
    );
    let context_files = inherited_context_files(&review.record.draft, scope, &inventory)?;
    Ok(AcceptedScanScopeSelection {
        reference: reference.clone(),
        name: scope.name.clone(),
        source: review.record.source,
        discovery_files: files,
        context_files,
    })
}

fn discovery_files(
    draft: &ScanScopeDraft,
    scope: &ProposedScanScope,
    inventory: &RepositoryInventory,
) -> Result<Vec<String>> {
    Ok(inventory
        .inspection
        .as_ref()
        .context("scope inventory has no membership")?
        .files
        .iter()
        .filter(|file| includes_file(draft, scope, file))
        .cloned()
        .collect())
}

fn includes_file(draft: &ScanScopeDraft, scope: &ProposedScanScope, file: &str) -> bool {
    scope.paths.iter().any(|path| covers(path, file))
        && !draft
            .exclusions
            .iter()
            .any(|excluded| covers(&excluded.path, file))
}

fn covers(path: &str, file: &str) -> bool {
    path == "."
        || path == file
        || file
            .strip_prefix(path)
            .is_some_and(|tail| tail.starts_with('/'))
}

fn inherited_context_files(
    draft: &ScanScopeDraft,
    scope: &ProposedScanScope,
    inventory: &RepositoryInventory,
) -> Result<Vec<String>> {
    let shared = draft
        .shared_scope
        .as_ref()
        .filter(|_| !draft.shared_discovery);
    let inherited = draft
        .scopes
        .iter()
        .chain(draft.shared_scope.iter())
        .filter(|candidate| {
            scope.shared_dependencies.contains(&candidate.id)
                || shared.is_some_and(|shared| shared.id == candidate.id)
        });
    let files = &inventory
        .inspection
        .as_ref()
        .context("scope inventory has no membership")?
        .files;
    let mut selected = BTreeSet::new();
    for inherited_scope in inherited {
        selected.extend(
            files
                .iter()
                .filter(|file| includes_file(draft, inherited_scope, file))
                .cloned(),
        );
    }
    Ok(selected.into_iter().collect())
}

#[cfg(test)]
mod tests;
