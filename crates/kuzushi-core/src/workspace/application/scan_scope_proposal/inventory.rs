use super::*;
use crate::workspace::source_snapshot::SourceSnapshot;

pub(crate) fn load_or_build(
    ctx: &ToolExecutionContext<'_>,
) -> Result<(ScanScopeSource, RepositoryInventory, String)> {
    let workspace = ctx
        .workspace
        .context("scope inventory requires an active target")?;
    anyhow::ensure!(!ctx.is_cancelled(), "scope inventory was canceled");
    workspace.ensure_state_dir()?;
    let _guard = crate::file_lock::ExclusiveFileLock::acquire_cancellable(
        &workspace.state_dir().join(".scope-inventory.lock"),
        &|| ctx.is_cancelled(),
    )?;
    let git = target_git_metadata(workspace.root());
    let snapshot = SourceSnapshot::capture(ctx, "pack:scopes", workspace.root())?;
    let (snapshot_hash, tree_hash) = snapshot.hashes();
    let enumeration = membership::capture(ctx)?;
    let source = ScanScopeSource {
        snapshot_hash: snapshot_hash.into(),
        tree_hash: tree_hash.into(),
        git_revision: git.as_ref().map(|git| git.sha.clone()),
        dirty: git.map(|git| git.dirty),
        enumeration_hash: Some(enumeration.hash.clone()),
    };
    let (inventory, cached_hash) =
        cached_or_collect(ctx, workspace, &source, enumeration.enumeration)?;
    membership::ensure_collected(&enumeration.metadata_hash, &inventory)?;
    snapshot.ensure_current(ctx, "pack:scopes", workspace.root())?;
    ensure_git_current(workspace, &source)?;
    membership::ensure_current(ctx, &source)?;
    anyhow::ensure!(!ctx.is_cancelled(), "scope inventory was canceled");
    let hash = save_collected_inventory(workspace, &source, &inventory, cached_hash)?;
    Ok((source, inventory, hash))
}

fn cached_or_collect(
    ctx: &ToolExecutionContext<'_>,
    workspace: &WorkspaceTarget,
    source: &ScanScopeSource,
    enumeration: crate::workspace::GitIndexEnumeration,
) -> Result<(RepositoryInventory, Option<String>)> {
    if let Some(hash) = persistence::cached_inventory_hash(workspace, source)? {
        return Ok((persistence::load_inventory(workspace, &hash)?, Some(hash)));
    }
    let mut heartbeat = crate::progress::HeartbeatGate::new(std::time::Duration::from_secs(1));
    let inventory = crate::workspace::inventory::build_repository_inventory_from_enumeration(
        workspace.root(),
        &mut |entries| {
            if heartbeat.ready() {
                emit_inventory_progress(ctx, entries);
            }
        },
        &|| ctx.is_cancelled(),
        enumeration,
        crate::workspace::inventory::MAX_REPOSITORY_INSPECTED_BYTES,
    )?;
    anyhow::ensure!(!ctx.is_cancelled(), "scope inventory was canceled");
    Ok((inventory, None))
}

fn save_collected_inventory(
    workspace: &WorkspaceTarget,
    source: &ScanScopeSource,
    inventory: &RepositoryInventory,
    cached_hash: Option<String>,
) -> Result<String> {
    if let Some(hash) = cached_hash {
        return Ok(hash);
    }
    let hash = persistence::save_inventory(workspace, inventory)?;
    persistence::cache_inventory_hash(workspace, source, &hash)?;
    Ok(hash)
}

pub(super) fn ensure_current(
    ctx: &ToolExecutionContext<'_>,
    source: &ScanScopeSource,
) -> Result<()> {
    let workspace = ctx
        .workspace
        .context("scope review requires an active target")?;
    anyhow::ensure!(!ctx.is_cancelled(), "scope review was canceled");
    let mut heartbeat = crate::progress::HeartbeatGate::new(std::time::Duration::from_secs(1));
    let current = crate::incremental_index::current_workspace_tree_hash_cancellable(
        workspace.root(),
        &mut |files| {
            if heartbeat.ready() {
                emit_source_progress(ctx, files);
            }
        },
        &|| ctx.is_cancelled(),
    )?;
    anyhow::ensure!(
        current == source.tree_hash,
        "source content changed; generate a new scope draft before acceptance"
    );
    anyhow::ensure!(!ctx.is_cancelled(), "scope review was canceled");
    ensure_git_current(workspace, source)?;
    membership::ensure_current(ctx, source)
}

fn ensure_git_current(workspace: &WorkspaceTarget, source: &ScanScopeSource) -> Result<()> {
    let git = target_git_metadata(workspace.root());
    let revision = git.as_ref().map(|git| git.sha.clone());
    anyhow::ensure!(
        revision == source.git_revision,
        "Git revision changed; generate a new scope draft before acceptance"
    );
    Ok(())
}

fn emit_source_progress(ctx: &ToolExecutionContext<'_>, files: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                "pack:scopes",
                format!("source verification · {files} files hashed"),
            )
            .emit();
    }
}

fn emit_inventory_progress(ctx: &ToolExecutionContext<'_>, entries: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                "pack:scopes",
                format!("repository inventory · {entries} entries examined"),
            )
            .emit();
    }
}
