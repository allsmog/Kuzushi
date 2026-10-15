use super::*;
use crate::workspace::inventory::{
    build_repository_inventory_from_enumeration, MAX_REPOSITORY_ENTRIES,
};
use crate::workspace::{git_tracked_relative_paths, GitIndexEnumeration};

pub(super) struct ScopeEnumeration {
    pub hash: String,
    pub metadata_hash: String,
    pub enumeration: GitIndexEnumeration,
}

pub(super) fn capture(ctx: &ToolExecutionContext<'_>) -> Result<ScopeEnumeration> {
    let workspace = ctx
        .workspace
        .context("scope membership requires an active target")?;
    anyhow::ensure!(
        !ctx.is_cancelled(),
        "scope membership inspection was canceled"
    );
    let enumeration =
        git_tracked_relative_paths(workspace.root(), MAX_REPOSITORY_ENTRIES, &|| {
            ctx.is_cancelled()
        })?;
    let index_hash = match &enumeration {
        GitIndexEnumeration::Tracked { fingerprint, .. } => fingerprint.clone(),
        GitIndexEnumeration::Unavailable => "filesystem".into(),
        GitIndexEnumeration::Canceled => anyhow::bail!("scope membership inspection was canceled"),
    };
    let metadata_hash = capture_metadata_hash(ctx, workspace, enumeration.clone())?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"scope-enumeration-v1\0");
    hash.update(index_hash.as_bytes());
    hash.update(metadata_hash.as_bytes());
    Ok(ScopeEnumeration {
        hash: hash.finalize().to_hex().to_string(),
        metadata_hash,
        enumeration,
    })
}

fn capture_metadata_hash(
    ctx: &ToolExecutionContext<'_>,
    workspace: &WorkspaceTarget,
    enumeration: GitIndexEnumeration,
) -> Result<String> {
    let mut heartbeat = crate::progress::HeartbeatGate::new(std::time::Duration::from_secs(1));
    let inventory = build_repository_inventory_from_enumeration(
        workspace.root(),
        &mut |entries| {
            if heartbeat.ready() {
                emit_membership_progress(ctx, entries);
            }
        },
        &|| ctx.is_cancelled(),
        enumeration,
        0,
    )?;
    anyhow::ensure!(
        !ctx.is_cancelled(),
        "scope membership inspection was canceled"
    );
    inventory_hash(&inventory)
}

fn emit_membership_progress(ctx: &ToolExecutionContext<'_>, entries: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                "pack:scopes",
                format!("inventory membership · {entries} entries checked"),
            )
            .emit();
    }
}

fn inventory_hash(inventory: &RepositoryInventory) -> Result<String> {
    let inspection = inventory
        .inspection
        .as_ref()
        .context("scope inventory has no inspection receipt")?;
    let value = serde_json::to_vec(&(
        &inspection.enumeration,
        inspection.entries,
        &inspection.files,
        &inspection.omitted_paths,
    ))?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"inventory-membership-metadata-v1\0");
    hash.update(&value);
    Ok(hash.finalize().to_hex().to_string())
}

pub(super) fn ensure_current(
    ctx: &ToolExecutionContext<'_>,
    source: &ScanScopeSource,
) -> Result<()> {
    let expected = source.enumeration_hash.as_ref().context("scope inventory predates membership binding; build and accept a new scope draft before new work")?;
    anyhow::ensure!(capture(ctx)?.hash == *expected,
        "repository inventory membership changed; build and accept a new scope draft before new work");
    Ok(())
}

pub(super) fn ensure_collected(expected: &str, inventory: &RepositoryInventory) -> Result<()> {
    anyhow::ensure!(
        expected == inventory_hash(inventory)?,
        "saved inventory membership does not match its captured enumeration; inspect the inventory cache before creating a new draft"
    );
    Ok(())
}
