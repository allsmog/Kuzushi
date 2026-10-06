use super::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::path::PathBuf;

const MAX_INVENTORY_BYTES: usize = 32 * 1024 * 1024;
const MAX_REVISION_BYTES: usize = 256 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InventoryCache {
    schema_version: u32,
    source: ScanScopeSource,
    inventory_hash: String,
}

pub(super) fn cached_inventory_hash(
    workspace: &WorkspaceTarget,
    source: &ScanScopeSource,
) -> Result<Option<String>> {
    let relative = cache_path(source)?;
    let Some(text) =
        read_optional_workspace_text(workspace.root(), &workspace.root().join(relative), 2048)?
    else {
        return Ok(None);
    };
    let cache: InventoryCache = serde_json::from_str(&text)?;
    anyhow::ensure!(
        cache.schema_version == 1 && cache.source == *source,
        "saved scope inventory has a different source identity"
    );
    Ok(Some(cache.inventory_hash))
}

pub(super) fn cache_inventory_hash(
    workspace: &WorkspaceTarget,
    source: &ScanScopeSource,
    hash: &str,
) -> Result<()> {
    let cache = InventoryCache {
        schema_version: 1,
        source: source.clone(),
        inventory_hash: hash.into(),
    };
    write_workspace_state_file(
        workspace.root(),
        cache_path(source)?,
        &serde_json::to_vec(&cache)?,
    )?;
    Ok(())
}

fn cache_path(source: &ScanScopeSource) -> Result<PathBuf> {
    crate::identity::Blake3Hash::new(source.snapshot_hash.clone())?;
    Ok(PathBuf::from(".kuzushi/v3/scan-scopes/snapshots")
        .join(format!("{}.json", source.snapshot_hash)))
}

pub(super) fn save_inventory(
    workspace: &WorkspaceTarget,
    inventory: &RepositoryInventory,
) -> Result<String> {
    save_object(workspace, "inventories", inventory, MAX_INVENTORY_BYTES)
}

pub(super) fn load_inventory(
    workspace: &WorkspaceTarget,
    hash: &str,
) -> Result<RepositoryInventory> {
    load_object(workspace, "inventories", hash, MAX_INVENTORY_BYTES)
}

pub(super) fn save_revision(
    workspace: &WorkspaceTarget,
    record: ScanScopeRevision,
    coverage: ScanScopeCoverage,
) -> Result<ScanScopeReview> {
    let hash = save_object(workspace, "revisions", &record, MAX_REVISION_BYTES)?;
    let reference = ScanScopeProposalRef {
        proposal_id: record.proposal_id.clone(),
        revision: record.revision,
        record_hash: hash,
    };
    let inventory = load_inventory(workspace, &record.inventory_hash)?;
    let identity_omissions = identity_coverage::omissions(workspace, &record, &inventory)?;
    Ok(ScanScopeReview {
        reference,
        record,
        coverage,
        identity_omissions,
    })
}

pub(super) fn load_record(
    workspace: &WorkspaceTarget,
    reference: &ScanScopeProposalRef,
) -> Result<ScanScopeRevision> {
    let record: ScanScopeRevision = load_object(
        workspace,
        "revisions",
        &reference.record_hash,
        MAX_REVISION_BYTES,
    )?;
    anyhow::ensure!(
        record.schema_version == 1,
        "unsupported scope revision schema"
    );
    anyhow::ensure!(
        record.proposal_id == reference.proposal_id && record.revision == reference.revision,
        "scope reference does not identify the saved revision"
    );
    validate_previous(&record)?;
    Ok(record)
}

fn validate_previous(record: &ScanScopeRevision) -> Result<()> {
    let Some(previous) = &record.previous else {
        anyhow::ensure!(
            record.revision == 1,
            "scope revision has no previous reference"
        );
        return Ok(());
    };
    crate::identity::Blake3Hash::new(previous.record_hash.clone())?;
    anyhow::ensure!(
        previous.proposal_id == record.proposal_id
            && previous.revision.checked_add(1) == Some(record.revision),
        "scope revision lineage is inconsistent"
    );
    Ok(())
}

pub(super) fn load_revision(
    workspace: &WorkspaceTarget,
    reference: &ScanScopeProposalRef,
) -> Result<ScanScopeReview> {
    let record = load_record(workspace, reference)?;
    let inventory = load_inventory(workspace, &record.inventory_hash)?;
    let coverage = record.draft.evaluate(&inventory)?;
    let identity_omissions = identity_coverage::omissions(workspace, &record, &inventory)?;
    validate_acceptance(&record, &coverage, &identity_omissions)?;
    Ok(ScanScopeReview {
        reference: reference.clone(),
        record,
        coverage,
        identity_omissions,
    })
}

fn validate_acceptance(
    record: &ScanScopeRevision,
    coverage: &ScanScopeCoverage,
    omissions: &ScopeFilePreview,
) -> Result<()> {
    if let Some(approval) = &record.acceptance {
        coverage.ensure_acceptable(approval)?;
        identity_coverage::require_bound_members(omissions)?;
    }
    Ok(())
}

fn save_object(
    workspace: &WorkspaceTarget,
    kind: &str,
    value: &impl Serialize,
    limit: usize,
) -> Result<String> {
    let body = serde_json::to_vec(value)?;
    anyhow::ensure!(
        body.len() <= limit,
        "scan scope {kind} exceeds its {limit}-byte storage limit"
    );
    let hash = blake3::hash(&body).to_hex().to_string();
    let relative = object_path(kind, &hash)?;
    let existing =
        read_optional_workspace_text(workspace.root(), &workspace.root().join(&relative), limit)?;
    ensure_same_or_write(workspace, &relative, &body, existing)?;
    Ok(hash)
}

fn ensure_same_or_write(
    workspace: &WorkspaceTarget,
    relative: &std::path::Path,
    body: &[u8],
    existing: Option<String>,
) -> Result<()> {
    if let Some(existing) = existing {
        anyhow::ensure!(
            existing.as_bytes() == body,
            "saved scan scope object has changed"
        );
        return Ok(());
    }
    write_workspace_state_file(workspace.root(), relative, body)?;
    Ok(())
}

fn load_object<T: DeserializeOwned>(
    workspace: &WorkspaceTarget,
    kind: &str,
    hash: &str,
    limit: usize,
) -> Result<T> {
    let relative = object_path(kind, hash)?;
    let text =
        read_optional_workspace_text(workspace.root(), &workspace.root().join(relative), limit)?
            .context("saved scan scope object is missing")?;
    anyhow::ensure!(
        blake3::hash(text.as_bytes()).to_hex().as_str() == hash,
        "saved scan scope object digest does not match"
    );
    serde_json::from_str(&text).context("saved scan scope object is malformed")
}

fn object_path(kind: &str, hash: &str) -> Result<PathBuf> {
    crate::identity::Blake3Hash::new(hash.to_owned())?;
    Ok(PathBuf::from(".kuzushi/v3/scan-scopes")
        .join(kind)
        .join(format!("{hash}.json")))
}
