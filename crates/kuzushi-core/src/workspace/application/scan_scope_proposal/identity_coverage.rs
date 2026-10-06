use super::*;
use crate::content_store::{object_hash, ContentStore, ObjectKind, TargetSnapshot, TreeObject};
use crate::identity::Blake3Hash;
use std::collections::BTreeSet;

pub(super) fn omissions(
    workspace: &WorkspaceTarget,
    record: &ScanScopeRevision,
    inventory: &RepositoryInventory,
) -> Result<ScopeFilePreview> {
    let store = ContentStore::open(workspace.objects_dir())?;
    let snapshot: TargetSnapshot =
        read_verified(&store, ObjectKind::Snapshot, &record.source.snapshot_hash)?;
    anyhow::ensure!(
        snapshot.tree_hash.as_str() == record.source.tree_hash,
        "scope source snapshot and content tree disagree"
    );
    anyhow::ensure!(
        snapshot.git_commit == record.source.git_revision,
        "scope source snapshot and Git revision disagree"
    );
    anyhow::ensure!(
        snapshot.workspace_root_fingerprint
            == crate::incremental_index::workspace_root_fingerprint(workspace.root()),
        "scope source belongs to a different target"
    );
    let tree: TreeObject = read_verified(&store, ObjectKind::Tree, &record.source.tree_hash)?;
    let paths = tree
        .entries
        .into_iter()
        .map(|entry| entry.name)
        .collect::<BTreeSet<_>>();
    record.draft.identity_omissions(inventory, &paths)
}

fn read_verified<T: serde::de::DeserializeOwned>(
    store: &ContentStore,
    kind: ObjectKind,
    expected: &str,
) -> Result<T> {
    let hash = Blake3Hash::new(expected.to_owned())?;
    let bytes = store.get(&hash)?;
    anyhow::ensure!(
        object_hash(kind, &bytes) == hash,
        "scope content identity failed its integrity check"
    );
    serde_json::from_slice(&bytes).context("scope content identity is malformed")
}

pub(super) fn require_bound_members(omissions: &ScopeFilePreview) -> Result<()> {
    anyhow::ensure!(omissions.total == 0,
        "{} included files are outside content identity coverage; explicitly exclude them before accepting scopes: {:?}",
        omissions.total, omissions.files.iter().take(8).collect::<Vec<_>>());
    Ok(())
}
