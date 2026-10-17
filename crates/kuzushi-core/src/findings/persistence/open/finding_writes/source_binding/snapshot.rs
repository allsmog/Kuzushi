//! Authenticate the original workspace snapshot before source capture.
use super::*;
use crate::content_store::TargetSnapshot;

pub(crate) struct FindingSourceSnapshot {
    pub(super) root: PathBuf,
    pub(super) snapshot: SnapshotWrite,
    pub(super) tree: ReviewSourceTree,
}

impl FindingStore {
    pub(crate) fn require_workspace_target(&self, target: &Path) -> Result<PathBuf> {
        let root = self
            .v3_workspace_root()
            .context("Active findings ledger requires workspace storage")?
            .canonicalize()?;
        anyhow::ensure!(root == target.canonicalize()?,
            "Active findings ledger does not belong to the selected repository; reopen the target before model work");
        Ok(root)
    }

    pub(crate) fn prepare_finding_source_snapshot(
        &self,
        target: &Path,
        snapshot_hash: &str,
        tree_hash: &str,
    ) -> Result<FindingSourceSnapshot> {
        let root = self.require_workspace_target(target)?;
        let workspace = WorkspaceTarget::new(&root)?;
        let store = ContentStore::open(workspace.objects_dir())?;
        let snapshot = load_snapshot(&store, &root, snapshot_hash, tree_hash)?;
        let tree = ReviewSourceTree::load(&workspace, tree_hash)
            .context("Source capture is unavailable for this snapshot; no model request started")?;
        Ok(FindingSourceSnapshot {
            root,
            snapshot,
            tree,
        })
    }
}

pub(super) fn load_snapshot(
    store: &ContentStore,
    root: &Path,
    raw: &str,
    tree: &str,
) -> Result<SnapshotWrite> {
    let hash = Blake3Hash::new(raw.into())?;
    let bytes = store
        .get_bounded(&hash, ObjectKind::Snapshot, 64 * 1024)?
        .context("Observation snapshot is unavailable or exceeds 64 KiB")?;
    let snapshot: TargetSnapshot = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        snapshot.tree_hash.as_str() == tree,
        "Observation snapshot tree does not match"
    );
    anyhow::ensure!(
        snapshot.workspace_root_fingerprint
            == crate::incremental_index::workspace_root_fingerprint(root),
        "Observation snapshot belongs to a different workspace"
    );
    Ok(SnapshotWrite {
        snapshot_hash: raw.into(),
        tree_hash: tree.into(),
        workspace_root_fingerprint: snapshot.workspace_root_fingerprint,
        git_commit: snapshot.git_commit,
        git_branch: snapshot.git_branch,
        dirty_hash: snapshot.dirty_hash.map(|hash| hash.as_str().to_owned()),
        index_hash: snapshot.index_hash.map(|hash| hash.as_str().to_owned()),
        config_hash: snapshot.config_hash.map(|hash| hash.as_str().to_owned()),
        actor: "finding-store".into(),
    })
}
