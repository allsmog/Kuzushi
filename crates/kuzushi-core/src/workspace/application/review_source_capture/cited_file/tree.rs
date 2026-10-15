use super::*;
use crate::content_store::TreeObject;
use std::collections::BTreeMap;

/// One authenticated membership lookup reused across every selected citation.
pub(crate) struct ReviewSourceTree {
    files: BTreeMap<String, Blake3Hash>,
}

impl ReviewSourceTree {
    pub(crate) fn load(workspace: &WorkspaceTarget, raw: &str) -> Result<Self> {
        let hash = Blake3Hash::new(raw.into())?;
        let store = ContentStore::open(workspace.objects_dir())?;
        let bytes = store
            .get_bounded(&hash, ObjectKind::Tree, 64 * 1024 * 1024)?
            .context("Review source tree is unavailable or exceeds the 64 MiB read limit")?;
        let tree: TreeObject = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(
            tree.entries.len() <= 100_000,
            "Review source tree exceeds the 100000-entry membership limit"
        );
        let count = tree.entries.len();
        let files: BTreeMap<_, _> = tree
            .entries
            .into_iter()
            .map(|entry| (entry.name, entry.hash))
            .collect();
        anyhow::ensure!(
            files.len() == count,
            "Review source tree has duplicate path memberships"
        );
        Ok(Self { files })
    }

    pub(crate) fn file_hash(&self, path: &str) -> Option<Blake3Hash> {
        self.files.get(path).cloned()
    }
}
