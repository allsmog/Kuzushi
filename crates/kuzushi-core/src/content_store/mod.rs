use crate::identity::{hash_parts, Blake3Hash};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectKind {
    Blob,
    Tree,
    Snapshot,
    ContextSnapshot,
    AttackSurfaceSnapshot,
    FindingObservationBatch,
    ProofSnapshot,
    ReportMarkdown,
    ReportSarif,
    PatchDiff,
    DiagnosticBundle,
}

impl ObjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
            Self::Snapshot => "snapshot",
            Self::ContextSnapshot => "context-snapshot",
            Self::AttackSurfaceSnapshot => "attack-surface-snapshot",
            Self::FindingObservationBatch => "finding-observation-batch",
            Self::ProofSnapshot => "proof-snapshot",
            Self::ReportMarkdown => "report-markdown",
            Self::ReportSarif => "report-sarif",
            Self::PatchDiff => "patch-diff",
            Self::DiagnosticBundle => "diagnostic-bundle",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectRef {
    pub kind: ObjectKind,
    pub hash: Blake3Hash,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TreeEntryKind {
    Blob,
    Tree,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeEntry {
    pub name: String,
    pub kind: TreeEntryKind,
    pub hash: Blake3Hash,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeObject {
    pub entries: Vec<TreeEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetSnapshot {
    pub tree_hash: Blake3Hash,
    pub workspace_root_fingerprint: String,
    pub git_commit: Option<String>,
    pub git_branch: Option<String>,
    pub dirty_hash: Option<Blake3Hash>,
    pub index_hash: Option<Blake3Hash>,
    pub config_hash: Option<Blake3Hash>,
    pub rule_set_hashes: Vec<Blake3Hash>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct ContentStore {
    root: PathBuf,
}

impl ContentStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("blake3")).with_context(|| {
            format!("Could not create content store under {}", root.display())
        })?;
        Ok(Self { root })
    }

    pub fn put_bytes(&self, kind: ObjectKind, bytes: &[u8]) -> Result<ObjectRef> {
        let hash = object_hash(kind, bytes);
        let path = self.object_path(&hash);
        if path.exists() {
            return Ok(ObjectRef {
                kind,
                hash,
                size_bytes: bytes.len() as u64,
            });
        }
        let parent = path
            .parent()
            .context("content-addressed object path has no parent")?;
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
        let temp_path = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
        fs::write(&temp_path, bytes)
            .with_context(|| format!("Could not write {}", temp_path.display()))?;
        match fs::rename(&temp_path, &path) {
            Ok(()) => {}
            Err(error) if path.exists() => {
                let _ = fs::remove_file(&temp_path);
                drop(error);
            }
            Err(error) => return Err(error).with_context(|| format!("Could not move {}", path.display())),
        }
        Ok(ObjectRef {
            kind,
            hash,
            size_bytes: bytes.len() as u64,
        })
    }

    pub fn put_blob(&self, bytes: &[u8]) -> Result<ObjectRef> {
        self.put_bytes(ObjectKind::Blob, bytes)
    }

    pub fn put_json<T: Serialize>(&self, kind: ObjectKind, value: &T) -> Result<ObjectRef> {
        let bytes = serde_json::to_vec(value).context("Could not serialize CAS JSON object")?;
        self.put_bytes(kind, &bytes)
    }

    pub fn put_tree(&self, entries: Vec<TreeEntry>) -> Result<ObjectRef> {
        let object = TreeObject {
            entries: sorted_tree_entries(entries),
        };
        self.put_json(ObjectKind::Tree, &object)
    }

    pub fn put_snapshot(&self, snapshot: &TargetSnapshot) -> Result<ObjectRef> {
        self.put_json(ObjectKind::Snapshot, snapshot)
    }

    pub fn get(&self, hash: &Blake3Hash) -> Result<Vec<u8>> {
        let path = self.object_path(hash);
        fs::read(&path).with_context(|| format!("Could not read {}", path.display()))
    }

    pub fn get_object(&self, object_ref: &ObjectRef) -> Result<Vec<u8>> {
        let bytes = self.get(&object_ref.hash)?;
        let actual_size = bytes.len() as u64;
        if actual_size != object_ref.size_bytes {
            anyhow::bail!(
                "CAS object {} size mismatch: expected {}, got {}",
                object_ref.hash,
                object_ref.size_bytes,
                actual_size
            );
        }
        let actual_hash = object_hash(object_ref.kind, &bytes);
        if actual_hash != object_ref.hash {
            anyhow::bail!(
                "CAS object {} failed {} integrity check",
                object_ref.hash,
                object_ref.kind.as_str()
            );
        }
        Ok(bytes)
    }

    pub fn contains(&self, hash: &Blake3Hash) -> bool {
        self.object_path(hash).is_file()
    }

    pub fn object_path(&self, hash: &Blake3Hash) -> PathBuf {
        let hex = hash.as_str();
        self.root
            .join("blake3")
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(hex)
    }
}

pub fn object_hash(kind: ObjectKind, bytes: &[u8]) -> Blake3Hash {
    hash_parts("object", &[kind.as_str().as_bytes(), bytes])
}

fn sorted_tree_entries(mut entries: Vec<TreeEntry>) -> Vec<TreeEntry> {
    entries.sort_by(|left, right| left.name.cmp(&right.name).then_with(|| left.hash.cmp(&right.hash)));
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_bytes_have_same_blob_hash_and_path() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::open(tmp.path()).unwrap();

        let first = store.put_bytes(ObjectKind::Blob, b"hello").unwrap();
        let second = store.put_bytes(ObjectKind::Blob, b"hello").unwrap();

        assert_eq!(first.hash, second.hash);
        assert_eq!(store.get(&first.hash).unwrap(), b"hello");
        assert!(store.object_path(&first.hash).is_file());
    }

    #[test]
    fn kind_is_part_of_object_hash() {
        let blob = object_hash(ObjectKind::Blob, b"same");
        let report = object_hash(ObjectKind::ReportMarkdown, b"same");

        assert_ne!(blob, report);
    }

    #[test]
    fn verified_read_rejects_mutated_object_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::open(tmp.path()).unwrap();
        let object_ref = store.put_blob(b"original").unwrap();
        fs::write(store.object_path(&object_ref.hash), b"mutated").unwrap();

        let error = store.get_object(&object_ref).unwrap_err();

        assert!(error.to_string().contains("size mismatch"));
    }

    #[test]
    fn tree_hash_is_stable_for_entry_order() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::open(tmp.path()).unwrap();
        let a = store.put_blob(b"a").unwrap();
        let b = store.put_blob(b"b").unwrap();
        let first = store
            .put_tree(vec![
                tree_entry("b.rs", b.hash.clone()),
                tree_entry("a.rs", a.hash.clone()),
            ])
            .unwrap();
        let second = store
            .put_tree(vec![tree_entry("a.rs", a.hash), tree_entry("b.rs", b.hash)])
            .unwrap();

        assert_eq!(first.hash, second.hash);
    }

    #[test]
    fn snapshot_hash_depends_on_tree_and_rule_sets() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::open(tmp.path()).unwrap();
        let tree = store.put_tree(Vec::new()).unwrap();
        let rule_a = object_hash(ObjectKind::Blob, b"rule-a");
        let rule_b = object_hash(ObjectKind::Blob, b"rule-b");
        let first = store
            .put_snapshot(&snapshot(tree.hash.clone(), vec![rule_a]))
            .unwrap();
        let second = store.put_snapshot(&snapshot(tree.hash, vec![rule_b])).unwrap();

        assert_ne!(first.hash, second.hash);
    }

    fn tree_entry(name: &str, hash: Blake3Hash) -> TreeEntry {
        TreeEntry {
            name: name.to_string(),
            kind: TreeEntryKind::Blob,
            hash,
            executable: false,
        }
    }

    fn snapshot(tree_hash: Blake3Hash, rule_set_hashes: Vec<Blake3Hash>) -> TargetSnapshot {
        TargetSnapshot {
            tree_hash,
            workspace_root_fingerprint: "workspace".to_string(),
            git_commit: Some("abc".to_string()),
            git_branch: Some("main".to_string()),
            dirty_hash: None,
            index_hash: None,
            config_hash: None,
            rule_set_hashes,
            created_at: "1".to_string(),
        }
    }
}
