use crate::identity::{hash_parts, Blake3Hash};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
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

pub const MAX_CONTENT_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

impl ContentStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        ensure_content_directory(&root)?;
        ensure_content_directory(&root.join("blake3"))?;
        Ok(Self { root })
    }

    pub fn put_bytes(&self, kind: ObjectKind, bytes: &[u8]) -> Result<ObjectRef> {
        let hash = object_hash(kind, bytes);
        let object_ref = object_ref(kind, hash.clone(), bytes.len());
        let path = self.object_path(&hash);
        if existing_object_is_file(&path)? {
            self.get_object(&object_ref)?;
            return Ok(object_ref);
        }
        let parent = path
            .parent()
            .context("content-addressed object path has no parent")?;
        self.ensure_object_parent(parent)?;
        install_object(parent, &path, bytes)?;
        self.get_object(&object_ref)?;
        Ok(object_ref)
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
        self.validate_object_parent(&path)?;
        read_content_object(&path)
    }

    pub fn get_object(&self, object_ref: &ObjectRef) -> Result<Vec<u8>> {
        if object_ref.size_bytes > MAX_CONTENT_OBJECT_BYTES {
            anyhow::bail!(
                "CAS object {} declares {} bytes above the {}-byte read limit",
                object_ref.hash,
                object_ref.size_bytes,
                MAX_CONTENT_OBJECT_BYTES
            );
        }
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
        let path = self.object_path(hash);
        self.validate_object_parent(&path).is_ok()
            && existing_object_is_file(&path).unwrap_or(false)
    }

    pub fn object_path(&self, hash: &Blake3Hash) -> PathBuf {
        let hex = hash.as_str();
        self.root
            .join("blake3")
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(hex)
    }

    fn ensure_object_parent(&self, parent: &Path) -> Result<()> {
        let relative = parent
            .strip_prefix(&self.root)
            .context("content-addressed object path escaped store root")?;
        let mut current = self.root.clone();
        ensure_content_directory(&current)?;
        for component in relative.components() {
            current.push(component.as_os_str());
            ensure_content_directory(&current)?;
        }
        Ok(())
    }

    fn validate_object_parent(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .context("content-addressed object path has no parent")?;
        let relative = parent
            .strip_prefix(&self.root)
            .context("content-addressed object path escaped store root")?;
        let mut current = self.root.clone();
        validate_content_directory(&current)?;
        for component in relative.components() {
            current.push(component.as_os_str());
            validate_content_directory(&current)?;
        }
        Ok(())
    }
}

fn read_content_object(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("Could not inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!(
            "Content-addressed object must be a regular non-symlink file: {}",
            path.display()
        );
    }
    if metadata.len() > MAX_CONTENT_OBJECT_BYTES {
        anyhow::bail!(
            "Content-addressed object {} exceeds the {}-byte read limit",
            path.display(),
            MAX_CONTENT_OBJECT_BYTES
        );
    }
    let file = crate::bounded_file::open_regular_file(path)
        .with_context(|| format!("Could not open {}", path.display()))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_CONTENT_OBJECT_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("Could not read {}", path.display()))?;
    if bytes.len() as u64 > MAX_CONTENT_OBJECT_BYTES {
        anyhow::bail!("Content-addressed object grew beyond its read limit");
    }
    Ok(bytes)
}

fn existing_object_is_file(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!(
                "Content-addressed object must not be a symlink: {}",
                path.display()
            )
        }
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => anyhow::bail!("Content-addressed object is not a file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn ensure_content_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!(
                "Content store directory must not be a symlink: {}",
                path.display()
            )
        }
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => anyhow::bail!("Content store path is not a directory: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_content_directory(path)
        }
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn validate_content_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("Could not inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "Content store directory must be a real directory: {}",
            path.display()
        );
    }
    Ok(())
}

fn create_content_directory(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|parent| *parent != path) {
        ensure_content_directory(parent)?;
    }
    match fs::create_dir(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                sync_content_directory(parent);
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure_content_directory(path)
        }
        Err(error) => Err(error)
            .with_context(|| format!("Could not create content store under {}", path.display())),
    }
}

fn install_object(parent: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    let temp_path = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    write_synced_object(&temp_path, bytes)?;
    match fs::rename(&temp_path, path) {
        Ok(()) => sync_content_directory(parent),
        Err(_) if existing_object_is_file(path)? => {
            let _ = fs::remove_file(&temp_path);
        }
        Err(error) => {
            let _ = fs::remove_file(&temp_path);
            return Err(error).with_context(|| format!("Could not move {}", path.display()));
        }
    }
    Ok(())
}

fn write_synced_object(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = create_content_object(path)
        .with_context(|| format!("Could not create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("Could not write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("Could not fsync {}", path.display()))
}

#[cfg(unix)]
fn create_content_object(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn create_content_object(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
}

fn sync_content_directory(path: &Path) {
    if let Ok(directory) = fs::File::open(path) {
        let _ = directory.sync_all();
    }
}

fn object_ref(kind: ObjectKind, hash: Blake3Hash, size: usize) -> ObjectRef {
    ObjectRef {
        kind,
        hash,
        size_bytes: size as u64,
    }
}

pub fn object_hash(kind: ObjectKind, bytes: &[u8]) -> Blake3Hash {
    hash_parts("object", &[kind.as_str().as_bytes(), bytes])
}

fn sorted_tree_entries(mut entries: Vec<TreeEntry>) -> Vec<TreeEntry> {
    entries.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.hash.cmp(&right.hash))
    });
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

    #[cfg(unix)]
    #[test]
    fn reads_reject_object_symlinks_without_exposing_outside_bytes() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::open(tmp.path()).unwrap();
        let object_ref = store.put_blob(b"original").unwrap();
        let path = store.object_path(&object_ref.hash);
        fs::remove_file(&path).unwrap();
        let outside = tmp.path().join("outside-secret");
        fs::write(&outside, "secret").unwrap();
        symlink(&outside, &path).unwrap();

        assert!(store.get(&object_ref.hash).is_err());
        assert!(store.get_object(&object_ref).is_err());
    }

    #[test]
    fn reads_reject_oversized_sparse_object_before_allocation() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::open(tmp.path()).unwrap();
        let object_ref = store.put_blob(b"small").unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(store.object_path(&object_ref.hash))
            .unwrap()
            .set_len(MAX_CONTENT_OBJECT_BYTES + 1)
            .unwrap();

        assert!(store.get(&object_ref.hash).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_store_root_and_hash_shards() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let linked_root = tmp.path().join("linked-objects");
        symlink(outside.path(), &linked_root).unwrap();
        assert!(ContentStore::open(&linked_root).is_err());

        let root = tmp.path().join("objects");
        let store = ContentStore::open(&root).unwrap();
        let hash = object_hash(ObjectKind::Blob, b"secret");
        symlink(
            outside.path(),
            root.join("blake3").join(&hash.as_str()[0..2]),
        )
        .unwrap();
        assert!(store.put_blob(b"secret").is_err());
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
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
        let second = store
            .put_snapshot(&snapshot(tree.hash, vec![rule_b]))
            .unwrap();

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
