use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::workspace::WorkspaceTarget;

pub const SUPPORTED_ATTACHMENT_MODULES: &[&str] =
    &["context", "threat-model", "carlini-threat-hunt", "x-ray"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AttachmentKind {
    Path,
    Url,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentRecord {
    pub id: String,
    pub module_id: String,
    pub kind: AttachmentKind,
    pub source: String,
    pub title: String,
    pub metadata_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_count: Option<u64>,
    pub status: String,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownArtifact {
    pub module_id: String,
    pub path: String,
    pub description: String,
    pub exists: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttachmentStoreFile {
    version: u8,
    attachments: Vec<AttachmentRecord>,
}

impl Default for AttachmentStoreFile {
    fn default() -> Self {
        Self {
            version: 1,
            attachments: Vec::new(),
        }
    }
}

pub fn is_supported_attachment_module(module_id: &str) -> bool {
    SUPPORTED_ATTACHMENT_MODULES.contains(&module_id)
}

pub fn attachment_store_path(workspace: &WorkspaceTarget) -> PathBuf {
    workspace.state_dir().join("attachments.json")
}

pub fn list_attachments(workspace: &WorkspaceTarget) -> Result<Vec<AttachmentRecord>> {
    let mut records = load_store(workspace)?.attachments;
    records.sort_by(|left, right| {
        left.module_id
            .cmp(&right.module_id)
            .then_with(|| left.source.cmp(&right.source))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(records)
}

pub fn attach_source(
    workspace: &WorkspaceTarget,
    module_id: &str,
    raw_source: &str,
) -> Result<AttachmentRecord> {
    ensure_supported_module(module_id)?;
    let raw_source = raw_source.trim();
    if raw_source.is_empty() {
        anyhow::bail!("attach requires a path or URL. Next: attach <path-or-url>");
    }

    let record = if looks_like_url(raw_source) {
        build_url_record(module_id, raw_source)?
    } else {
        build_path_record(workspace, module_id, raw_source)?
    };
    upsert_record(workspace, record)
}

pub fn detach_source(workspace: &WorkspaceTarget, id: &str) -> Result<AttachmentRecord> {
    let mut store = load_store(workspace)?;
    let Some(index) = store.attachments.iter().position(|record| record.id == id) else {
        anyhow::bail!(
            "unknown attachment id {id:?}. Valid attachment IDs: {}. Next: kb",
            valid_attachment_ids(&store.attachments)
        );
    };
    let removed = store.attachments.remove(index);
    save_store(workspace, &store)?;
    Ok(removed)
}

pub fn reparse_source(workspace: &WorkspaceTarget, id: &str) -> Result<AttachmentRecord> {
    let store = load_store(workspace)?;
    let Some(existing) = store.attachments.iter().find(|record| record.id == id) else {
        anyhow::bail!(
            "unknown attachment id {id:?}. Valid attachment IDs: {}. Next: kb",
            valid_attachment_ids(&store.attachments)
        );
    };
    let reparsed = match existing.kind {
        AttachmentKind::Path => {
            build_path_record(workspace, &existing.module_id, &existing.source)?
        }
        AttachmentKind::Url => build_url_record(&existing.module_id, &existing.source)?,
    };
    upsert_record(workspace, reparsed)
}

pub fn known_artifacts(workspace: &WorkspaceTarget, module_id: &str) -> Result<Vec<KnownArtifact>> {
    ensure_supported_module(module_id)?;
    let candidates: Vec<(&str, &str)> = match module_id {
        "context" => vec![(".kuzushi/context-snapshot.json", "context snapshot")],
        "threat-model" => vec![
            (".kuzushi/threat-model.json", "persisted threat model"),
            (
                ".kuzushi/tm-artifacts/normalized-threat-model.json",
                "normalized threat model",
            ),
        ],
        "carlini-threat-hunt" => vec![
            (".kuzushi/threat-model.json", "required threat-model input"),
            (".kuzushi/v2/findings.sqlite3", "hunt findings database"),
        ],
        "x-ray" => vec![
            ("x-ray/x-ray.md", "x-ray report"),
            ("x-ray/entry-points.md", "entry point report"),
            ("x-ray/invariants.md", "invariants report"),
            ("x-ray/architecture.svg", "architecture diagram"),
        ],
        _ => Vec::new(),
    };

    Ok(candidates
        .into_iter()
        .map(|(path, description)| KnownArtifact {
            module_id: module_id.to_string(),
            path: path.to_string(),
            description: description.to_string(),
            exists: workspace.root().join(path).exists(),
        })
        .collect())
}

fn ensure_supported_module(module_id: &str) -> Result<()> {
    if !is_supported_attachment_module(module_id) {
        anyhow::bail!(
            "KB attachments support context, threat-model, carlini-threat-hunt, and x-ray; got {module_id:?}. Next: kb context"
        );
    }
    Ok(())
}

fn load_store(workspace: &WorkspaceTarget) -> Result<AttachmentStoreFile> {
    let path = attachment_store_path(workspace);
    if !path.exists() {
        return Ok(AttachmentStoreFile::default());
    }
    let body =
        fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&body)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    if value.is_array() {
        let attachments = serde_json::from_value(value)
            .with_context(|| format!("Could not parse {}", path.display()))?;
        return Ok(AttachmentStoreFile {
            version: 1,
            attachments,
        });
    }
    serde_json::from_value(value).with_context(|| format!("Could not parse {}", path.display()))
}

fn save_store(workspace: &WorkspaceTarget, store: &AttachmentStoreFile) -> Result<()> {
    workspace.ensure_state_dir()?;
    let path = attachment_store_path(workspace);
    let body = format!("{}\n", serde_json::to_string_pretty(store)?);
    fs::write(&path, body).with_context(|| format!("Could not write {}", path.display()))
}

fn upsert_record(
    workspace: &WorkspaceTarget,
    record: AttachmentRecord,
) -> Result<AttachmentRecord> {
    let mut store = load_store(workspace)?;
    if let Some(existing) = store
        .attachments
        .iter_mut()
        .find(|existing| existing.id == record.id)
    {
        *existing = record.clone();
    } else {
        store.attachments.push(record.clone());
    }
    save_store(workspace, &store)?;
    Ok(record)
}

fn build_url_record(module_id: &str, raw_source: &str) -> Result<AttachmentRecord> {
    let normalized = raw_source.trim();
    if !is_supported_url(normalized) {
        anyhow::bail!(
            "unsupported attachment URL scheme in {normalized:?}; only http:// and https:// are recorded as metadata. Next: attach <path-or-url>"
        );
    }
    Ok(AttachmentRecord {
        id: attachment_id(module_id, "url", normalized),
        module_id: module_id.to_string(),
        kind: AttachmentKind::Url,
        source: normalized.to_string(),
        title: url_title(normalized),
        metadata_only: true,
        content_hash: None,
        byte_count: None,
        status: "metadata-only; URL was not fetched".to_string(),
        updated_at_unix: now_unix(),
    })
}

fn build_path_record(
    workspace: &WorkspaceTarget,
    module_id: &str,
    raw_source: &str,
) -> Result<AttachmentRecord> {
    let source_path = resolve_safe_attachment_path(workspace, raw_source)?;
    let bytes = fs::read(&source_path)
        .with_context(|| format!("Could not read attachment {}", source_path.display()))?;
    let relative = relative_workspace_path(workspace.root(), &source_path);
    Ok(AttachmentRecord {
        id: attachment_id(module_id, "path", &relative),
        module_id: module_id.to_string(),
        kind: AttachmentKind::Path,
        source: relative.clone(),
        title: source_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&relative)
            .to_string(),
        metadata_only: false,
        content_hash: Some(fnv1a_hex(&bytes)),
        byte_count: Some(bytes.len() as u64),
        status: "indexed metadata; content ready for local KB import".to_string(),
        updated_at_unix: now_unix(),
    })
}

fn resolve_safe_attachment_path(workspace: &WorkspaceTarget, raw_source: &str) -> Result<PathBuf> {
    let raw_source = raw_source.trim();
    if raw_source.is_empty() {
        anyhow::bail!("attachment path cannot be empty");
    }
    let raw_path = Path::new(raw_source);
    let candidate = if raw_path.is_absolute() {
        raw_path.to_path_buf()
    } else {
        workspace.root().join(raw_path)
    };
    let canonical = fs::canonicalize(&candidate)
        .with_context(|| format!("Could not resolve attachment path {}", candidate.display()))?;
    if !canonical.starts_with(workspace.root()) {
        anyhow::bail!(
            "unsafe attachment path {} escapes workspace root {}. Next: attach <repo-relative-path>",
            raw_source,
            workspace.root().display()
        );
    }
    if !canonical.is_file() {
        anyhow::bail!(
            "attachment path must be a file inside the workspace: {}",
            relative_workspace_path(workspace.root(), &canonical)
        );
    }
    Ok(canonical)
}

fn relative_workspace_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn looks_like_url(value: &str) -> bool {
    value.contains("://")
}

fn is_supported_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn url_title(value: &str) -> String {
    value
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').find(|part| !part.is_empty()))
        .unwrap_or(value)
        .to_string()
}

fn valid_attachment_ids(records: &[AttachmentRecord]) -> String {
    if records.is_empty() {
        "none".to_string()
    } else {
        records
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn attachment_id(module_id: &str, kind: &str, source: &str) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(module_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(kind.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(source.as_bytes());
    let hash = fnv1a_hex(&bytes);
    format!("A-{}", &hash[..12])
}

fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attaches_repo_file_under_v2_state() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("notes.md"), "operator note\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let record = attach_source(&workspace, "context", "notes.md").unwrap();

        assert_eq!(record.module_id, "context");
        assert_eq!(record.kind, AttachmentKind::Path);
        assert_eq!(record.source, "notes.md");
        assert_eq!(record.byte_count, Some("operator note\n".len() as u64));
        assert!(record.content_hash.is_some());
        assert!(attachment_store_path(&workspace).ends_with(".kuzushi/v2/attachments.json"));
        assert!(attachment_store_path(&workspace).exists());
    }

    #[test]
    fn rejects_paths_outside_workspace_root() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let error = attach_source(&workspace, "context", outside.path().to_str().unwrap())
            .unwrap_err()
            .to_string();

        assert!(error.contains("escapes workspace root"));
    }

    #[test]
    fn url_attachments_are_metadata_only() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let record =
            attach_source(&workspace, "threat-model", "https://example.test/design").unwrap();

        assert_eq!(record.kind, AttachmentKind::Url);
        assert!(record.metadata_only);
        assert_eq!(record.content_hash, None);
        assert!(record.status.contains("not fetched"));
    }

    #[test]
    fn reparse_updates_file_hash_and_detach_removes_record() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("x-ray.md"), "first\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let first = attach_source(&workspace, "x-ray", "x-ray.md").unwrap();
        fs::write(tmp.path().join("x-ray.md"), "second\n").unwrap();

        let second = reparse_source(&workspace, &first.id).unwrap();

        assert_eq!(first.id, second.id);
        assert_ne!(first.content_hash, second.content_hash);
        let removed = detach_source(&workspace, &first.id).unwrap();
        assert_eq!(removed.id, first.id);
        assert!(list_attachments(&workspace).unwrap().is_empty());
    }

    #[test]
    fn known_artifacts_cover_supported_bridge_modules() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("x-ray")).unwrap();
        fs::write(tmp.path().join("x-ray/x-ray.md"), "# X-Ray\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        for module_id in SUPPORTED_ATTACHMENT_MODULES {
            let artifacts = known_artifacts(&workspace, module_id).unwrap();
            assert!(!artifacts.is_empty(), "missing artifacts for {module_id}");
        }
        let x_ray = known_artifacts(&workspace, "x-ray").unwrap();
        assert!(x_ray.iter().any(|artifact| {
            artifact.path == "x-ray/x-ray.md" && artifact.description == "x-ray report"
        }));
    }
}
