use super::*;

pub const SUPPORTED_ATTACHMENT_MODULES: &[&str] =
    &["context", "threat-model", "offense-review", "x-ray"];

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
pub(crate) struct AttachmentStoreFile {
    pub(crate) version: u8,
    pub(crate) attachments: Vec<AttachmentRecord>,
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
    SUPPORTED_ATTACHMENT_MODULES.contains(&module_id) || module_id == "carlini-threat-hunt"
}

pub fn attachment_store_path(workspace: &WorkspaceTarget) -> PathBuf {
    crate::workspace::workspace_attachments_path(workspace.root())
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
        anyhow::bail!("{}", attachment_id_error(id, &store.attachments));
    };
    let removed = store.attachments.remove(index);
    save_store(workspace, &store)?;
    Ok(removed)
}
