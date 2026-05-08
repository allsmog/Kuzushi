use super::prelude::*;
use super::*;

pub(crate) fn build_url_record(module_id: &str, raw_source: &str) -> Result<AttachmentRecord> {
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

pub(crate) fn build_path_record(
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

pub(crate) fn resolve_safe_attachment_path(
    workspace: &WorkspaceTarget,
    raw_source: &str,
) -> Result<PathBuf> {
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

pub(crate) fn relative_workspace_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

pub(crate) fn looks_like_url(value: &str) -> bool {
    value.contains("://")
}

pub(crate) fn is_supported_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

pub(crate) fn url_title(value: &str) -> String {
    value
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').find(|part| !part.is_empty()))
        .unwrap_or(value)
        .to_string()
}

pub(crate) fn valid_attachment_ids(records: &[AttachmentRecord]) -> String {
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
