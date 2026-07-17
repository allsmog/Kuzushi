use super::*;

pub(super) const MAX_VIEW_SOURCE_BYTES: usize = 2 * 1024 * 1024;
pub(super) const MAX_VIEW_HARNESS_BYTES: usize = 1024 * 1024;

const MAX_VIEW_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_VIEW_PROMPT_BYTES: usize = 1024 * 1024;
const MAX_VIEW_DIRECTORY_ENTRIES: usize = 1024;

pub(super) fn read_json_file(target: &Path, path: &Path) -> JsonFileState {
    match inspect_workspace_path(target, path) {
        PathState::File { .. } => {}
        PathState::Missing => return JsonFileState::Missing,
        PathState::Unreadable => return JsonFileState::Unreadable,
        PathState::Directory | PathState::Other => return JsonFileState::NonFile,
    }
    let raw = match read_workspace_text(target, path, MAX_VIEW_JSON_BYTES) {
        Ok(raw) => raw,
        Err(_) => return JsonFileState::Unreadable,
    };
    serde_json::from_str(&raw)
        .map(JsonFileState::Present)
        .unwrap_or(JsonFileState::Malformed)
}

pub(super) fn read_directory(target: &Path, path: &Path) -> DirectoryListingState {
    let checked = match checked_workspace_path(target, path) {
        Ok(Some(checked)) if checked.metadata.is_dir() => checked,
        Ok(Some(_)) => return DirectoryListingState::NonDirectory,
        Ok(None) => return DirectoryListingState::Missing,
        Err(_) => return DirectoryListingState::Unreadable,
    };
    let entries = match std::fs::read_dir(checked.path) {
        Ok(entries) => entries,
        Err(_) => return DirectoryListingState::Unreadable,
    };
    collect_regular_files(entries)
}

fn collect_regular_files(entries: std::fs::ReadDir) -> DirectoryListingState {
    let mut files = Vec::new();
    for (index, entry) in entries.take(MAX_VIEW_DIRECTORY_ENTRIES + 1).enumerate() {
        if index == MAX_VIEW_DIRECTORY_ENTRIES {
            return DirectoryListingState::Unreadable;
        }
        let Ok(entry) = entry else {
            return DirectoryListingState::Unreadable;
        };
        if entry.file_type().is_ok_and(|kind| kind.is_file()) {
            files.push(entry.path());
        }
    }
    files.sort();
    DirectoryListingState::Ready(files)
}

pub(super) fn prompt_override_hash(target: &Path, path: &Path) -> Result<Option<String>, String> {
    read_optional_workspace_text(target, path, MAX_VIEW_PROMPT_BYTES)
        .map(|text| text.map(|text| kuzushi_core::prompt_content_sha256(&text)))
}

pub(super) fn inspect_workspace_path(target: &Path, path: &Path) -> PathState {
    match checked_workspace_path(target, path) {
        Ok(Some(checked)) if checked.metadata.is_file() => PathState::File {
            len: checked.metadata.len(),
        },
        Ok(Some(checked)) if checked.metadata.is_dir() => PathState::Directory,
        Ok(Some(_)) => PathState::Other,
        Ok(None) => PathState::Missing,
        Err(_) => PathState::Unreadable,
    }
}

pub(super) fn read_workspace_text(
    target: &Path,
    path: &Path,
    max_bytes: usize,
) -> Result<String, String> {
    kuzushi_core::workspace::read_workspace_text(target, path, max_bytes)
        .map_err(|error| error.to_string())
}

pub(super) fn read_optional_workspace_text(
    target: &Path,
    path: &Path,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    kuzushi_core::workspace::read_optional_workspace_text(target, path, max_bytes)
        .map_err(|error| error.to_string())
}

pub(super) struct CheckedWorkspacePath {
    pub(super) path: PathBuf,
    pub(super) metadata: std::fs::Metadata,
}

pub(super) fn checked_workspace_path(
    target: &Path,
    path: &Path,
) -> Result<Option<CheckedWorkspacePath>, String> {
    let expected = expected_workspace_path(target, path)?;
    let resolved = match std::fs::canonicalize(&expected) {
        Ok(resolved) => resolved,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    if resolved != expected {
        return Err(format!(
            "workspace view path contains a symlink: {}",
            path.display()
        ));
    }
    let metadata = std::fs::symlink_metadata(&resolved).map_err(|error| error.to_string())?;
    Ok(Some(CheckedWorkspacePath {
        path: resolved,
        metadata,
    }))
}

fn expected_workspace_path(target: &Path, path: &Path) -> Result<PathBuf, String> {
    let root = std::fs::canonicalize(target).map_err(|error| error.to_string())?;
    let relative = path
        .strip_prefix(target)
        .map_err(|_| format!("{} is outside target", path.display()))?;
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(format!("invalid workspace view path {}", path.display()));
    }
    Ok(root.join(relative))
}
