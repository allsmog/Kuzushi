use super::*;

pub(super) const MAX_VIEW_SOURCE_BYTES: usize = 2 * 1024 * 1024;
pub(super) const MAX_VIEW_HARNESS_BYTES: usize = 1024 * 1024;

const MAX_VIEW_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_VIEW_PROMPT_BYTES: usize = 1024 * 1024;
const MAX_VIEW_DIRECTORY_ENTRIES: usize = 1024;

pub(super) fn read_json_file(target: &Path, path: &Path) -> JsonFileHydration {
    match inspect_workspace_path(target, path) {
        PathState::File { .. } => {}
        PathState::Missing => return JsonFileHydration::state(JsonFileState::Missing),
        PathState::Unreadable => return JsonFileHydration::state(JsonFileState::Unreadable),
        PathState::Directory | PathState::Other => {
            return JsonFileHydration::state(JsonFileState::NonFile)
        }
    }
    let raw = match read_workspace_text(target, path, json_read_limit(target, path)) {
        Ok(raw) => raw,
        Err(_) => return JsonFileHydration::state(JsonFileState::Unreadable),
    };
    let Ok(document) = serde_json::from_str(&raw) else {
        return JsonFileHydration::state(JsonFileState::Malformed);
    };
    let content_sha256 = hydrated_json_sha256(target, path, &raw, &document);
    let entry_point_catalog_authentication = catalog_authentication(target, path, &document);
    let entry_point_catalog_context_authentication = catalog_context_authentication(
        target,
        &document,
        entry_point_catalog_authentication.as_ref(),
    );
    JsonFileHydration {
        content_sha256,
        entry_point_catalog_authentication,
        entry_point_catalog_context_authentication,
        state: JsonFileState::Present(document),
    }
}

fn hydrated_json_sha256(
    target: &Path,
    path: &Path,
    raw: &str,
    document: &serde_json::Value,
) -> Option<String> {
    if is_context_snapshot(target, path) {
        return Some(kuzushi_core::prompt_content_sha256(raw));
    }
    if path != kuzushi_core::capabilities::persistent_threat_model_path(target) {
        return None;
    }
    kuzushi_core::review_yield::domain::canonical_json_bytes(document)
        .ok()
        .map(|bytes| kuzushi_core::run_lifecycle::sha256_content_digest(&bytes))
}

fn json_read_limit(target: &Path, path: &Path) -> usize {
    let catalog = kuzushi_core::workspace::workspace_state_root(target).join("entry-points.json");
    if path == catalog {
        kuzushi_core::capabilities::entry_points::MAX_ENTRY_POINT_CATALOG_BYTES
    } else if is_context_snapshot(target, path) {
        kuzushi_core::context::MAX_CONTEXT_SNAPSHOT_BYTES
    } else {
        MAX_VIEW_JSON_BYTES
    }
}

fn is_context_snapshot(target: &Path, path: &Path) -> bool {
    path == kuzushi_core::context_snapshot_path(target)
}

fn catalog_authentication(
    target: &Path,
    path: &Path,
    document: &serde_json::Value,
) -> Option<Result<kuzushi_core::capabilities::entry_points::EntryPointCatalogAuthentication, String>>
{
    let catalog = kuzushi_core::workspace::workspace_state_root(target).join("entry-points.json");
    (path == catalog).then(|| {
        kuzushi_core::capabilities::entry_points::authenticate_entry_point_catalog(target, document)
            .map_err(|error| error.to_string())
    })
}

fn catalog_context_authentication(
    target: &Path,
    catalog: &serde_json::Value,
    catalog_authentication: Option<
        &Result<kuzushi_core::capabilities::entry_points::EntryPointCatalogAuthentication, String>,
    >,
) -> Option<EntryPointCatalogContextAuthentication> {
    let catalog_authentication = catalog_authentication?;
    if catalog_authentication.is_err() {
        return None;
    }
    let context_path = kuzushi_core::context_snapshot_path(target);
    let context = read_json_file(target, &context_path);
    let context_document = match context.state {
        JsonFileState::Present(document) => document,
        state => {
            return Some(EntryPointCatalogContextAuthentication::Unavailable(
                context_state_label(&state).to_string(),
            ))
        }
    };
    let Some(context_sha256) = context.content_sha256 else {
        return Some(EntryPointCatalogContextAuthentication::Unavailable(
            "context snapshot digest unavailable".to_string(),
        ));
    };
    let result =
        kuzushi_core::capabilities::entry_points::authenticate_entry_point_catalog_against_context(
            target,
            catalog,
            &context_document,
            &context_sha256,
        );
    Some(match result {
        Ok(authentication) => EntryPointCatalogContextAuthentication::Authenticated(authentication),
        Err(error) => EntryPointCatalogContextAuthentication::Rejected(error.to_string()),
    })
}

fn context_state_label(state: &JsonFileState) -> &'static str {
    match state {
        JsonFileState::Present(_) => "context snapshot ready",
        JsonFileState::Missing => "context snapshot missing",
        JsonFileState::NonFile => "context snapshot is not a file",
        JsonFileState::Malformed => "context snapshot malformed",
        JsonFileState::Unreadable => "context snapshot unreadable",
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_point_catalog_uses_its_16_mib_contract_without_widening_generic_json() {
        let target = tempfile::tempdir().unwrap();
        let state_root = kuzushi_core::workspace::workspace_state_root(target.path());
        std::fs::create_dir_all(&state_root).unwrap();
        let body = format!("{{\"padding\":\"{}\"}}", "a".repeat(9 * 1024 * 1024));
        let catalog = state_root.join("entry-points.json");
        let generic = state_root.join("other.json");
        std::fs::write(&catalog, &body).unwrap();
        std::fs::write(&generic, &body).unwrap();

        let catalog_hydration = read_json_file(target.path(), &catalog);
        assert!(matches!(catalog_hydration.state, JsonFileState::Present(_)));
        assert!(catalog_hydration
            .entry_point_catalog_authentication
            .is_some());
        assert!(matches!(
            read_json_file(target.path(), &generic).state,
            JsonFileState::Unreadable
        ));
    }

    #[test]
    fn context_snapshot_hydration_carries_the_exact_raw_digest_off_thread() {
        let target = tempfile::tempdir().unwrap();
        let context = kuzushi_core::context_snapshot_path(target.path());
        std::fs::create_dir_all(context.parent().unwrap()).unwrap();
        let body = format!("{{\"padding\":\"{}\"}}", "a".repeat(9 * 1024 * 1024));
        std::fs::write(&context, &body).unwrap();

        let hydration = read_json_file(target.path(), &context);

        assert!(matches!(hydration.state, JsonFileState::Present(_)));
        assert_eq!(
            hydration.content_sha256.as_deref(),
            Some(kuzushi_core::prompt_content_sha256(&body).as_str())
        );
        assert!(hydration.entry_point_catalog_authentication.is_none());
    }

    #[test]
    fn catalog_hydration_authenticates_exact_rows_against_context_off_thread() {
        let target = tempfile::tempdir().unwrap();
        let catalog = write_empty_catalog_and_context(target.path());

        let hydration = read_json_file(target.path(), &catalog);

        assert!(matches!(
            hydration.entry_point_catalog_context_authentication,
            Some(EntryPointCatalogContextAuthentication::Authenticated(authentication))
                if authentication.total == 0
                    && authentication.context_sha256.starts_with("sha256:")
        ));
    }

    #[test]
    fn catalog_hydration_rejects_context_provenance_disagreement_off_thread() {
        let target = tempfile::tempdir().unwrap();
        let catalog = write_empty_catalog_and_context(target.path());
        let mut document: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&catalog).unwrap()).unwrap();
        document["provenance"]["contextSnapshotSha256"] = serde_json::json!("sha256:wrong");
        std::fs::write(&catalog, serde_json::to_string(&document).unwrap()).unwrap();

        let hydration = read_json_file(target.path(), &catalog);

        assert!(matches!(
            hydration.entry_point_catalog_context_authentication,
            Some(EntryPointCatalogContextAuthentication::Rejected(error))
                if error.contains("context digest is stale")
        ));
    }

    #[test]
    fn catalog_hydration_rejects_a_catalog_recording_no_coverage_off_thread() {
        let target = tempfile::tempdir().unwrap();
        let catalog = write_empty_catalog_and_context(target.path());
        let mut document: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&catalog).unwrap()).unwrap();
        document.as_object_mut().unwrap().remove("snapshotCoverage");
        std::fs::write(&catalog, serde_json::to_string(&document).unwrap()).unwrap();

        let hydration = read_json_file(target.path(), &catalog);

        assert!(matches!(
            hydration.entry_point_catalog_context_authentication,
            Some(EntryPointCatalogContextAuthentication::Rejected(error))
                if error.contains("records no snapshot coverage")
        ));
    }

    fn write_empty_catalog_and_context(target: &Path) -> PathBuf {
        let context_path = kuzushi_core::context_snapshot_path(target);
        std::fs::create_dir_all(context_path.parent().unwrap()).unwrap();
        let canonical_target = std::fs::canonicalize(target).unwrap();
        let context = serde_json::json!({
            "target": canonical_target,
            "timestamp": 10,
            "attackSurfaceMap": {"surfaces": []}
        });
        let context_body = serde_json::to_string(&context).unwrap();
        std::fs::write(&context_path, &context_body).unwrap();
        let catalog = serde_json::json!({
            "target": canonical_target,
            "timestamp": 20,
            "snapshotTimestamp": 10,
            "total": 0,
            "entryPoints": [],
            "snapshotCoverage": {"state": "complete"},
            "provenance": {
                "builtAtMs": 20,
                "sha256": kuzushi_core::prompt_content_sha256("[]"),
                "contextSnapshotTimestamp": 10,
                "contextSnapshotSha256": kuzushi_core::prompt_content_sha256(&context_body)
            }
        });
        let catalog_path =
            kuzushi_core::workspace::workspace_state_root(target).join("entry-points.json");
        std::fs::write(&catalog_path, serde_json::to_string(&catalog).unwrap()).unwrap();
        catalog_path
    }
}
