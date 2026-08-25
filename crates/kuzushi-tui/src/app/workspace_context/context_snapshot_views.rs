use super::*;
use anyhow::Context;
use std::path::Path;

pub(crate) fn default_context_snapshot_view(snapshot_path: Option<PathBuf>) -> ContextSnapshotView {
    ContextSnapshotView {
        snapshot_path,
        exists: false,
        freshness: None,
        status: "missing. Next: context build".to_string(),
        target: None,
        discovery: None,
        files_indexed: None,
        total_files: None,
        languages: Vec::new(),
        frameworks: Vec::new(),
        generated_slices: Vec::new(),
        stale_slices: Vec::new(),
        enrichment_claims: 0,
        enrichment_model: None,
    }
}

pub(crate) fn default_workspace_view(target: Option<&WorkspaceTarget>) -> WorkspaceView {
    match target {
        Some(workspace) => WorkspaceView {
            root: Some(workspace.root().to_path_buf()),
            state_dir: Some(workspace.state_dir()),
            findings_db: Some(workspace.findings_db_path()),
            findings_count: None,
            last_export: None,
            status: "workspace ready. Next: workspace status".to_string(),
        },
        None => WorkspaceView {
            root: None,
            state_dir: None,
            findings_db: None,
            findings_count: None,
            last_export: None,
            status: "no active workspace. Next: target <path>, then map; or full <path>"
                .to_string(),
        },
    }
}

pub(crate) fn load_context_snapshot_view(snapshot_path: PathBuf) -> Result<ContextSnapshotView> {
    let workspace_root = context_snapshot_workspace_root(&snapshot_path)?;
    let body = match kuzushi_core::workspace::read_optional_workspace_text(
        &workspace_root,
        &snapshot_path,
        kuzushi_core::context::MAX_CONTEXT_SNAPSHOT_BYTES,
    ) {
        Ok(Some(body)) => body,
        Ok(None) => return Ok(default_context_snapshot_view(Some(snapshot_path))),
        Err(error) => {
            return Ok(invalid_context_snapshot_view(
                snapshot_path,
                &format!("unsafe or unreadable: {error}"),
            ))
        }
    };
    match read_context_snapshot_json(&body) {
        ContextSnapshotRead::Present(snapshot) => Ok(present_context_snapshot_view(
            snapshot_path,
            &workspace_root,
            &snapshot,
        )),
        ContextSnapshotRead::Malformed => Ok(malformed_context_snapshot_view(snapshot_path)),
    }
}

fn context_snapshot_workspace_root(snapshot_path: &std::path::Path) -> Result<PathBuf> {
    let state_root = snapshot_path
        .parent()
        .context("Context snapshot path has no state directory")?;
    let root = state_root
        .parent()
        .context("Context snapshot path has no workspace root")?;
    anyhow::ensure!(
        kuzushi_core::context_snapshot_path(root) == snapshot_path,
        "Context snapshot path is outside the canonical workspace state location"
    );
    Ok(root.to_path_buf())
}

fn present_context_snapshot_view(
    snapshot_path: PathBuf,
    workspace_root: &Path,
    snapshot: &serde_json::Value,
) -> ContextSnapshotView {
    let (files_indexed, total_files) = context_snapshot_file_counts(snapshot);
    let generated_slices = json_string_array(snapshot.get("generatedSlices"));
    let stale_slices = json_string_array(snapshot.get("staleSlices"));
    let languages = json_string_array(snapshot.pointer("/repoContext/languages"));
    let frameworks = json_string_array(snapshot.pointer("/repoContext/frameworks"));
    let (target, discovery) = context_snapshot_labels(snapshot);
    let freshness = kuzushi_core::context::context_snapshot_freshness(workspace_root, snapshot);
    let (enrichment_claims, enrichment_model) = context_enrichment_details(snapshot);
    let status = context_snapshot_status(files_indexed, total_files, &freshness);

    ContextSnapshotView {
        snapshot_path: Some(snapshot_path),
        exists: true,
        freshness: Some(freshness),
        status,
        target,
        discovery,
        files_indexed,
        total_files,
        languages,
        frameworks,
        generated_slices,
        stale_slices,
        enrichment_claims,
        enrichment_model,
    }
}

fn context_snapshot_file_counts(snapshot: &serde_json::Value) -> (Option<u64>, Option<u64>) {
    (
        snapshot
            .get("filesIndexed")
            .and_then(serde_json::Value::as_u64),
        snapshot
            .pointer("/fileIndex/totalFiles")
            .and_then(serde_json::Value::as_u64),
    )
}

fn context_snapshot_labels(snapshot: &serde_json::Value) -> (Option<String>, Option<String>) {
    let text = |key| {
        snapshot
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    (text("target"), text("discovery"))
}

fn context_enrichment_details(snapshot: &serde_json::Value) -> (usize, Option<String>) {
    let claims = context_enrichment_claim_count(snapshot);
    let model = snapshot
        .pointer("/provenance/enrichment/model")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    (claims, model)
}

fn read_context_snapshot_json(body: &str) -> ContextSnapshotRead {
    match serde_json::from_str(body) {
        Ok(value) => ContextSnapshotRead::Present(value),
        Err(_) => ContextSnapshotRead::Malformed,
    }
}

enum ContextSnapshotRead {
    Present(serde_json::Value),
    Malformed,
}

fn malformed_context_snapshot_view(snapshot_path: PathBuf) -> ContextSnapshotView {
    ContextSnapshotView {
        snapshot_path: Some(snapshot_path),
        exists: false,
        freshness: None,
        status: "malformed context snapshot. Next: context build".to_string(),
        target: None,
        discovery: None,
        files_indexed: None,
        total_files: None,
        languages: Vec::new(),
        frameworks: Vec::new(),
        generated_slices: Vec::new(),
        stale_slices: Vec::new(),
        enrichment_claims: 0,
        enrichment_model: None,
    }
}

fn invalid_context_snapshot_view(snapshot_path: PathBuf, reason: &str) -> ContextSnapshotView {
    ContextSnapshotView {
        snapshot_path: Some(snapshot_path),
        exists: false,
        freshness: None,
        status: format!("malformed context snapshot ({reason}). Next: context build"),
        target: None,
        discovery: None,
        files_indexed: None,
        total_files: None,
        languages: Vec::new(),
        frameworks: Vec::new(),
        generated_slices: Vec::new(),
        stale_slices: Vec::new(),
        enrichment_claims: 0,
        enrichment_model: None,
    }
}

fn context_enrichment_claim_count(snapshot: &serde_json::Value) -> usize {
    [
        "customMiddleware",
        "customSanitizers",
        "trustBoundaries",
        "dataClassifications",
        "architecturalNotes",
    ]
    .iter()
    .map(|key| {
        snapshot
            .pointer(&format!("/enrichedContext/{key}"))
            .and_then(serde_json::Value::as_array)
            .map(Vec::len)
            .unwrap_or(0)
    })
    .sum()
}

fn context_snapshot_status(
    files_indexed: Option<u64>,
    total_files: Option<u64>,
    freshness: &kuzushi_core::context::ContextSnapshotFreshness,
) -> String {
    let count = files_indexed.or(total_files).unwrap_or(0);
    match freshness {
        kuzushi_core::context::ContextSnapshotFreshness::Current => {
            format!("snapshot current; {count} indexed file(s). Next: context regen repo")
        }
        kuzushi_core::context::ContextSnapshotFreshness::Stale(reason) => {
            format!("stale · {reason}; {count} indexed file(s). Next: context build")
        }
        kuzushi_core::context::ContextSnapshotFreshness::Unverifiable(reason) => {
            format!("freshness unverified · {reason}; {count} indexed file(s). Next: context build")
        }
    }
}

pub(crate) fn json_string_array(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn normalize_kb_module_id(raw_id: &str) -> String {
    match raw_id.trim().to_ascii_lowercase().as_str() {
        "tm" | "threat" | "threats" => "threat-model".to_string(),
        "carlini" | "threat-hunt" | "carlini-threat-hunt" => "offense-review".to_string(),
        "xray" | "x_ray" => "x-ray".to_string(),
        other => other.to_string(),
    }
}

pub(crate) fn unknown_kb_module_message(module_id: &str) -> String {
    format!(
        "unknown KB module {module_id:?}. Supported KB modules: {}. Next: kb context",
        SUPPORTED_ATTACHMENT_MODULES.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_context_snapshot_view_surfaces_malformed_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot_path = kuzushi_core::context_snapshot_path(temp.path());
        fs::create_dir_all(snapshot_path.parent().unwrap()).unwrap();
        fs::write(&snapshot_path, "{not-json").unwrap();

        let view = load_context_snapshot_view(snapshot_path.clone()).unwrap();

        assert_eq!(view.snapshot_path, Some(snapshot_path));
        assert!(!view.exists);
        assert_eq!(
            view.status,
            "malformed context snapshot. Next: context build"
        );
        assert!(view.languages.is_empty());
        assert!(view.frameworks.is_empty());
    }

    #[test]
    fn load_context_snapshot_view_surfaces_non_file_snapshot_path() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot_path = kuzushi_core::context_snapshot_path(temp.path());
        fs::create_dir_all(&snapshot_path).unwrap();

        let view = load_context_snapshot_view(snapshot_path.clone()).unwrap();

        assert_eq!(view.snapshot_path, Some(snapshot_path));
        assert!(!view.exists);
        assert!(
            view.status.contains("unsafe or unreadable"),
            "{}",
            view.status
        );
        assert!(view.languages.is_empty());
        assert!(view.frameworks.is_empty());
    }

    #[test]
    fn load_context_snapshot_view_marks_changed_source_as_stale() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("source.rs"), "fn first() {}\n").unwrap();
        let snapshot_path = kuzushi_core::context_snapshot_path(temp.path());
        fs::create_dir_all(snapshot_path.parent().unwrap()).unwrap();
        let tree_hash =
            kuzushi_core::incremental_index::current_workspace_tree_hash(temp.path()).unwrap();
        fs::write(
            &snapshot_path,
            serde_json::json!({
                "target": temp.path(),
                "provenance": {
                    "treeHash": tree_hash,
                    "enrichment": {"model": "openai:gpt-test"}
                },
                "filesIndexed": 1,
                "fileIndex": {"totalFiles": 1},
                "enrichedContext": {
                    "customMiddleware": [{"name": "guard"}],
                    "architecturalNotes": [{"note": "single tenant"}]
                }
            })
            .to_string(),
        )
        .unwrap();
        fs::write(temp.path().join("source.rs"), "fn changed() {}\n").unwrap();

        let view = load_context_snapshot_view(snapshot_path).unwrap();

        assert!(matches!(
            view.freshness,
            Some(kuzushi_core::context::ContextSnapshotFreshness::Stale(_))
        ));
        assert!(view.status.starts_with("stale ·"), "{}", view.status);
        assert!(view.status.contains("Next: context build"));
        assert_eq!(view.enrichment_claims, 2);
        assert_eq!(view.enrichment_model.as_deref(), Some("openai:gpt-test"));
    }

    #[cfg(unix)]
    #[test]
    fn load_context_snapshot_view_rejects_outside_symlink_without_disclosing_content() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), "OUTSIDE_CONTEXT_TOKEN").unwrap();
        let snapshot_path = kuzushi_core::context_snapshot_path(temp.path());
        fs::create_dir_all(snapshot_path.parent().unwrap()).unwrap();
        symlink(outside.path(), &snapshot_path).unwrap();

        let view = load_context_snapshot_view(snapshot_path).unwrap();

        assert!(view.status.contains("unsafe or unreadable"));
        assert!(!view.status.contains("OUTSIDE_CONTEXT_TOKEN"));
    }
}
