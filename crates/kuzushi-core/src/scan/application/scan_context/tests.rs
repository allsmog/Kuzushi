use super::*;
use serde_json::json;

fn source() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("main.rs"),
        "fn main() { println!(\"hello\"); }\n",
    )
    .unwrap();
    root
}

fn context(root: &Path, note: &str) {
    let tree = crate::incremental_index::current_workspace_tree_hash(root).unwrap();
    let path = crate::context::context_snapshot_path(root);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let value = json!({"target":root,"provenance":{"treeHash":tree},"enrichedContext":{"architecturalNotes":[{"note":note}]}});
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

fn frozen(root: &Path) -> Value {
    let mut input = json!({});
    freeze_scan_context(root, &mut input).unwrap();
    input
}

#[test]
fn frozen_scan_context_preserves_text_and_absence() {
    let root = source();
    let absent = frozen(root.path());
    context(root.path(), "Accepted architecture A");
    assert_eq!(selected_scan_context(root.path(), &absent).unwrap(), None);
    let mut accepted = frozen(root.path());
    let original = accepted.clone();
    let expected = selected_scan_context(root.path(), &accepted)
        .unwrap()
        .unwrap();
    assert!(expected.contains("Accepted architecture A"));
    context(root.path(), "Later architecture B");
    freeze_scan_context(root.path(), &mut accepted).unwrap();
    assert_eq!(accepted, original);
    assert_eq!(
        selected_scan_context(root.path(), &accepted).unwrap(),
        Some(expected)
    );
    assert_eq!(
        selected_scan_context(root.path(), &json!({"scanContextRef":null})).unwrap(),
        None
    );
}

#[test]
fn frozen_scan_context_rejects_drift_but_keeps_history_readable() {
    let root = source();
    context(root.path(), "Recorded architecture");
    let input = frozen(root.path());
    std::fs::write(
        root.path().join("main.rs"),
        "fn main() { println!(\"changed\"); }\n",
    )
    .unwrap();
    assert!(selected_scan_context(root.path(), &input)
        .unwrap_err()
        .to_string()
        .contains("different source"));
    assert!(inspect_scan_context(root.path(), &input)
        .unwrap()
        .unwrap()
        .contains("Recorded architecture"));
}

#[test]
fn frozen_scan_context_rejects_invalid_reference_and_foreign_target() {
    let root = source();
    let input = frozen(root.path());
    for (field, value) in [("schemaVersion", json!(2)), ("object", json!({}))] {
        let mut invalid = input.clone();
        invalid["scanContextRef"][field] = value;
        assert!(selected_scan_context(root.path(), &invalid).is_err());
    }
    let other = source();
    let mut document = read_bound_scan_context(root.path(), &input["scanContextRef"])
        .unwrap()
        .unwrap();
    document.target = other.path().to_string_lossy().into_owned();
    let reference = crate::scan::save_scan_context(root.path(), &document).unwrap();
    assert!(selected_scan_context(root.path(), &json!({"scanContextRef":reference})).is_err());
}

#[test]
fn frozen_scan_context_refuses_missing_tampered_and_oversized_content() {
    let root = source();
    let input = frozen(root.path());
    let reference: ScanContextRef =
        serde_json::from_value(input["scanContextRef"].clone()).unwrap();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let store = crate::content_store::ContentStore::open(workspace.objects_dir()).unwrap();
    let path = store.object_path(&reference.object.hash);
    std::fs::write(&path, b"tampered").unwrap();
    assert!(selected_scan_context(root.path(), &input).is_err());
    assert!(inspect_scan_context(root.path(), &input).is_err());
    std::fs::remove_file(&path).unwrap();
    assert!(selected_scan_context(root.path(), &input).is_err());
    assert!(inspect_scan_context(root.path(), &input).is_err());
    let mut invalid = input;
    invalid["scanContextRef"]["object"]["sizeBytes"] = json!(65537);
    assert!(selected_scan_context(root.path(), &invalid).is_err());
    let document = ScanContextDocument {
        schema_version: 1,
        target: root.path().to_string_lossy().into_owned(),
        source_identity: "test".into(),
        context_enrichment: Some("x".repeat(65537)),
    };
    assert!(crate::scan::save_scan_context(root.path(), &document).is_err());
}

#[test]
fn frozen_scan_context_is_canonical_in_both_dispatch_descriptors() {
    let root = source();
    let input = frozen(root.path());
    let registry = crate::ModuleRegistry::with_v2_builtins();
    let config = crate::V2Config::default();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let ctx = crate::modules::ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    for tool in ["sast:scan", "agentic-sast:scan"] {
        let prepared = registry
            .prepare_dispatch_input(tool, input.clone(), &ctx, None)
            .unwrap();
        assert_eq!(prepared.value()["scanContextRef"], input["scanContextRef"]);
    }
}

#[test]
fn frozen_scan_context_requires_an_explicit_choice_for_invalid_live_context() {
    let root = source();
    context(root.path(), "Current architecture");
    let path = crate::context::context_snapshot_path(root.path());
    std::fs::write(&path, b"malformed").unwrap();
    assert!(freeze_scan_context(root.path(), &mut json!({})).is_err());
    let mut omitted = json!({"scanContextRef":null});
    freeze_scan_context(root.path(), &mut omitted).unwrap();
    assert_eq!(selected_scan_context(root.path(), &omitted).unwrap(), None);
    context(root.path(), "Architecture before source drift");
    std::fs::write(
        root.path().join("main.rs"),
        "fn main() { println!(\"drift\"); }\n",
    )
    .unwrap();
    assert!(freeze_scan_context(root.path(), &mut json!({}))
        .unwrap_err()
        .to_string()
        .contains("stale or unverifiable"));
}
