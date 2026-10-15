use super::*;
use crate::capabilities::{
    agentic_sast::selected_threat_model_scan_context, threat_model::commit_test_model,
};

fn fixture() -> (tempfile::TempDir, ThreatModelRef, Value) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("owned.txt"), "Owned inert source.\n").unwrap();
    let reference = commit_test_model(root.path(), "ALPHA");
    let mut input = json!({"taskMode":"manual","tasks":["agentic-sast"],"threatModelRef":reference,"triage":false,"verify":false,"autoPatch":false});
    freeze_threat_model_digest(root.path(), &mut input, "sast:scan").unwrap();
    (root, reference, input)
}

fn replace_recorded_text(
    root: &Path,
    reference: &ThreatModelRef,
    input: &mut Value,
    text: Option<&str>,
) {
    let mut recorded =
        inspect_threat_model_digest(root, &input["threatModelDigestRef"], reference).unwrap();
    recorded.preview["text"] = json!(text);
    recorded.preview["sha256"] = json!(text.map(crate::prompt_content_sha256));
    input["threatModelDigestRef"] =
        json!(crate::scan::save_threat_model_digest(root, &recorded).unwrap());
}

#[test]
fn execution_keeps_recorded_bytes_and_absence_across_renderer_and_active_context_changes() {
    let (root, reference, mut input) = fixture();
    replace_recorded_text(
        root.path(),
        &reference,
        &mut input,
        Some("Synthetic previous renderer context"),
    );
    commit_test_model(root.path(), "BETA");
    assert_eq!(
        selected_threat_model_scan_context(root.path(), &input)
            .unwrap()
            .as_deref(),
        Some("Synthetic previous renderer context")
    );
    let previous = input.clone();
    freeze_threat_model_digest(root.path(), &mut input, "sast:scan").unwrap();
    assert_eq!(input, previous);
    replace_recorded_text(root.path(), &reference, &mut input, None);
    assert!(selected_threat_model_scan_context(root.path(), &input)
        .unwrap()
        .is_none());
}

#[test]
fn source_drift_refuses_execution_but_preserves_exact_historical_reading() {
    let (root, reference, input) = fixture();
    std::fs::write(root.path().join("owned.txt"), "Changed owned source.\n").unwrap();
    assert!(selected_threat_model_scan_context(root.path(), &input)
        .unwrap_err()
        .to_string()
        .contains("different source"));
    let history =
        inspect_threat_model_digest(root.path(), &input["threatModelDigestRef"], &reference)
            .unwrap();
    assert!(history.preview["text"].as_str().unwrap().contains("ALPHA"));
    assert_eq!(history.preview["origin"], "frozen-study");
}

#[test]
fn context_mismatch_and_implicit_or_omitted_selection_cannot_substitute_context() {
    let (root, _, input) = fixture();
    let other = commit_test_model(root.path(), "BETA");
    let mut changed = input.clone();
    changed["threatModelRef"] = json!(other);
    assert!(selected_threat_model_scan_context(root.path(), &changed)
        .unwrap_err()
        .to_string()
        .contains("different context revision"));
    changed["threatModelRef"] = Value::Null;
    assert!(selected_threat_model_scan_context(root.path(), &changed).is_err());
    changed.as_object_mut().unwrap().remove("threatModelRef");
    assert!(selected_threat_model_scan_context(root.path(), &changed).is_err());
}

#[test]
fn missing_or_corrupt_saved_bytes_never_fall_back_to_the_current_renderer() {
    let (root, reference, input) = fixture();
    let frozen: ScanContextRef =
        serde_json::from_value(input["threatModelDigestRef"].clone()).unwrap();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let store = crate::content_store::ContentStore::open(workspace.objects_dir()).unwrap();
    let path = store.object_path(&frozen.object.hash);
    std::fs::write(&path, "Corrupted context").unwrap();
    assert!(selected_threat_model_scan_context(root.path(), &input).is_err());
    assert!(crate::capabilities::campaign::capture_batch_equivalence(
        root.path(),
        &input,
        &crate::V2Config::default(),
        &crate::ModuleRegistry::with_v2_builtins(),
    )
    .is_err());
    std::fs::remove_file(&path).unwrap();
    assert!(selected_threat_model_scan_context(root.path(), &input).is_err());
    assert!(
        inspect_threat_model_digest(root.path(), &input["threatModelDigestRef"], &reference)
            .is_err()
    );
}

#[test]
fn a_foreign_target_or_invalid_projection_hash_is_rejected_even_with_a_valid_blob_hash() {
    let (root, reference, mut input) = fixture();
    let original =
        inspect_threat_model_digest(root.path(), &input["threatModelDigestRef"], &reference)
            .unwrap();
    let other = tempfile::tempdir().unwrap();
    let mut foreign = original.clone();
    foreign.target = other.path().to_string_lossy().into_owned();
    input["threatModelDigestRef"] =
        json!(crate::scan::save_threat_model_digest(root.path(), &foreign).unwrap());
    assert!(selected_threat_model_scan_context(root.path(), &input)
        .unwrap_err()
        .to_string()
        .contains("different target"));
    let mut invalid = original;
    invalid.preview["sha256"] = json!("wrong");
    input["threatModelDigestRef"] =
        json!(crate::scan::save_threat_model_digest(root.path(), &invalid).unwrap());
    assert!(selected_threat_model_scan_context(root.path(), &input)
        .unwrap_err()
        .to_string()
        .contains("text hash"));
}

#[test]
fn runtime_free_and_explicitly_omitted_context_do_not_create_a_projection() {
    let (root, reference, _) = fixture();
    let mut native = json!({"taskMode":"manual","tasks":["secret-scan"],"threatModelRef":reference,"triage":false,"verify":false,"autoPatch":false});
    freeze_threat_model_digest(root.path(), &mut native, "sast:scan").unwrap();
    assert!(native.get("threatModelDigestRef").is_none());
    let mut omitted = json!({"threatModelRef":null});
    freeze_threat_model_digest(root.path(), &mut omitted, "agentic-sast:scan").unwrap();
    assert!(omitted.get("threatModelDigestRef").is_none());
}

#[test]
fn legacy_approved_model_work_requires_a_replacement_without_touching_history() {
    let (root, _, mut input) = fixture();
    input
        .as_object_mut()
        .unwrap()
        .remove("threatModelDigestRef");
    input["allowanceRef"] = json!({"synthetic":"no request made"});
    assert!(selected_threat_model_scan_context(root.path(), &input)
        .unwrap_err()
        .to_string()
        .contains("replacement plan"));
    input.as_object_mut().unwrap().remove("allowanceRef");
    assert!(selected_threat_model_scan_context(root.path(), &input)
        .unwrap()
        .unwrap()
        .contains("ALPHA"));
}

#[test]
fn size_limits_and_reference_shape_are_checked_before_loading_text() {
    let (root, reference, input) = fixture();
    let original =
        inspect_threat_model_digest(root.path(), &input["threatModelDigestRef"], &reference)
            .unwrap();
    let mut huge = original;
    huge.preview["text"] = json!("x".repeat(512 * 1024 + 1));
    assert!(crate::scan::save_threat_model_digest(root.path(), &huge)
        .unwrap_err()
        .to_string()
        .contains("512 KiB"));
    for value in [
        Value::Null,
        json!({}),
        json!({"schemaVersion":2,"object":input["threatModelDigestRef"]["object"]}),
    ] {
        assert!(inspect_threat_model_digest(root.path(), &value, &reference).is_err());
    }
    let mut oversize = input.clone();
    oversize["threatModelDigestRef"]["object"]["sizeBytes"] = json!(512 * 1024 + 1);
    assert!(selected_threat_model_scan_context(root.path(), &oversize).is_err());
}

#[test]
fn all_consumers_declare_and_preserve_the_same_reference_in_prepared_dispatch() {
    let (root, _, input) = fixture();
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
    for tool in [
        "sast:scan",
        "agentic-sast:scan",
        "triage:run",
        "threat-model:read",
    ] {
        let prepared = registry.prepare_dispatch_input(tool, json!({"threatModelRef":input["threatModelRef"],"threatModelDigestRef":input["threatModelDigestRef"]}), &ctx, None).unwrap();
        assert_eq!(
            prepared.value()["threatModelDigestRef"],
            input["threatModelDigestRef"]
        );
    }
}
