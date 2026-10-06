use super::*;
use crate::capabilities::threat_model::{
    commit_threat_model_revision, load_active_threat_model, threat_model_object_path, ScopeRef,
    ThreatModelCommit, ThreatModelRevisionSource,
};
use crate::run_artifacts::{
    try_record_tool_run_complete_settled, try_record_tool_run_started_with_reproducibility,
    ToolRunRecord,
};
use serde_json::json;

fn commit(root: &Path, label: &str) -> (ThreatModelRef, Value) {
    let document = json!({"version":"1", "methodology":"stride", "title":label,
        "dfd":{"nodes":[{"id":"app","name":label}],"flows":[],"trustBoundaries":[]},
        "threats":[],"summary":{}});
    let result = commit_threat_model_revision(
        root,
        &document,
        ThreatModelCommit {
            model_id: None,
            new_model: true,
            label: label.into(),
            scope: ScopeRef::legacy_root(root, &format!("sha256:{}", "1".repeat(64))),
            methodology: "stride".into(),
            source: ThreatModelRevisionSource::Import,
            source_revision_id: None,
            run_id: None,
            activate: Some(true),
            actor: "test".into(),
        },
    )
    .unwrap();
    (result.model_ref, document)
}

fn record(root: &Path, run: &str, data: Value) {
    let record = ToolRunRecord::new(root, run, "tool", "threat-model:build");
    try_record_tool_run_started_with_reproducibility(record, &json!({}), None, None, Vec::new())
        .unwrap();
    let observation = crate::run_lifecycle::RunObservationHandle::jsonl(root, run).unwrap();
    let call = crate::modules::ApplicationToolCall::start(
        observation.clone(),
        "threat-model:build",
        &json!({}),
        None,
        None,
    )
    .unwrap();
    let output = json!({"ok":true,"status":"completed","data":data});
    let completion = call.completion_from_result(&Ok(output.clone()));
    try_record_tool_run_complete_settled(record, &output, &observation, completion).unwrap();
}

#[test]
fn map_context_uses_recorded_revision_even_after_another_model_is_active() {
    let root = tempfile::tempdir().unwrap();
    let (first, doc) = commit(root.path(), "Alpha");
    record(
        root.path(),
        "map-model",
        json!({"modelRef":first,"document":doc}),
    );
    let (active, _) = commit(root.path(), "Beta");
    record(
        root.path(),
        "map-inventory",
        json!({"snapshot":{"filesIndexed":2}}),
    );
    let refs = ["map-model", "map-inventory"].map(str::to_string);
    let context = load_map_run_context(root.path(), &refs).unwrap().unwrap();
    assert_eq!(context.model_ref, Some(first));
    assert_eq!(context.document["title"], "Alpha");
    assert_eq!(context.run_id, "map-model");
    assert_eq!(context.allowance_ref, None);
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        active
    );
}

#[test]
fn no_model_result_never_inherits_active_context() {
    let root = tempfile::tempdir().unwrap();
    commit(root.path(), "Unrelated active context");
    record(
        root.path(),
        "map-inventory",
        json!({"snapshot":{"filesIndexed":2}}),
    );
    assert!(load_map_run_context(root.path(), &["map-inventory".into()])
        .unwrap()
        .is_none());
    assert!(load_map_run_context(root.path(), &[]).unwrap().is_none());
}

#[test]
fn authenticated_pre_revision_document_remains_readable() {
    let root = tempfile::tempdir().unwrap();
    let (_, document) = commit(root.path(), "Historical");
    record(
        root.path(),
        "historical-model",
        json!({"document":document}),
    );
    let context = load_map_run_context(root.path(), &["historical-model".into()])
        .unwrap()
        .unwrap();
    assert_eq!(context.model_ref, None);
    assert_eq!(context.document, document);
}

#[test]
fn altered_result_and_corrupt_or_missing_objects_never_fall_back() {
    let root = tempfile::tempdir().unwrap();
    let (reference, document) = commit(root.path(), "Alpha");
    record(
        root.path(),
        "map-model",
        json!({"modelRef":reference,"document":document}),
    );
    commit(root.path(), "Beta");
    let refs = ["map-model".into()];
    let object = threat_model_object_path(root.path(), &reference.sha256).unwrap();
    std::fs::write(&object, "{}").unwrap();
    assert!(load_map_run_context(root.path(), &refs).is_err());
    std::fs::remove_file(&object).unwrap();
    assert!(load_map_run_context(root.path(), &refs).is_err());
    std::fs::write(
        crate::run_artifact_path(root.path(), "map-model", "result.json"),
        "{}",
    )
    .unwrap();
    let error = load_map_run_context(root.path(), &refs).unwrap_err();
    assert!(
        error.to_string().contains("cannot be authenticated"),
        "{error:#}"
    );
}

#[test]
fn invalid_reference_and_contradictory_document_are_errors() {
    let root = tempfile::tempdir().unwrap();
    let (reference, document) = commit(root.path(), "Alpha");
    record(
        root.path(),
        "invalid-ref",
        json!({"modelRef":"active","document":document}),
    );
    assert!(load_map_run_context(root.path(), &["invalid-ref".into()]).is_err());
    record(
        root.path(),
        "mismatch",
        json!({"modelRef":reference,"document":{"title":"Wrong"}}),
    );
    let error = load_map_run_context(root.path(), &["mismatch".into()]).unwrap_err();
    assert!(error.to_string().contains("disagrees"));
}

#[test]
fn missing_and_degraded_run_streams_are_unavailable() {
    let root = tempfile::tempdir().unwrap();
    assert!(load_map_run_context(root.path(), &["missing-run".into()]).is_err());
    record(root.path(), "damaged-run", json!({}));
    use std::io::Write;
    let mut stream = std::fs::OpenOptions::new()
        .append(true)
        .open(crate::run_artifact_path(
            root.path(),
            "damaged-run",
            "items.jsonl",
        ))
        .unwrap();
    writeln!(stream, "broken").unwrap();
    let error = load_map_run_context(root.path(), &["damaged-run".into()]).unwrap_err();
    assert!(error.to_string().contains("degraded"));
}

#[test]
fn present_but_invalid_accounting_provenance_never_becomes_an_unbound_map() {
    let root = tempfile::tempdir().unwrap();
    let (reference, document) = commit(root.path(), "Alpha");
    for provenance in [
        Value::Null,
        json!({"schemaVersion":2,"investigationId":"study","revision":1,"workId":"map"}),
        json!({"schemaVersion":1,"investigationId":"study","revision":0,"workId":"map"}),
    ] {
        let result =
            json!({"data":{"modelRef":reference,"document":document},"allowanceRef":provenance});
        assert!(context_from_result(root.path(), "map-model", &result).is_err());
    }
}
