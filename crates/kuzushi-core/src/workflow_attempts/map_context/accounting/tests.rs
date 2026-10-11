use super::*;
use crate::capabilities::threat_model::{
    commit_threat_model_revision, threat_model_manifest_path, threat_model_object_path, ScopeRef,
    ThreatModelCommit, ThreatModelRevisionSource,
};
use crate::run_artifacts::*;
use serde_json::json;

fn allowance(id: &str) -> AllowanceReferenceV1 {
    serde_json::from_value(json!({"schemaVersion":1,"investigationId":id,"revision":1,"workId":"owned-context"})).unwrap()
}

fn copy(root: &Path, source: Option<&ThreatModelRef>, run: Option<&str>) -> ThreatModelRef {
    let document = json!({"version":"1","methodology":"stride","systemContext":"Owned accounting fixture",
        "dfd":{"nodes":[{"id":"app","name":"App"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{}});
    commit_threat_model_revision(root, &document, ThreatModelCommit {
        model_id: None, new_model: true, label: "Owned accounting fixture".into(),
        scope: ScopeRef::legacy_root(root, &format!("sha256:{}", "0".repeat(64))),
        methodology: "stride".into(), source: ThreatModelRevisionSource::Import,
        source_revision_id: source.map(|reference| reference.revision_id.clone()),
        run_id: run.map(str::to_owned), activate: Some(false), actor: "test".into(),
    }).unwrap().model_ref
}

fn context(root: &Path, reference: &ThreatModelRef) -> MapRunContext {
    MapRunContext { run_id: "owned-copy".into(), model_ref: Some(reference.clone()), allowance_ref: None,
        document: load_exact_threat_model(root, reference).unwrap() }
}

fn record(root: &Path, run: &str, reference: &ThreatModelRef, binding: &AllowanceReferenceV1) {
    let record = ToolRunRecord::new(root, run, "tool", "threat-model:import");
    let input = json!({"allowanceRef":binding});
    try_record_tool_run_started_with_reproducibility(record, &input, None, None, Vec::new()).unwrap();
    let observation = crate::run_lifecycle::RunObservationHandle::jsonl(root, run).unwrap();
    let call = crate::modules::ApplicationToolCall::start(observation.clone(), "threat-model:import", &input, None, None).unwrap();
    let output = json!({"ok":true,"status":"completed","allowanceRef":binding,
        "data":{"modelRef":reference,"document":load_exact_threat_model(root, reference).unwrap()}});
    let completion = call.completion_from_result(&Ok(output.clone()));
    try_record_tool_run_complete_settled(record, &output, &observation, completion).unwrap();
}

#[test]
fn immutable_copies_recover_recorded_spending_and_ignore_document_budget_claims() {
    let root = tempfile::tempdir().unwrap();
    let original = copy(root.path(), None, Some("origin"));
    record(root.path(), "origin", &original, &allowance("original-investigation"));
    let edited = copy(root.path(), Some(&original), None);
    let checked = copy(root.path(), Some(&edited), None);
    let mut selected = context(root.path(), &checked);
    selected.document["allowanceRef"] = json!(allowance("unrelated-document-claim"));
    assert_eq!(resolve(root.path(), &selected).unwrap(), Some(allowance("original-investigation")));
    selected.allowance_ref = Some(allowance("explicit-current-run"));
    assert_eq!(resolve(root.path(), &selected).unwrap(), selected.allowance_ref);
}

#[test]
fn known_origin_with_missing_or_corrupt_run_never_becomes_unbound_spending() {
    let root = tempfile::tempdir().unwrap();
    let original = copy(root.path(), None, Some("origin"));
    let checked = copy(root.path(), Some(&original), None);
    assert!(resolve(root.path(), &context(root.path(), &checked)).is_err());
    record(root.path(), "origin", &original, &allowance("original-investigation"));
    std::fs::write(run_dir(root.path(), "origin").join("result.json"), "{}\n").unwrap();
    assert!(resolve(root.path(), &context(root.path(), &checked)).is_err());
}

#[test]
fn a_producing_run_for_another_revision_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let original = copy(root.path(), None, Some("wrong-origin"));
    let unrelated = copy(root.path(), None, None);
    record(root.path(), "wrong-origin", &unrelated, &allowance("unrelated"));
    let checked = copy(root.path(), Some(&original), None);
    let error = resolve(root.path(), &context(root.path(), &checked)).unwrap_err();
    assert!(error.to_string().contains("different revision"), "{error:#}");
}

#[test]
fn missing_copy_origins_and_changed_objects_are_errors() {
    let root = tempfile::tempdir().unwrap();
    let original = copy(root.path(), None, None);
    let checked = copy(root.path(), Some(&original), None);
    let selected = context(root.path(), &checked);
    std::fs::write(threat_model_object_path(root.path(), &original.sha256).unwrap(), "{}\n").unwrap();
    assert!(resolve(root.path(), &selected).is_err());
    let path = threat_model_manifest_path(root.path());
    let mut manifest: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    manifest["models"].as_array_mut().unwrap().remove(0);
    std::fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let error = resolve(root.path(), &selected).unwrap_err();
    assert!(error.to_string().contains("copy origin is missing"), "{error:#}");
}

#[test]
fn cycles_and_excessive_copy_depth_are_finite_errors_while_legacy_roots_stay_unbound() {
    let root = tempfile::tempdir().unwrap();
    let original = copy(root.path(), None, None);
    assert_eq!(resolve(root.path(), &context(root.path(), &original)).unwrap(), None);
    let mut cursor = original.clone();
    for _ in 0..MAX_ACCOUNTING_COPY_DEPTH {
        cursor = copy(root.path(), Some(&cursor), None);
    }
    assert_eq!(resolve(root.path(), &context(root.path(), &cursor)).unwrap(), None);
    cursor = copy(root.path(), Some(&cursor), None);
    let selected = context(root.path(), &cursor);
    let error = resolve(root.path(), &selected).unwrap_err();
    assert!(error.to_string().contains("exceeds"));
    let path = threat_model_manifest_path(root.path());
    let mut manifest: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    manifest["models"][MAX_ACCOUNTING_COPY_DEPTH + 1]["revisions"][0]["sourceRevisionId"] = json!(cursor.revision_id);
    std::fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let error = resolve(root.path(), &selected).unwrap_err();
    assert!(error.to_string().contains("cycle"), "{error:#}");
}
