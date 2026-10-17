use super::*;

fn first_case(context: Value) -> Value {
    json!({
        "threatModelRef": context,
        "threatModelDigestRef": {"hash":"boundary-scanner-text"},
        "scanScopeRef": {"scopeId":"app"},
        "scanContextRef": {"hash":"frozen-repository-source"},
        "tasks":["secret-scan"], "taskMode":"manual", "paths":[]
    })
}

#[test]
fn changed_common_context_retires_only_the_boundary_projection() {
    let first = first_case(json!({"revisionId":"override","sha256":"first"}));
    let original = first.clone();
    let common = json!({"revisionId":"common","sha256":"second"});
    let draft = common_draft_input(&first, &common).unwrap();
    assert_eq!(draft["threatModelRef"], common);
    assert!(draft.get("threatModelDigestRef").is_none());
    assert!(draft.get("scanScopeRef").is_none());
    assert_eq!(draft["scanContextRef"], first["scanContextRef"]);
    assert_eq!(draft["tasks"], first["tasks"]);
    assert_eq!(first, original, "The recorded case must remain immutable");
}

#[test]
fn identical_context_preserves_its_exact_frozen_scanner_text() {
    let reference = json!({"revisionId":"same","sha256":"same"});
    let first = first_case(reference.clone());
    let draft = common_draft_input(&first, &reference).unwrap();
    assert_eq!(draft["threatModelDigestRef"], first["threatModelDigestRef"]);
    assert!(draft.get("scanScopeRef").is_none());
}

#[test]
fn changing_common_to_omission_never_reuses_the_override_text() {
    let first = first_case(json!({"revisionId":"override"}));
    let draft = common_draft_input(&first, &Value::Null).unwrap();
    assert!(draft["threatModelRef"].is_null());
    assert!(draft.get("threatModelDigestRef").is_none());
}

#[test]
fn restoring_common_after_an_omitted_case_requires_fresh_projection() {
    let mut first = first_case(Value::Null);
    first
        .as_object_mut()
        .unwrap()
        .remove("threatModelDigestRef");
    let common = json!({"revisionId":"common"});
    let draft = common_draft_input(&first, &common).unwrap();
    assert_eq!(draft["threatModelRef"], common);
    assert!(draft.get("threatModelDigestRef").is_none());
}

#[test]
fn legacy_alias_cannot_override_the_restored_common_selection() {
    let mut first = first_case(json!({"revisionId":"override"}));
    first["threat_model_ref"] = json!({"revisionId":"legacy"});
    let draft = common_draft_input(&first, &Value::Null).unwrap();
    assert!(draft.get("threat_model_ref").is_none());
    assert!(common_draft_input(&json!([]), &Value::Null).is_err());
}
