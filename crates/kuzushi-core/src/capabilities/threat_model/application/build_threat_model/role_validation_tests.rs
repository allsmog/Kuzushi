use super::*;

fn document() -> Value {
    json!({"version":"1","dfd":{"nodes":[{"id":"app","name":"App","type":"process","trustZone":"internal"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{}})
}

#[test]
fn generated_role_validation_runs_before_unscoped_query_acceptance() {
    let mut raw = document();
    raw["dfd"]["nodes"][0]["type"] = json!("data-type");
    let error = validate_threat_model_raw(raw.clone(), "stride").unwrap_err();
    assert!(error.to_string().contains("/dfd/nodes/0/type"));
    let legacy = normalize_document(raw, "stride").unwrap();
    assert_eq!(legacy["dfd"]["nodes"][0]["type"], "process");
}

#[test]
fn generated_role_validation_allows_canonical_roles_and_known_aliases() {
    let mut raw = document();
    raw["dfd"]["nodes"][0]["type"] = json!("externalEntity");
    assert_eq!(
        validate_threat_model_raw(raw.clone(), "stride").unwrap(),
        raw
    );
    let generated = normalize_threat_model_raw(raw, "stride").unwrap();
    assert_eq!(
        generated.document["dfd"]["nodes"][0]["type"],
        "external-entity"
    );
}

#[test]
fn generated_role_validation_checks_the_document_wrapper_used_by_normalization() {
    let mut raw = document();
    raw["dfd"]["nodes"][0]
        .as_object_mut()
        .unwrap()
        .remove("type");
    let wrapped = json!({"document":{"document":raw}});
    assert!(normalize_threat_model_raw(wrapped, "stride").is_err());
}
