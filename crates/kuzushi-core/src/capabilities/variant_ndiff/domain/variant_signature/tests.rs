use super::*;

fn signature() -> Value {
    json!({"source":"Owned input metadata","sink":"Owned output metadata",
        "missingGuard":"Owned scope condition","description":"Labeled owned draft. No defect is claimed.",
        "languages":["rust"],"keywords":["owned-marker"]})
}

#[test]
fn complete_draft_and_legacy_guard_alias_preserve_their_contents() {
    let mut value = signature();
    value["extraMetadata"] = json!({"owned":true});
    assert_eq!(validate_variant_signature(value.clone()).unwrap(), value);
    let guard = value
        .as_object_mut()
        .unwrap()
        .remove("missingGuard")
        .unwrap();
    value["missing_guard"] = guard;
    assert_eq!(validate_variant_signature(value.clone()).unwrap(), value);
}

#[test]
fn empty_or_incomplete_objects_are_not_successful_patterns() {
    for invalid in [json!({}), json!([]), Value::Null] {
        assert!(validate_variant_signature(invalid).is_err());
    }
    for key in [
        "source",
        "sink",
        "missingGuard",
        "description",
        "languages",
        "keywords",
    ] {
        let mut value = signature();
        value.as_object_mut().unwrap().remove(key);
        assert!(validate_variant_signature(value).is_err(), "{key}");
    }
}

#[test]
fn text_and_list_resource_bounds_are_enforced() {
    for invalid in [json!(" "), json!(42), json!("x".repeat(4097))] {
        let mut value = signature();
        value["source"] = invalid;
        assert!(validate_variant_signature(value).is_err());
    }
    for invalid in [
        json!([]),
        json!([1]),
        json!([""]),
        json!(["x".repeat(129)]),
        json!(vec!["x"; 33]),
    ] {
        let mut value = signature();
        value["keywords"] = invalid;
        assert!(validate_variant_signature(value).is_err());
    }
}
