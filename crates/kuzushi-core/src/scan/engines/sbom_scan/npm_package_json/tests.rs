use super::*;
use serde_json::json;

fn parse(value: Value) -> Result<Vec<PackageDependency>> {
    package_dependencies(
        Path::new("/owned"),
        Path::new("/owned/packages/child/package.json"),
        &value.to_string(),
    )
}

#[test]
fn non_object_documents_are_not_empty_package_inventories() {
    for value in [json!([]), Value::Null, json!(false), json!(42), json!("private-input")] {
        let error = parse(value).err().unwrap().to_string();
        assert!(error.contains("packages/child/package.json must contain a JSON object"), "{error}");
        assert!(!error.contains("private-input"));
    }
}

#[test]
fn every_supported_scope_requires_a_dependency_map() {
    for &scope in NPM_DEPENDENCY_SCOPES {
        for value in [Value::Null, json!([]), json!(true), json!(42), json!("private-input")] {
            let error = parse(json!({scope: value})).err().unwrap().to_string();
            assert!(error.contains(&format!("{scope} must be an object")), "{error}");
            assert!(!error.contains("private-input"));
        }
    }
}

#[test]
fn unsupported_versions_are_named_without_dumping_the_value() {
    for value in [Value::Null, json!(true), json!(42), json!([]), json!({}),
        json!({"version": ["private-input"]})] {
        let error = parse(json!({"dependencies": {"owned": value}})).err().unwrap().to_string();
        assert!(error.contains("dependencies.owned needs a string specification"), "{error}");
        assert!(error.contains("packages/child/package.json"));
        assert!(!error.contains("private-input"));
    }
}

#[test]
fn missing_or_empty_dependency_maps_remain_valid() {
    assert!(parse(json!({})).unwrap().is_empty());
    assert!(parse(json!({"dependencies": {}, "name": "owned"})).unwrap().is_empty());
}
