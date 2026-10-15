use super::*;

fn observation() -> Value {
    json!({"filePath":"hello.txt","severity":"INFO","confidence":"MEDIUM"})
}

#[test]
fn missing_or_malformed_arrays_cannot_be_clean_searches() {
    for value in [
        json!({}),
        json!([]),
        json!({"variants":null}),
        json!({"variants":{}}),
    ] {
        assert!(validate_variant_observations(value).is_err());
    }
    assert_eq!(
        validate_variant_observations(json!({"variants":[]})).unwrap(),
        json!({"variants":[]})
    );
}

#[test]
fn malformed_rows_cannot_be_silently_dropped() {
    for row in [
        json!(null),
        json!(1),
        json!({}),
        json!({"filePath":" ","severity":"INFO","confidence":"HIGH"}),
    ] {
        assert!(validate_variant_observations(json!({"variants":[row]})).is_err());
    }
}

#[test]
fn source_lines_are_positive_and_do_not_overflow() {
    for line in [
        json!(0),
        json!(-1),
        json!(4294967296_u64),
        json!(1.5),
        json!("1"),
    ] {
        let mut row = observation();
        row["startLine"] = line;
        assert!(validate_variant_observations(json!({"variants":[row]})).is_err());
    }
    let mut row = observation();
    row["startLine"] = json!(u32::MAX);
    assert!(validate_variant_observations(json!({"variants":[row]})).is_ok());
}

#[test]
fn legacy_path_alias_and_extra_metadata_are_retained() {
    let value = json!({"variants":[{"file_path":"hello.txt","severity":"WARNING",
        "confidence":"LOW","ownedMetadata":true}],"extra":"retained"});
    assert_eq!(validate_variant_observations(value.clone()).unwrap(), value);
}
