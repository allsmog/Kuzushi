use super::*;

#[test]
fn typed_projection_keeps_the_serialized_receipt_contract() {
    let mut inspection = HygieneInspection::new(Path::new("owned-fixture"), 11, 3);
    inspection.receipt.manifests_attempted = 2;
    inspection.receipt.manifests_inspected = 1;
    inspection.receipt.content_bytes_reserved = u64::MAX;
    inspection.receipt.gaps = vec!["Owned \"manifest\"\n東京 could not be inspected".into()];
    let result = inspection.to_tool_json();
    assert_eq!(result["status"], "partial");
    let mut actual = result["data"]["inspection"].clone();
    actual.as_object_mut().unwrap().remove("limits");
    actual.as_object_mut().unwrap().remove("exclusions");
    assert_eq!(actual, serde_json::to_value(&inspection.receipt).unwrap());
}
