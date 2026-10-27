use super::support::dispatch;
use serde_json::json;

#[test]
fn shared_dispatch_keeps_export_omission_warning_before_inspection_receipt() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("Cargo.lock"),
        r#"version = 3
[[package]]
name = "app"
version = "1.0.0"
dependencies = ["library 1.0.0", "missing 1.0.0"]
[[package]]
name = "library"
version = "1.0.0"
[[package]]
name = "library"
version = "2.0.0"
"#,
    )
    .unwrap();
    let output = dispatch(root.path(), json!({}));
    assert_eq!(output["data"]["spdxExport"]["omittedRelationshipCount"], 2);
    let summary = output["output"].as_str().unwrap();
    assert!(
        summary.contains("SPDX and CycloneDX omitted 2 dependency relationships"),
        "{summary}"
    );
    assert!(
        summary.contains("Captured dependency inputs: 1 file;"),
        "{summary}"
    );
    assert!(
        summary.find("SPDX and CycloneDX omitted").unwrap()
            < summary.find("Captured dependency inputs").unwrap()
    );
}
