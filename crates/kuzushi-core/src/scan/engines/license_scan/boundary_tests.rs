use super::*;
use serde_json::json;

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("LICENSE"), "Owned inert text.\n").unwrap();
    root
}

fn manifest(root: &Path, directory: &str, value: serde_json::Value) {
    let directory = root.join(directory);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("package.json"), value.to_string()).unwrap();
}

fn header(root: &Path, path: &str, license: Option<&str>) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let text = license.map_or_else(
        || "// Owned inert source without a header.\n".into(),
        |license| format!("// SPDX-License-Identifier: {license}\n// Owned inert source.\n"),
    );
    fs::write(path, text).unwrap();
}

fn mismatches(report: &LicenseScanReport) -> Vec<&LicenseScanFinding> {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "license-scan/spdx-header-mismatch")
        .collect()
}

#[test]
fn each_package_uses_its_own_manifest_for_header_comparison() {
    let root = fixture();
    manifest(
        root.path(),
        "client",
        json!({"name":"client","license":"MIT"}),
    );
    manifest(
        root.path(),
        "service",
        json!({"name":"service","license":"Apache-2.0"}),
    );
    header(root.path(), "client/src/example.rs", Some("MIT"));
    header(root.path(), "service/src/example.rs", Some("Apache-2.0"));

    let report = scan_licenses(root.path(), &ScanCancellation::default()).unwrap();
    assert_eq!(report.manifests_scanned, 2);
    assert!(mismatches(&report).is_empty(), "{:#?}", report.findings);
}

#[test]
fn unrelated_matching_manifest_cannot_hide_a_local_header_mismatch() {
    let root = fixture();
    manifest(
        root.path(),
        "client",
        json!({"name":"client","license":"MIT"}),
    );
    manifest(
        root.path(),
        "service",
        json!({"name":"service","license":"Apache-2.0"}),
    );
    header(root.path(), "client/src/example.rs", Some("MIT"));
    header(root.path(), "service/src/example.rs", Some("MIT"));

    let report = scan_licenses(root.path(), &ScanCancellation::default()).unwrap();
    let findings = mismatches(&report);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].file_path, "service/src/example.rs");
    assert!(findings[0].evidence.contains("apache-2.0"));
}

#[test]
fn missing_package_license_does_not_borrow_an_ancestor_declaration() {
    let root = fixture();
    manifest(root.path(), "", json!({"name":"parent","license":"MIT"}));
    manifest(root.path(), "child", json!({"name":"child"}));
    header(root.path(), "child/example.rs", Some("Apache-2.0"));

    let report = scan_licenses(root.path(), &ScanCancellation::default()).unwrap();
    assert!(mismatches(&report).is_empty());
    assert!(report.findings.iter().any(|finding| {
        finding.rule_id == "license-scan/missing-license"
            && finding.file_path == "child/package.json"
    }));
}

#[test]
fn private_package_is_a_separate_header_boundary() {
    let root = fixture();
    manifest(root.path(), "", json!({"name":"parent","license":"MIT"}));
    manifest(
        root.path(),
        "private",
        json!({"name":"private","private":true}),
    );
    header(root.path(), "private/example.rs", Some("Apache-2.0"));

    let report = scan_licenses(root.path(), &ScanCancellation::default()).unwrap();
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
}

#[test]
fn sources_outside_any_package_do_not_use_a_sibling_declaration() {
    let root = fixture();
    manifest(
        root.path(),
        "client",
        json!({"name":"client","license":"MIT"}),
    );
    header(root.path(), "client/example.rs", Some("MIT"));
    header(root.path(), "shared/example.rs", Some("Apache-2.0"));

    let report = scan_licenses(root.path(), &ScanCancellation::default()).unwrap();
    assert!(mismatches(&report).is_empty());
}

#[test]
fn multiple_local_declarations_do_not_arbitrarily_select_one_license() {
    let root = fixture();
    manifest(root.path(), "", json!({"name":"owned","license":"MIT"}));
    fs::write(
        root.path().join("Cargo.toml"),
        "[package]\nname='owned'\nlicense='Apache-2.0'\n",
    )
    .unwrap();
    header(root.path(), "first.rs", Some("MIT"));
    header(root.path(), "second.rs", Some("Apache-2.0"));

    let report = scan_licenses(root.path(), &ScanCancellation::default()).unwrap();
    assert!(mismatches(&report).is_empty());
}

#[test]
fn required_headers_still_apply_inside_unknown_and_private_packages() {
    let root = fixture();
    manifest(root.path(), "unknown", json!({"name":"unknown"}));
    manifest(
        root.path(),
        "private",
        json!({"name":"private","private":true}),
    );
    header(root.path(), "unknown/example.rs", None);
    header(root.path(), "private/example.rs", None);

    let report = scan_licenses_with_options(
        root.path(),
        &ScanCancellation::default(),
        LicenseScanOptions {
            require_source_spdx_headers: true,
        },
    )
    .unwrap();
    let paths = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "license-scan/missing-spdx-header")
        .map(|finding| finding.file_path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(paths, ["private/example.rs", "unknown/example.rs"]);
}

#[test]
fn child_declaration_applies_to_its_nested_sources() {
    let root = fixture();
    manifest(root.path(), "", json!({"name":"parent","license":"MIT"}));
    manifest(
        root.path(),
        "child",
        json!({"name":"child","license":"Apache-2.0"}),
    );
    header(
        root.path(),
        "child/src/nested/example.rs",
        Some("Apache-2.0"),
    );

    let report = scan_licenses(root.path(), &ScanCancellation::default()).unwrap();
    assert!(mismatches(&report).is_empty());
}
