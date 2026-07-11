use super::*;

#[test]
fn license_scan_detects_missing_and_copyleft_manifest_licenses() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"name":"demo","license":"AGPL-3.0"}"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("LICENSE"),
        "GNU Affero General Public License\nVersion 3\n",
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();
    let rule_ids = report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 2);
    assert!(rule_ids.contains(&"license-scan/strong-copyleft"));
    assert!(rule_ids.contains(&"license-scan/missing-license"));
    assert!(report.output().contains("license-scan: 2 findings"));
}

#[test]
fn license_scan_skips_private_package_json_license_absence() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"name":"private-demo","private":true}"#,
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_reads_package_json_license_type_objects() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"name":"demo","license":{"type":"MIT","url":"https://opensource.org/licenses/MIT"}}"#,
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_reads_pyproject_license_tables() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("pyproject.toml"),
        "[project]\nname = \"demo\"\nlicense = { text = \"MIT\" }\n",
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_accepts_pyproject_license_file_metadata() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("pyproject.toml"),
        "[project]\nname = \"demo\"\nlicense = { file = \"LICENSE\" }\n",
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-license"));
}

#[test]
fn license_scan_reads_composer_license_arrays() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("composer.json"),
        r#"{"name":"demo/app","license":["MIT","Apache-2.0"]}"#,
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-license"));
    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-license-file"));
    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/license-file-mismatch"));
}

#[test]
fn license_scan_flags_composer_copyleft_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("composer.json"),
        r#"{"name":"demo/app","license":"GPL-3.0-only"}"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("LICENSE"),
        "GNU General Public License\nVersion 3\n",
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/strong-copyleft"));
}

#[test]
fn license_scan_flags_additional_weak_copyleft_manifest_licenses() {
    for license in ["MPL-2.0", "EPL-2.0", "CDDL-1.0"] {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            format!(r#"{{"name":"demo","license":"{license}"}}"#),
        )
        .unwrap();
        fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();

        let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == "license-scan/weak-copyleft"),
            "{license} should be flagged as weak copyleft"
        );
    }
}

#[test]
fn license_scan_does_not_treat_plain_words_as_license_identifiers() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"name":"demo","license":"sample project license"}"#,
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "sample project license\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/weak-copyleft"));
}

#[test]
fn license_scan_reads_dotnet_package_license_expressions() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Demo.csproj"),
        r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageId>Demo.Package</PackageId>
    <PackageLicenseExpression>MIT</PackageLicenseExpression>
  </PropertyGroup>
</Project>
"#,
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_flags_dotnet_package_missing_license_expression() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Demo.fsproj"),
        r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageId>Demo.Package</PackageId>
  </PropertyGroup>
</Project>
"#,
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-license"));
}

#[test]
fn license_scan_skips_dotnet_application_projects() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("App.vbproj"),
        r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
</Project>
"#,
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_reads_maven_pom_license_names() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("pom.xml"),
        r#"<project>
  <licenses>
    <license>
      <name>MIT</name>
    </license>
  </licenses>
</project>
"#,
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_flags_maven_pom_copyleft_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("pom.xml"),
        r#"<project>
  <licenses>
    <license>
      <name>GNU General Public License v3.0</name>
    </license>
  </licenses>
</project>
"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("LICENSE"),
        "GNU General Public License\nVersion 3\n",
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/strong-copyleft"));
}

#[test]
fn license_scan_reads_pubspec_yaml_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("pubspec.yaml"),
        "name: demo\nversion: 0.1.0\nlicense: MIT\n",
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_flags_pubspec_yaml_missing_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("pubspec.yaml"),
        "name: demo\nversion: 0.1.0\n",
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-license"));
}

#[test]
fn license_scan_reads_haxelib_json_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("haxelib.json"),
        r#"{"name":"demo","license":"MIT","dependencies":{"utest":"1.13.2"}}"#,
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_flags_haxelib_json_missing_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("haxelib.json"),
        r#"{"name":"demo","dependencies":{"utest":"1.13.2"}}"#,
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-license"));
}

#[test]
fn license_scan_reads_gleam_toml_licences() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("gleam.toml"),
        "name = \"demo\"\nversion = \"1.0.0\"\nlicences = [\"MIT\"]\n",
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_flags_gleam_toml_missing_licences() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("gleam.toml"),
        "name = \"demo\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-license"));
}

#[test]
fn license_scan_reads_shard_yml_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("shard.yml"),
        "name: demo\nversion: 0.1.0\nlicense: MIT\n",
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_flags_shard_yaml_missing_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("shard.yaml"),
        "name: demo\nversion: 0.1.0\n",
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-license"));
}

#[test]
fn license_scan_reads_bower_json_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("bower.json"),
        r#"{"name":"demo","license":"MIT","dependencies":{"jquery":"3.7.1"}}"#,
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_flags_bower_json_missing_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("bower.json"),
        r#"{"name":"demo","dependencies":{"jquery":"3.7.1"}}"#,
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-license"));
}

#[test]
fn license_scan_reads_elm_json_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("elm.json"),
        r#"{"type":"package","name":"demo/package","version":"1.0.0","license":"MIT"}"#,
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_flags_elm_json_missing_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("elm.json"),
        r#"{"type":"package","name":"demo/package","version":"1.0.0"}"#,
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-license"));
}

#[test]
fn license_scan_reads_vcpkg_json_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("vcpkg.json"),
        r#"{"name":"demo","version":"1.0.0","license":"MIT","dependencies":["zlib"]}"#,
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_flags_vcpkg_json_missing_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("vcpkg.json"),
        r#"{"name":"demo","version":"1.0.0","dependencies":["zlib"]}"#,
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-license"));
}

#[test]
fn license_scan_reads_nimble_license_assignment() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("demo.nimble"),
        "version = \"0.1.0\"\nlicense = \"MIT\"\nrequires \"jester\"\n",
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_flags_nimble_missing_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("demo.nimble"),
        "version = \"0.1.0\"\nrequires \"jester\"\n",
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-license"));
}

#[test]
fn license_scan_reads_opam_license_field() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("demo.opam"),
        "opam-version: \"2.0\"\nlicense: \"MIT\"\ndepends: [ \"dune\" ]\n",
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_flags_opam_missing_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("demo.opam"),
        "opam-version: \"2.0\"\ndepends: [ \"dune\" ]\n",
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-license"));
}

#[test]
fn license_scan_reads_cabal_license_field() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("demo.cabal"),
        "cabal-version: 3.0\nname: demo\nlicense: BSD-3-Clause\n",
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "BSD 3-Clause License\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_flags_cabal_missing_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("demo.cabal"),
        "cabal-version: 3.0\nname: demo\n",
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-license"));
}

#[test]
fn license_scan_reads_r_description_license_field() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("DESCRIPTION"),
        "Package: demo\nVersion: 0.1.0\nLicense: MIT\n",
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn license_scan_flags_r_description_missing_license() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("DESCRIPTION"),
        "Package: demo\nVersion: 0.1.0\n",
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-license"));
}

#[test]
fn license_scan_flags_missing_repository_license_file() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"name":"demo","license":"MIT"}"#,
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-license-file"));
}

#[test]
fn license_scan_flags_manifest_license_file_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"name":"demo","license":"MIT"}"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("LICENSE"),
        "Apache License\nVersion 2.0, January 2004\n",
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "license-scan/license-file-mismatch")
        .unwrap();

    assert_eq!(finding.file_path, "LICENSE");
    assert_eq!(finding.license.as_deref(), Some("MIT"));
}

#[test]
fn license_scan_flags_spdx_header_manifest_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"name":"demo","license":"MIT"}"#,
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();
    fs::create_dir_all(temp.path().join("src")).unwrap();
    fs::write(
        temp.path().join("src/lib.rs"),
        "// SPDX-License-Identifier: Apache-2.0\nfn main() {}\n",
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "license-scan/spdx-header-mismatch")
        .unwrap();

    assert_eq!(finding.file_path, "src/lib.rs");
    assert_eq!(finding.license.as_deref(), Some("Apache-2.0"));
}

#[test]
fn license_scan_accepts_matching_spdx_header() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"name":"demo","license":"MIT"}"#,
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();
    fs::write(
        temp.path().join("index.js"),
        "// SPDX-License-Identifier: MIT\nconsole.log('ok')\n",
    )
    .unwrap();

    let report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();

    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/spdx-header-mismatch"));
}

#[test]
fn license_scan_can_require_source_spdx_headers() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"name":"demo","license":"MIT"}"#,
    )
    .unwrap();
    fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();
    fs::create_dir_all(temp.path().join("src")).unwrap();
    fs::write(temp.path().join("src/lib.rs"), "pub fn demo() {}\n").unwrap();

    let default_report = scan_licenses(temp.path(), &ScanCancellation::default()).unwrap();
    let strict_report = scan_licenses_with_options(
        temp.path(),
        &ScanCancellation::default(),
        LicenseScanOptions {
            require_source_spdx_headers: true,
        },
    )
    .unwrap();

    assert!(!default_report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "license-scan/missing-spdx-header"));
    assert!(strict_report.findings.iter().any(|finding| finding.rule_id
        == "license-scan/missing-spdx-header"
        && finding.file_path == "src/lib.rs"));
}

#[test]
fn license_scan_core_findings_are_signal_only() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Cargo.toml"),
        "[package]\nname = \"demo\"\n",
    )
    .unwrap();

    let findings = LicenseScanScanner
        .scan(temp.path(), &ScanCancellation::default())
        .unwrap();

    assert_eq!(findings[0].tool, "license-scan");
    assert_eq!(findings[0].rule_id, "license-scan/missing-license");
    assert_eq!(
        findings[0].static_proof_state,
        Some(StaticProofState::SignalOnly)
    );
}
