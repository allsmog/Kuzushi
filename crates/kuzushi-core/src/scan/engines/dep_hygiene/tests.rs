#[cfg(test)]
mod tests {
    use super::super::id::severity_from_cvss;
    use super::super::*;

    const PACKAGE_JSON: &str =
        include_str!("../../../../../../tests/fixtures/dep-hygiene/node/package.json");
    const PYPROJECT_TOML: &str =
        include_str!("../../../../../../tests/fixtures/dep-hygiene/python/pyproject.toml");
    const CARGO_TOML: &str =
        include_str!("../../../../../../tests/fixtures/dep-hygiene/rust/Cargo.toml");
    const GO_MOD: &str = include_str!("../../../../../../tests/fixtures/dep-hygiene/go/go.mod");

    #[test]
    fn analyzes_package_json_like_typescript_module() {
        let findings = analyze_manifest(
            ManifestKind::PackageJson,
            Path::new("/repo/package.json"),
            PACKAGE_JSON,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["lodash"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["express"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["axios"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["left-pad"].severity, DepHygieneSeverity::Low);
        assert_eq!(by_package["vitest"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("good-lib"));
        assert!(!by_package.contains_key("react"));
    }

    #[test]
    fn ignores_unparseable_package_json() {
        let findings = analyze_manifest(
            ManifestKind::PackageJson,
            Path::new("/repo/package.json"),
            "{ this is not json",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn analyzes_pyproject_toml_like_typescript_module() {
        let findings = analyze_manifest(
            ManifestKind::PyprojectToml,
            Path::new("/repo/pyproject.toml"),
            PYPROJECT_TOML,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["requests"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["flask"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["loguru"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["httpx"].severity, DepHygieneSeverity::Medium);
        assert!(!by_package.contains_key("django"));
        assert!(!by_package.contains_key("pydantic"));
        assert!(!by_package.contains_key("sqlalchemy"));
        assert!(!by_package.contains_key("python"));
    }

    #[test]
    fn analyzes_cargo_toml_like_typescript_module() {
        let findings = analyze_manifest(
            ManifestKind::CargoToml,
            Path::new("/repo/Cargo.toml"),
            CARGO_TOML,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["serde"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["tokio"].severity, DepHygieneSeverity::Medium);
        assert!(!by_package.contains_key("anyhow"));
        assert!(!by_package.contains_key("proptest"));
    }

    #[test]
    fn analyzes_go_mod_like_typescript_module() {
        let findings = analyze_manifest(ManifestKind::GoMod, Path::new("/repo/go.mod"), GO_MOD);
        let by_package = finding_map(&findings);

        assert!(!by_package.contains_key("github.com/example/safe"));
        assert_eq!(
            by_package["github.com/example/commit-pin"].severity,
            DepHygieneSeverity::Medium
        );
        assert_eq!(
            by_package["github.com/example/floating"].severity,
            DepHygieneSeverity::High
        );
        assert_eq!(
            by_package["github.com/example/zero"].severity,
            DepHygieneSeverity::High
        );
    }

    #[test]
    fn check_dependency_hygiene_reads_root_manifests() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("package.json"), PACKAGE_JSON).unwrap();
        fs::write(tmp.path().join("pyproject.toml"), PYPROJECT_TOML).unwrap();
        fs::write(tmp.path().join("Cargo.toml"), CARGO_TOML).unwrap();
        fs::write(tmp.path().join("go.mod"), GO_MOD).unwrap();

        let report = check_dependency_hygiene(tmp.path()).unwrap();

        assert_eq!(report.count, 14);
        assert!(report.output().contains("dep-hygiene: 14 risky specifiers"));
    }

    #[test]
    fn scanner_converts_report_to_core_findings() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();
        let scanner = DepHygieneScanner;
        let findings = scanner
            .scan(tmp.path(), &ScanCancellation::default())
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "dep-hygiene");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].file_path, "package.json");
        assert_eq!(
            findings[0].static_proof_state,
            Some(StaticProofState::SignalOnly)
        );
        assert!(findings[0].message.contains("lodash@latest"));
    }

    #[test]
    fn missing_target_error_is_actionable() {
        let tmp = tempfile::tempdir().unwrap();
        let err = check_dependency_hygiene(&tmp.path().join("missing"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("dep-hygiene: target does not exist"));
    }

    fn finding_map(
        findings: &[DepHygieneFinding],
    ) -> std::collections::BTreeMap<String, DepHygieneFinding> {
        findings
            .iter()
            .map(|finding| (finding.package_name.clone(), finding.clone()))
            .collect()
    }

    /// Captured shape of a real `cargo audit --json` document, narrowed to
    /// the fields the parser reads. Two advisories with different CVSS
    /// inputs to exercise score parsing and the textual fallback.
    const CARGO_AUDIT_FIXTURE: &str = r#"{
      "database": { "advisory_count": 0 },
      "lockfile": { "dependency_count": 1 },
      "settings": {},
      "vulnerabilities": {
        "found": true,
        "count": 2,
        "list": [
          {
            "advisory": {
              "id": "RUSTSEC-2020-0071",
              "package": "time",
              "title": "Potential segfault in localtime_r invocations",
              "cvss": "6.2"
            },
            "versions": { "patched": [">=0.2.23"], "unaffected": [] },
            "affected": null,
            "package": {
              "name": "time",
              "version": "0.1.40",
              "source": "registry+https://github.com/rust-lang/crates.io-index"
            }
          },
          {
            "advisory": {
              "id": "RUSTSEC-2099-0001",
              "package": "fakecrate",
              "title": "Hypothetical critical RCE",
              "cvss": "CRITICAL/AV:N/AC:L/PR:N"
            },
            "package": {
              "name": "fakecrate",
              "version": "1.0.0",
              "source": "registry+https://github.com/rust-lang/crates.io-index"
            }
          }
        ]
      },
      "warnings": {}
    }"#;

    #[test]
    fn parse_cargo_audit_emits_finding_per_advisory() {
        let findings = parse_cargo_audit_output(CARGO_AUDIT_FIXTURE);
        assert_eq!(findings.len(), 2);
        let by_rule: std::collections::BTreeMap<_, _> = findings
            .iter()
            .map(|f| (f.rule_id.clone(), f.clone()))
            .collect();

        let time_finding = &by_rule["RUSTSEC-2020-0071"];
        assert_eq!(time_finding.tool, "cargo-audit");
        assert_eq!(time_finding.severity, Severity::Medium);
        assert_eq!(time_finding.file_path, "Cargo.lock");
        assert!(time_finding.message.contains("time@0.1.40"));
        assert!(time_finding.message.contains("Potential segfault"));

        let fake_finding = &by_rule["RUSTSEC-2099-0001"];
        assert_eq!(fake_finding.severity, Severity::Critical);
        assert!(fake_finding.message.contains("fakecrate@1.0.0"));
    }

    #[test]
    fn parse_cargo_audit_returns_empty_for_invalid_json() {
        assert!(parse_cargo_audit_output("{ this is not json").is_empty());
    }

    #[test]
    fn parse_cargo_audit_returns_empty_when_no_vulnerabilities_key() {
        assert!(parse_cargo_audit_output(r#"{"vulnerabilities":{"found":false}}"#).is_empty());
    }

    #[test]
    fn cargo_audit_severity_buckets_match_cvss_score() {
        assert_eq!(severity_from_cvss(Some("9.8")), Severity::Critical);
        assert_eq!(severity_from_cvss(Some("7.5")), Severity::High);
        assert_eq!(severity_from_cvss(Some("5.0")), Severity::Medium);
        assert_eq!(severity_from_cvss(Some("2.1")), Severity::Low);
        assert_eq!(severity_from_cvss(Some("0.0")), Severity::Unknown);
        assert_eq!(severity_from_cvss(None), Severity::Medium);
        // Vector-style CVSS strings fall back to keyword detection.
        assert_eq!(
            severity_from_cvss(Some("CVSS:3.1/AV:N/AC:L/PR:N/C:H/I:H/A:H")),
            Severity::High
        );
        assert_eq!(severity_from_cvss(Some("medium")), Severity::Medium);
        assert_eq!(
            severity_from_cvss(Some("CVSS:3.1/AV:N/AC:L/C:L")),
            Severity::Low
        );
        assert_eq!(
            severity_from_cvss(Some("unscored vector")),
            Severity::Medium
        );
    }

    #[test]
    fn cargo_audit_scanner_no_lockfile_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        // No Cargo.lock written. The scanner must short-circuit cleanly,
        // even when cargo-audit is missing from PATH (binary_available
        // is never reached because the lockfile gate fires first).
        let scanner = CargoAuditScanner;
        let findings = scanner
            .scan(tmp.path(), &ScanCancellation::default())
            .unwrap();
        assert!(findings.is_empty());
    }
}
