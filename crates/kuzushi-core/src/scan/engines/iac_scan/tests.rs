#[cfg(test)]
mod tests {
    use super::super::*;
    use tempfile::tempdir;

    #[test]
    fn scans_dockerfile_github_actions_and_terraform() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("Dockerfile"),
            "FROM node:latest\nCOPY . /app\nUSER root\n",
        )
        .unwrap();
        fs::create_dir_all(temp.path().join(".github/workflows")).unwrap();
        fs::write(
            temp.path().join(".github/workflows/ci.yml"),
            "on: pull_request_target\npermissions: write-all\nrun: echo ${{ github.event.pull_request.title }}\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("main.tf"),
            "cidr_blocks = [\"0.0.0.0/0\"]\nacl = \"public-read\"\n",
        )
        .unwrap();

        let report = scan_iac(
            temp.path(),
            &IacScanOptions::default(),
            &ScanCancellation::default(),
        )
        .unwrap();
        let rules = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();

        assert!(rules.contains(&"iac-scan/dockerfile-floating-image"));
        assert!(rules.contains(&"iac-scan/dockerfile-root-user"));
        assert!(rules.contains(&"iac-scan/actions-pull-request-target"));
        assert!(rules.contains(&"iac-scan/actions-write-all-permissions"));
        assert!(rules.contains(&"iac-scan/terraform-public-ingress"));
        assert!(rules.contains(&"iac-scan/terraform-public-s3-acl"));
        assert_eq!(report.files_scanned, 3);
        assert_eq!(
            report.findings[0].to_core_finding().static_proof_state,
            Some(StaticProofState::SignalOnly)
        );
    }

    #[test]
    fn kind_filter_limits_scanned_manifest_family() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("Dockerfile"), "FROM node:latest\n").unwrap();
        fs::write(
            temp.path().join("main.tf"),
            "cidr_blocks = [\"0.0.0.0/0\"]\n",
        )
        .unwrap();

        let report = scan_iac(
            temp.path(),
            &IacScanOptions {
                kind: IacScanKind::Terraform,
                ..IacScanOptions::default()
            },
            &ScanCancellation::default(),
        )
        .unwrap();

        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].rule_id,
            "iac-scan/terraform-public-ingress"
        );
    }

    #[test]
    fn dockerfile_flags_implicit_latest_base_images() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("Dockerfile"),
            "FROM --platform=linux/amd64 ubuntu AS base\nFROM registry.local:5000/app\nFROM scratch\nFROM node:20\n",
        )
        .unwrap();

        let report = scan_iac(
            temp.path(),
            &IacScanOptions {
                kind: IacScanKind::Dockerfile,
                ..IacScanOptions::default()
            },
            &ScanCancellation::default(),
        )
        .unwrap();
        let unpinned = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "iac-scan/dockerfile-unpinned-image")
            .collect::<Vec<_>>();

        assert_eq!(unpinned.len(), 2);
        assert!(unpinned
            .iter()
            .any(|finding| finding.evidence == "FROM --platform=linux/amd64 ubuntu AS base"));
        assert!(unpinned
            .iter()
            .any(|finding| finding.evidence == "FROM registry.local:5000/app"));
    }

    #[test]
    fn github_actions_flags_mutable_external_action_references() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join(".github/workflows")).unwrap();
        fs::write(
            temp.path().join(".github/workflows/ci.yml"),
            r#"jobs:
  test:
    steps:
      - uses: actions/checkout@main
      - uses: docker://alpine:latest
      - uses: ./local-action
      - uses: actions/setup-node@v4
"#,
        )
        .unwrap();

        let report = scan_iac(
            temp.path(),
            &IacScanOptions {
                kind: IacScanKind::GithubActions,
                ..IacScanOptions::default()
            },
            &ScanCancellation::default(),
        )
        .unwrap();
        let evidence = report
            .findings
            .iter()
            .map(|finding| finding.evidence.as_str())
            .collect::<Vec<_>>();

        assert_eq!(report.findings.len(), 2);
        assert!(evidence.contains(&"actions/checkout@main"));
        assert!(evidence.contains(&"docker://alpine:latest"));
        assert!(report.findings.iter().all(|finding| {
            finding.rule_id == "iac-scan/actions-mutable-action-reference"
                && finding.severity == Severity::Medium
        }));
    }

    #[test]
    fn github_actions_flags_sensitive_write_permission_scopes() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join(".github/workflows")).unwrap();
        fs::write(
            temp.path().join(".github/workflows/release.yml"),
            r#"permissions:
  contents: write
  id-token: write
  issues: read
"#,
        )
        .unwrap();

        let report = scan_iac(
            temp.path(),
            &IacScanOptions {
                kind: IacScanKind::GithubActions,
                ..IacScanOptions::default()
            },
            &ScanCancellation::default(),
        )
        .unwrap();
        let evidence = report
            .findings
            .iter()
            .map(|finding| finding.evidence.as_str())
            .collect::<Vec<_>>();

        assert_eq!(report.findings.len(), 2);
        assert!(evidence.contains(&"contents: write"));
        assert!(evidence.contains(&"id-token: write"));
        assert!(report.findings.iter().all(|finding| {
            finding.rule_id == "iac-scan/actions-write-permission-scope"
                && finding.severity == Severity::Medium
        }));
    }

    #[test]
    fn missing_target_failure_is_actionable() {
        let temp = tempdir().unwrap();
        let err = scan_iac(
            &temp.path().join("missing"),
            &IacScanOptions::default(),
            &ScanCancellation::default(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("iac-scan: target does not exist"));
    }

    #[test]
    fn cancellation_is_observed_before_file_analysis() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("main.tf"),
            "cidr_blocks = [\"0.0.0.0/0\"]\n",
        )
        .unwrap();
        let cancellation = ScanCancellation::default();
        cancellation.cancel();

        let err = scan_iac(temp.path(), &IacScanOptions::default(), &cancellation)
            .unwrap_err()
            .to_string();

        assert!(err.contains("iac-scan scan cancelled"));
    }
}
