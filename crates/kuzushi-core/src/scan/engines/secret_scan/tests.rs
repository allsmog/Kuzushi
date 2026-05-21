#[cfg(test)]
mod tests {
    use super::super::*;
    #[test]
    fn detects_curated_secret_shapes_and_redacts_evidence() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/config.env"),
            [
                "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
                "aws_secret_access_key = \"abcdEFGH1234567890abcdEFGH1234567890ABCD\"",
                "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
                "GITHUB_FINE_GRAINED=github_pat_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456789",
                "GITLAB_TOKEN=glpat-abcdefghijklmnopqrst",
                "NPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
                "password = \"aB3$eF6!hI9@kL2%mN5^\"",
            ]
            .join("\n"),
        )
        .unwrap();
        fs::create_dir(temp.path().join("node_modules")).unwrap();
        fs::write(
            temp.path().join("node_modules/ignored.env"),
            "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGH",
        )
        .unwrap();

        let report = scan_for_secrets(
            temp.path(),
            &SecretScanOptions::default(),
            &ScanCancellation::default(),
        )
        .unwrap();

        let rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(report.files_scanned, 1);
        assert!(rule_ids.contains("secret-scan/aws-access-key"));
        assert!(rule_ids.contains("secret-scan/aws-secret-key"));
        assert!(rule_ids.contains("secret-scan/github-pat"));
        assert!(rule_ids.contains("secret-scan/gitlab-pat"));
        assert!(rule_ids.contains("secret-scan/npm-access-token"));
        assert!(rule_ids.contains("secret-scan/generic-secret-assignment"));
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.rule_id == "secret-scan/github-pat")
                .count(),
            2
        );
        assert!(report
            .findings
            .iter()
            .all(|finding| !finding.evidence.contains("abcdEFGH1234567890")));
    }
}
