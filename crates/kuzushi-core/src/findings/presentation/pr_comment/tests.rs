#[cfg(test)]
mod tests {
    use super::super::*;

    fn make_finding(severity: Severity, fp: &str, title: &str) -> Finding {
        Finding {
            id: None,
            scan_id: None,
            fingerprint: fp.to_string(),
            rule_id: "test/rule".to_string(),
            title: title.to_string(),
            severity,
            file_path: "src/x.rs".to_string(),
            start_line: 1,
            end_line: None,
            message: String::new(),
            tool: "test".to_string(),
            actor_fingerprint: None,
            static_proof_state: None,
            triage: None,
            verification: None,
            created_at: String::new(),
            vuln_source: None,
            dedup_key: None,
            evidence: Vec::new(),
        }
    }

    #[test]
    fn header_uses_repo_name_and_run_url() {
        let input = PrCommentInput {
            repo_name: Some("acme-api".to_string()),
            run_url: Some("https://example/run/1".to_string()),
            ..PrCommentInput::default()
        };
        let body = build_pr_comment(&input);
        assert!(body.contains("### 🔐 Kuzushi scan · `acme-api`"));
        assert!(body.contains("[run](https://example/run/1)"));
    }

    #[test]
    fn empty_findings_render_no_findings_block() {
        let body = build_pr_comment(&PrCommentInput::default());
        assert!(body.contains("**No findings triaged.**"));
        assert!(body.contains("_No true-positive findings._"));
    }

    #[test]
    fn findings_table_includes_severity_badge_and_alias() {
        let input = PrCommentInput {
            findings: vec![
                make_finding(Severity::High, "fhigh", "ssrf in admin"),
                make_finding(Severity::Critical, "fcrit", "sqli"),
            ],
            cost_usd: 0.42,
            ..PrCommentInput::default()
        };
        let body = build_pr_comment(&input);
        assert!(body.contains("F-0001"));
        assert!(body.contains("F-0002"));
        assert!(body.contains("🟥 CRIT"));
        assert!(body.contains("🟧 HIGH"));
        assert!(body.contains("$0.42"));
        // critical-first ordering
        let crit_pos = body.find("F-0001").unwrap();
        let high_pos = body.find("F-0002").unwrap();
        assert!(crit_pos < high_pos);
        // critical row should be the SQLI finding (sorted to top).
        let crit_row_start = body[crit_pos..].find("|").unwrap() + crit_pos;
        let crit_row_end = body[crit_row_start..].find('\n').unwrap() + crit_row_start;
        assert!(body[crit_row_start..crit_row_end].contains("sqli"));
    }

    #[test]
    fn diff_section_preserves_global_stable_aliases() {
        let mut critical = make_finding(Severity::Critical, "fcrit", "global critical");
        critical.file_path = "src/old.rs".to_string();
        let input = PrCommentInput {
            findings: vec![
                critical,
                make_finding(Severity::High, "fhigh", "changed high"),
            ],
            changed_files: vec!["src/x.rs".to_string()],
            ..PrCommentInput::default()
        };
        let body = build_pr_comment(&input);

        let new_section = body
            .split("#### New in this PR")
            .nth(1)
            .and_then(|section| section.split("#### Top findings").next())
            .unwrap_or("");

        assert!(new_section.contains("F-0002"));
        assert!(!new_section.contains("F-0001"));
    }

    #[test]
    fn top_n_truncates_and_emits_truncation_note() {
        let findings: Vec<Finding> = (0..15)
            .map(|i| make_finding(Severity::Medium, &format!("fp-{i:02}"), "x"))
            .collect();
        let input = PrCommentInput {
            findings,
            top_n: Some(5),
            ..PrCommentInput::default()
        };
        let body = build_pr_comment(&input);
        assert!(body.contains("**10** more findings"));
        assert!(body.contains("Top findings (5 of 15)"));
    }

    #[test]
    fn changed_files_emits_new_in_pr_block() {
        let mut finding = make_finding(Severity::High, "fp1", "diff hit");
        finding.file_path = "src/admin.rs".to_string();
        let input = PrCommentInput {
            findings: vec![finding],
            changed_files: vec!["src/admin.rs".to_string()],
            ..PrCommentInput::default()
        };
        let body = build_pr_comment(&input);
        assert!(body.contains("New in this PR"));
        assert!(body.contains("🆕 **1 new in this PR**"));
    }

    #[test]
    fn footer_includes_optional_stamps_truncated() {
        let input = PrCommentInput {
            findings: (0..3)
                .map(|i| make_finding(Severity::Low, &format!("f-{i}"), "x"))
                .collect(),
            kuzushi_version: Some("0.24.0-alpha.0".to_string()),
            model: Some("openai:gpt-5.5".to_string()),
            git_sha: Some("abcdef1234567890".to_string()),
            run_id: Some("12345678-aaaa-bbbb-cccc-ddddeeeeffff".to_string()),
            top_n: Some(2),
            ..PrCommentInput::default()
        };
        let body = build_pr_comment(&input);
        assert!(body.contains("Kuzushi 0.24.0-alpha.0"));
        assert!(body.contains("model `openai:gpt-5.5`"));
        assert!(body.contains("git `abcdef1`"));
        assert!(body.contains("run `12345678`"));
        assert!(body.contains("Showing top 2; 1 truncated"));
    }
}
