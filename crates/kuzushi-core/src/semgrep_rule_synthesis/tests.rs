#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::findings::{Severity, StaticProofState};
    use crate::static_evidence::{StaticEvidenceNode, StaticEvidenceNodeKind};

    #[test]
    fn semgrep_rule_synthesis_validates_disabled_candidate_from_confirmed_finding() {
        let finding = Finding::new_tool(
            "agentic-sast",
            "js/sql-injection",
            "src/users.ts",
            3,
            Some(3),
            Severity::High,
            "req.query reaches db.query without sanitizer",
        )
        .with_static_proof_state(StaticProofState::StaticallyConfirmed);
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        store
            .upsert_node(
                &StaticEvidenceNode::new(
                    StaticEvidenceNodeKind::CodeSpan,
                    "confirmed SQL flow",
                    "const q = req.query.q;\nreturn db.query(`select * from users where name = ${q}`);",
                )
                .with_finding_fingerprint(finding.fingerprint.clone())
                .with_source_span("src/users.ts", 2, Some(3)),
            )
            .unwrap();
        let fixtures = vec![
            SemgrepRuleFixture::positive(
                "positive",
                "const q = req.query.q;\nreturn db.query(`select * from users where name = ${q}`);",
            )
            .for_finding(finding.fingerprint.clone()),
            SemgrepRuleFixture::negative(
                "negative",
                "const q = sanitize(req.query.q);\nreturn db.query(`select * from users where name = ${q}`);",
            )
            .for_finding(finding.fingerprint.clone()),
        ];

        let report =
            synthesize_candidate_semgrep_rules(&[finding], Some(&store), &fixtures).unwrap();

        assert_eq!(report.count, 1);
        assert_eq!(report.validation_passed, 1);
        let candidate = &report.candidates[0];
        assert!(candidate.validation.passed);
        assert!(candidate.ready_for_manual_enable);
        assert!(candidate.disabled);
        assert!(!candidate.enabled);
        assert!(candidate.rule_yaml.contains("disabled: true"));
        assert!(candidate.rule_yaml.contains("enabled: false"));
        assert!(candidate
            .rule_yaml
            .contains("kuzushiWhiteboxCandidate: true"));
        assert!(candidate.rule_yaml.contains("validationPassed: true"));
    }

    #[test]
    fn semgrep_rule_synthesis_ignores_non_confirmed_findings() {
        let unconfirmed = Finding::new_tool(
            "agentic-sast",
            "js/sql-injection",
            "src/users.ts",
            3,
            Some(3),
            Severity::High,
            "req.query reaches db.query",
        )
        .with_static_proof_state(StaticProofState::SourceSinkLinked);

        let report = synthesize_candidate_semgrep_rules(&[unconfirmed], None, &[]).unwrap();

        assert_eq!(report.count, 0);
        assert!(report.candidates.is_empty());
    }

    #[test]
    fn semgrep_rule_synthesis_keeps_failed_fixture_candidate_disabled() {
        let finding = Finding::new_tool(
            "agentic-sast",
            "js/command-injection",
            "src/admin.ts",
            5,
            Some(5),
            Severity::High,
            "req.body reaches exec(cmd) without validation",
        )
        .with_static_proof_state(StaticProofState::StaticallyConfirmed);
        let fixtures = vec![
            SemgrepRuleFixture::positive("positive", "const cmd = req.body.cmd;\nexec(cmd);")
                .for_finding(finding.fingerprint.clone()),
            SemgrepRuleFixture::negative(
                "negative-still-unsafe",
                "const cmd = req.body.cmd;\nexec(cmd);",
            )
            .for_finding(finding.fingerprint.clone()),
        ];

        let report = synthesize_candidate_semgrep_rules(&[finding], None, &fixtures).unwrap();

        assert_eq!(report.count, 1);
        assert_eq!(report.validation_passed, 0);
        let candidate = &report.candidates[0];
        assert!(!candidate.validation.passed);
        assert!(!candidate.ready_for_manual_enable);
        assert!(candidate.disabled);
        assert!(!candidate.enabled);
        assert_eq!(
            candidate.validation.unexpected_negative_matches,
            vec!["negative-still-unsafe".to_string()]
        );
        assert!(candidate.rule_yaml.contains("validationPassed: false"));
    }

    #[test]
    fn semgrep_language_for_path_covers_supported_extensions() {
        let cases = [
            ("app.js", "javascript"),
            ("component.tsx", "typescript"),
            ("worker.py", "python"),
            ("main.go", "go"),
            ("lib.rs", "rust"),
            ("Service.java", "java"),
            ("Handler.kt", "kotlin"),
            ("job.rb", "ruby"),
            ("index.php", "php"),
            ("native.c", "c"),
            ("header.hpp", "cpp"),
            ("Dockerfile", "generic"),
        ];
        for (path, language) in cases {
            assert_eq!(semgrep_language_for_path(path), language);
        }
    }
}
