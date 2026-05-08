#[cfg(test)]
mod tests {
    use std::fs;

    use super::super::*;
    use crate::findings::{Severity, StaticProofState};

    fn finding() -> Finding {
        Finding::new_tool(
            "semgrep",
            "javascript.express.xss",
            "src/server.js",
            2,
            Some(2),
            Severity::High,
            "query data reaches html response",
        )
        .with_static_proof_state(StaticProofState::StaticallyRejected)
    }

    fn write_fixture(root: &Path, line: &str) {
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/server.js"),
            format!("const express = require('express');\n{line}\n"),
        )
        .unwrap();
    }

    #[test]
    fn whitebox_suppression_requires_evidence_reason_author_and_expiration() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture(temp.path(), "res.send(escapeHtml(req.query.name));");
        let finding = finding();
        let mut record = build_whitebox_suppression_for_finding_at(
            temp.path(),
            &finding,
            "escaped before response",
            "security@example.test",
            10,
            20,
        )
        .unwrap();

        record.reason.clear();
        assert!(validate_whitebox_suppression(&record)
            .unwrap_err()
            .to_string()
            .contains("reason"));

        record.reason = "escaped before response".to_string();
        record.author.clear();
        assert!(validate_whitebox_suppression(&record)
            .unwrap_err()
            .to_string()
            .contains("author"));

        record.author = "security@example.test".to_string();
        record.evidence.clear();
        assert!(validate_whitebox_suppression(&record)
            .unwrap_err()
            .to_string()
            .contains("requires evidence"));

        record.evidence.push(WhiteboxSuppressionEvidence {
            file_path: "src/server.js".to_string(),
            start_line: 2,
            end_line: 2,
            snippet_hash: record.scope.snippet_hash.clone(),
            snippet: None,
            description: "reviewed sanitizer".to_string(),
        });
        record.expires_at_unix = record.created_at_unix;
        assert!(validate_whitebox_suppression(&record)
            .unwrap_err()
            .to_string()
            .contains("expiration"));
    }

    #[test]
    fn whitebox_suppression_round_trips_under_v2_state() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture(temp.path(), "res.send(escapeHtml(req.query.name));");
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let finding = finding();
        let record = build_whitebox_suppression_for_finding_at(
            workspace.root(),
            &finding,
            "escaped before response",
            "security@example.test",
            100,
            200,
        )
        .unwrap();

        upsert_whitebox_suppression(&workspace, record.clone()).unwrap();
        let loaded = load_whitebox_suppressions(&workspace).unwrap();

        assert_eq!(
            whitebox_suppression_store_path(&workspace),
            workspace.state_dir().join("whitebox-suppressions.json")
        );
        assert_eq!(loaded, vec![record]);
    }

    #[test]
    fn whitebox_suppression_matches_until_snippet_hash_changes() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture(temp.path(), "res.send(escapeHtml(req.query.name));");
        let finding = finding();
        let record = build_whitebox_suppression_for_finding_at(
            temp.path(),
            &finding,
            "escaped before response",
            "security@example.test",
            100,
            200,
        )
        .unwrap();

        let report =
            evaluate_whitebox_suppressions(temp.path(), &[finding.clone()], &[record.clone()], 150);
        assert_eq!(report.suppressed_count, 1);
        assert!(report.stale_suppressions.is_empty());
        assert!(report.findings_remain_visible);

        write_fixture(temp.path(), "res.send(req.query.name);");
        let report = evaluate_whitebox_suppressions(temp.path(), &[finding], &[record], 150);
        assert_eq!(report.suppressed_count, 0);
        assert_eq!(report.stale_suppressions.len(), 1);
        assert_eq!(
            report.stale_suppressions[0].reason,
            "suppressed source snippet hash changed"
        );
    }

    #[test]
    fn whitebox_suppression_expiration_prevents_match() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture(temp.path(), "res.send(escapeHtml(req.query.name));");
        let finding = finding();
        let record = build_whitebox_suppression_for_finding_at(
            temp.path(),
            &finding,
            "escaped before response",
            "security@example.test",
            100,
            120,
        )
        .unwrap();

        let report = evaluate_whitebox_suppressions(temp.path(), &[finding], &[record], 121);

        assert_eq!(report.suppressed_count, 0);
        assert_eq!(report.expired_suppressions.len(), 1);
        assert_eq!(report.active_suppressions, 0);
    }

    #[test]
    fn suppressed_findings_remain_visible_for_audit_and_report_mode() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture(temp.path(), "res.send(escapeHtml(req.query.name));");
        let finding = finding();
        let record = build_whitebox_suppression_for_finding_at(
            temp.path(),
            &finding,
            "escaped before response",
            "security@example.test",
            100,
            200,
        )
        .unwrap();

        let report =
            evaluate_whitebox_suppressions(temp.path(), &[finding.clone()], &[record], 150);
        let visible = findings_visible_with_whitebox_suppressions(&[finding.clone()]);

        assert_eq!(report.suppressed_count, 1);
        assert!(report
            .audit_note
            .contains("still includes suppressed findings"));
        assert_eq!(visible, vec![finding]);
    }
}
