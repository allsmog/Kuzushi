use super::prelude::*;
use super::*;

pub fn evaluate_whitebox_suppressions(
    repo_root: impl AsRef<Path>,
    findings: &[Finding],
    suppressions: &[WhiteboxSuppressionRecord],
    now_unix: u64,
) -> WhiteboxSuppressionReport {
    let repo_root = repo_root.as_ref();
    let mut report = WhiteboxSuppressionReport {
        total_suppressions: suppressions.len(),
        active_suppressions: 0,
        suppressed_count: 0,
        suppressed_findings: Vec::new(),
        stale_suppressions: Vec::new(),
        expired_suppressions: Vec::new(),
        findings_remain_visible: true,
        audit_note:
            "whitebox-static suppressions annotate false-positive memory; audit/report output still includes suppressed findings"
                .to_string(),
    };

    for suppression in suppressions {
        if suppression.expires_at_unix <= now_unix {
            report
                .expired_suppressions
                .push(WhiteboxExpiredSuppression {
                    suppression_id: suppression.id.clone(),
                    expired_at_unix: suppression.expires_at_unix,
                    reason: suppression.reason.clone(),
                });
            continue;
        }

        report.active_suppressions += 1;
        let current_span = extract_source_span(
            repo_root,
            &suppression.scope.file_path,
            suppression.scope.start_line,
            suppression.scope.end_line,
        );
        let Ok(current_span) = current_span else {
            report.stale_suppressions.push(WhiteboxStaleSuppression {
                suppression_id: suppression.id.clone(),
                file_path: suppression.scope.file_path.clone(),
                start_line: suppression.scope.start_line,
                end_line: suppression.scope.end_line,
                expected_snippet_hash: suppression.scope.snippet_hash.clone(),
                current_snippet_hash: None,
                reason: "suppressed source span no longer resolves under the repository"
                    .to_string(),
            });
            continue;
        };
        if current_span.content_hash != suppression.scope.snippet_hash {
            report.stale_suppressions.push(WhiteboxStaleSuppression {
                suppression_id: suppression.id.clone(),
                file_path: suppression.scope.file_path.clone(),
                start_line: suppression.scope.start_line,
                end_line: suppression.scope.end_line,
                expected_snippet_hash: suppression.scope.snippet_hash.clone(),
                current_snippet_hash: Some(current_span.content_hash),
                reason: "suppressed source snippet hash changed".to_string(),
            });
            continue;
        }

        for finding in findings {
            if !suppression_matches_finding(suppression, finding, &current_span.content_hash) {
                continue;
            }
            report.suppressed_findings.push(WhiteboxSuppressionMatch {
                finding_fingerprint: finding.fingerprint.clone(),
                suppression_id: suppression.id.clone(),
                reason: suppression.reason.clone(),
                author: suppression.author.clone(),
                expires_at_unix: suppression.expires_at_unix,
                file_path: suppression.scope.file_path.clone(),
                start_line: suppression.scope.start_line,
                end_line: suppression.scope.end_line,
                snippet_hash: suppression.scope.snippet_hash.clone(),
            });
        }
    }

    report.suppressed_findings.sort_by(|left, right| {
        left.finding_fingerprint
            .cmp(&right.finding_fingerprint)
            .then_with(|| left.suppression_id.cmp(&right.suppression_id))
    });
    report.suppressed_findings.dedup();
    report.suppressed_count = report.suppressed_findings.len();
    report
}

pub fn findings_visible_with_whitebox_suppressions(findings: &[Finding]) -> Vec<Finding> {
    findings.to_vec()
}
