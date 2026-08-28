use super::{extract_cwe, is_attack_chain_finding, Finding, ReviewDecisionRecord, TriageAuthor};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingIdentityAuditIssueKind {
    MultipleSourceSignatures,
    MultipleSymbols,
    NonOverlappingSpans,
    MultipleRuleFamilies,
    AttackChainMixing,
    ConflictingHumanDecisions,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FindingIdentityAuditGroup {
    pub identity_id: String,
    pub finding_ids: Vec<i64>,
    pub fingerprints: Vec<String>,
    pub issues: Vec<FindingIdentityAuditIssueKind>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FindingIdentityAuditReport {
    pub findings_scanned: usize,
    pub identity_groups_scanned: usize,
    pub suspicious_groups: Vec<FindingIdentityAuditGroup>,
}

/// Read-only safety audit over a persisted finding corpus. The report is
/// deliberately suspicious rather than self-healing: it provides migration
/// evidence and never rekeys, folds, suppresses, or changes a decision.
pub fn audit_finding_identities(
    findings: &[Finding],
    decisions: &[ReviewDecisionRecord],
) -> FindingIdentityAuditReport {
    let groups = identity_groups(findings);
    let suspicious_groups = groups
        .iter()
        .filter_map(|(identity_id, group)| audit_group(identity_id, group, decisions))
        .collect();
    FindingIdentityAuditReport {
        findings_scanned: findings.len(),
        identity_groups_scanned: groups.len(),
        suspicious_groups,
    }
}

fn identity_groups(findings: &[Finding]) -> BTreeMap<String, Vec<&Finding>> {
    let mut groups = BTreeMap::<String, Vec<&Finding>>::new();
    for finding in findings {
        if let Some(identity_id) = finding.identity_id.as_ref() {
            groups.entry(identity_id.clone()).or_default().push(finding);
        }
    }
    groups
}

fn audit_group(
    identity_id: &str,
    findings: &[&Finding],
    decisions: &[ReviewDecisionRecord],
) -> Option<FindingIdentityAuditGroup> {
    let issues = group_issues(identity_id, findings, decisions);
    if issues.is_empty() {
        return None;
    }
    let mut finding_ids = findings
        .iter()
        .filter_map(|finding| finding.id)
        .collect::<Vec<_>>();
    finding_ids.sort_unstable();
    finding_ids.dedup();
    let mut fingerprints = findings
        .iter()
        .map(|finding| finding.fingerprint.clone())
        .collect::<Vec<_>>();
    fingerprints.sort();
    fingerprints.dedup();
    Some(FindingIdentityAuditGroup {
        identity_id: identity_id.to_string(),
        finding_ids,
        fingerprints,
        issues,
    })
}

fn group_issues(
    identity_id: &str,
    findings: &[&Finding],
    decisions: &[ReviewDecisionRecord],
) -> Vec<FindingIdentityAuditIssueKind> {
    let mut issues = Vec::new();
    push_issue(
        &mut issues,
        multiple_source_signatures(findings),
        FindingIdentityAuditIssueKind::MultipleSourceSignatures,
    );
    push_issue(
        &mut issues,
        multiple_symbols(findings),
        FindingIdentityAuditIssueKind::MultipleSymbols,
    );
    push_issue(
        &mut issues,
        has_non_overlapping_spans(findings),
        FindingIdentityAuditIssueKind::NonOverlappingSpans,
    );
    push_issue(
        &mut issues,
        multiple_rule_families(findings),
        FindingIdentityAuditIssueKind::MultipleRuleFamilies,
    );
    push_issue(
        &mut issues,
        mixes_chain_and_component(findings),
        FindingIdentityAuditIssueKind::AttackChainMixing,
    );
    push_issue(
        &mut issues,
        conflicting_human_decisions(identity_id, decisions),
        FindingIdentityAuditIssueKind::ConflictingHumanDecisions,
    );
    issues
}

fn multiple_symbols(findings: &[&Finding]) -> bool {
    findings
        .iter()
        .filter_map(|finding| finding.normalized_symbol_locator())
        .collect::<BTreeSet<_>>()
        .len()
        > 1
}

fn push_issue(
    issues: &mut Vec<FindingIdentityAuditIssueKind>,
    present: bool,
    issue: FindingIdentityAuditIssueKind,
) {
    if present {
        issues.push(issue);
    }
}

fn multiple_source_signatures(findings: &[&Finding]) -> bool {
    findings
        .iter()
        .flat_map(|finding| {
            finding.source_signature.iter().chain(
                finding
                    .sources
                    .iter()
                    .map(|source| &source.source_signature),
            )
        })
        .filter(|signature| !signature.trim().is_empty())
        .collect::<BTreeSet<_>>()
        .len()
        > 1
}

fn has_non_overlapping_spans(findings: &[&Finding]) -> bool {
    let mut spans = BTreeMap::<String, Vec<(u32, u32)>>::new();
    for finding in findings.iter().filter(|finding| finding.start_line > 0) {
        let path = crate::identity::finding_identity::normalize_path(&finding.file_path);
        spans.entry(path).or_default().push((
            finding.start_line,
            finding.end_line.unwrap_or(finding.start_line),
        ));
    }
    spans.values().any(|spans| {
        spans.iter().enumerate().any(|(index, left)| {
            spans[index + 1..]
                .iter()
                .any(|right| left.1 < right.0 || right.1 < left.0)
        })
    })
}

fn multiple_rule_families(findings: &[&Finding]) -> bool {
    findings
        .iter()
        .map(|finding| rule_family(finding))
        .collect::<BTreeSet<_>>()
        .len()
        > 1
}

fn rule_family(finding: &Finding) -> String {
    extract_cwe(&finding.rule_id, &finding.title, &finding.message)
        .unwrap_or_else(|| {
            finding
                .rule_id
                .split(['.', '/', ':'])
                .find(|part| !part.trim().is_empty())
                .unwrap_or(&finding.rule_id)
                .to_string()
        })
        .to_ascii_lowercase()
}

fn mixes_chain_and_component(findings: &[&Finding]) -> bool {
    let chain_count = findings
        .iter()
        .filter(|finding| is_attack_chain_finding(finding))
        .count();
    chain_count > 0 && chain_count < findings.len()
}

fn conflicting_human_decisions(identity_id: &str, decisions: &[ReviewDecisionRecord]) -> bool {
    decisions
        .iter()
        .filter(|record| record.identity_id.as_deref() == Some(identity_id))
        .filter(|record| record.decision.author == TriageAuthor::Human)
        .filter(|record| record.decision.verdict.is_terminal())
        .map(|record| record.decision.verdict.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        > 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{ReviewDecision, ReviewDecisionVerdict};

    fn finding(id: i64, line: u32, signature: &str) -> Finding {
        Finding {
            id: Some(id),
            identity_id: Some("fi_shared".to_string()),
            fingerprint: format!("fp_{id}"),
            rule_id: "CWE-89".to_string(),
            file_path: "src/db.rs".to_string(),
            start_line: line,
            end_line: Some(line),
            source_signature: Some(signature.to_string()),
            ..Finding::default()
        }
    }

    fn human_decision(id: i64, verdict: ReviewDecisionVerdict) -> ReviewDecisionRecord {
        ReviewDecisionRecord {
            id,
            finding_id: id,
            identity_id: Some("fi_shared".to_string()),
            decision: ReviewDecision {
                verdict,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "reviewed".to_string(),
                dismiss_reason: None,
                actor: Some("operator".to_string()),
            },
            triage_verdict: None,
            created_at: "2026-08-27T00:00:00Z".to_string(),
            provenance: None,
        }
    }

    #[test]
    fn audit_reports_unsafe_group_signals_without_mutating_input() {
        let findings = vec![finding(1, 10, "db.rs:10:89"), finding(2, 90, "db.rs:90:89")];
        let decisions = vec![
            human_decision(1, ReviewDecisionVerdict::Confirmed),
            human_decision(2, ReviewDecisionVerdict::RejectedFalsePositive),
        ];

        let report = audit_finding_identities(&findings, &decisions);

        assert_eq!(report.findings_scanned, 2);
        assert_eq!(report.identity_groups_scanned, 1);
        assert_eq!(report.suspicious_groups.len(), 1);
        assert_eq!(
            report.suspicious_groups[0].issues,
            vec![
                FindingIdentityAuditIssueKind::MultipleSourceSignatures,
                FindingIdentityAuditIssueKind::NonOverlappingSpans,
                FindingIdentityAuditIssueKind::ConflictingHumanDecisions,
            ]
        );
        assert_eq!(findings[0].source_signature.as_deref(), Some("db.rs:10:89"));
    }

    #[test]
    fn audit_ignores_a_single_consistent_identity_observation() {
        let findings = vec![finding(1, 10, "db.rs:10:89")];
        let report = audit_finding_identities(&findings, &[]);

        assert_eq!(report.identity_groups_scanned, 1);
        assert!(report.suspicious_groups.is_empty());
    }

    #[test]
    fn audit_flags_multiple_symbols_inside_one_identity() {
        let mut first = finding(1, 10, "same-signature");
        first.symbol_locator = Some("crate::db::execute".to_string());
        let mut second = finding(2, 10, "same-signature");
        second.symbol_locator = Some("crate::db::prepare".to_string());

        let report = audit_finding_identities(&[first, second], &[]);

        assert_eq!(
            report.suspicious_groups[0].issues,
            vec![FindingIdentityAuditIssueKind::MultipleSymbols]
        );
    }
}
