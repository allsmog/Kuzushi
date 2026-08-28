use super::*;
use crate::findings::{FindingIdentityBasis, Severity};

fn finding(fingerprint: &str, tool: &str, rule: &str, line: u32) -> Finding {
    Finding {
        id: Some(i64::from(line)),
        fingerprint: fingerprint.to_string(),
        rule_id: rule.to_string(),
        title: "sink".to_string(),
        severity: Severity::High,
        file_path: "src/app.rs".to_string(),
        start_line: line,
        message: "sink".to_string(),
        tool: tool.to_string(),
        ..Finding::default()
    }
}

#[test]
fn report_proposes_cross_tool_span_cluster_without_mutating_findings() {
    let findings = vec![
        finding("one", "semgrep", "CWE-78", 20),
        finding("two", "codeql", "CWE-78", 20),
    ];
    let unchanged = findings.clone();

    let report = derive_cross_tool_cluster_report(&findings);

    assert!(report.report_only);
    assert_eq!(findings, unchanged);
    assert_eq!(report.candidate_clusters.len(), 1);
    assert_eq!(
        report.candidate_clusters[0].strongest_basis,
        CrossToolClusterBasis::OverlappingEvidenceSpan
    );
}

#[test]
fn attack_chains_never_enter_component_clusters() {
    let component = finding("component", "semgrep", "CWE-78", 20);
    let mut chain = finding("chain", "chains", "chains/model", 20);
    chain.identity_id = Some("shared".to_string());

    let report = derive_cross_tool_cluster_report(&[component, chain]);

    assert_eq!(report.attack_chains_excluded, 1);
    assert!(report.candidate_clusters.is_empty());
}

#[test]
fn validated_locator_outranks_span_and_same_tool_rows_do_not_cluster() {
    let mut semgrep = finding("one", "semgrep", "CWE-89", 12);
    let mut codeql = finding("two", "codeql", "CWE-89", 12);
    semgrep.identity_id = Some("fi_shared".to_string());
    codeql.identity_id = Some("fi_shared".to_string());
    semgrep.identity_basis = Some(FindingIdentityBasis::SourceLocator);
    codeql.identity_basis = Some(FindingIdentityBasis::SourceLocator);
    let same_tool = finding("three", "semgrep", "CWE-89", 12);

    let report = derive_cross_tool_cluster_report(&[semgrep, codeql, same_tool]);

    assert_eq!(report.candidate_clusters.len(), 2);
    assert!(report.candidate_clusters.iter().any(|cluster| {
        cluster.strongest_basis == CrossToolClusterBasis::ValidatedSourceLocator
    }));
    assert!(report
        .candidate_clusters
        .iter()
        .all(|cluster| { cluster.members[0].tool != cluster.members[1].tool }));
}

#[test]
fn symbol_and_source_signature_precedes_span_and_proximity() {
    let mut semgrep = finding("one", "semgrep", "CWE-89", 10);
    let mut codeql = finding("two", "codeql", "CWE-89", 80);
    for finding in [&mut semgrep, &mut codeql] {
        finding.symbol_locator = Some("Database.execute".to_string());
        finding.source_signature = Some("source:stable-statement".to_string());
    }

    let report = derive_cross_tool_cluster_report(&[semgrep, codeql]);

    assert_eq!(report.candidate_clusters.len(), 1);
    assert_eq!(
        report.candidate_clusters[0].strongest_basis,
        CrossToolClusterBasis::SymbolAndSourceSignature
    );
    assert_eq!(
        report.candidate_clusters[0].members[0]
            .symbol_locator
            .as_deref(),
        Some("Database.execute")
    );
}

#[test]
fn symbol_match_requires_the_same_nonempty_source_signature() {
    let mut semgrep = finding("one", "semgrep", "CWE-89", 10);
    let mut codeql = finding("two", "codeql", "CWE-89", 80);
    semgrep.symbol_locator = Some("Database.execute".to_string());
    codeql.symbol_locator = Some("Database.execute".to_string());
    semgrep.source_signature = Some("source:first".to_string());
    codeql.source_signature = Some("source:second".to_string());

    let report = derive_cross_tool_cluster_report(&[semgrep, codeql]);

    assert!(report.candidate_clusters.is_empty());
}

#[test]
fn conservative_proximity_is_report_only_and_stops_after_three_lines() {
    let close = derive_cross_tool_cluster_report(&[
        finding("one", "semgrep", "CWE-22", 10),
        finding("two", "codeql", "CWE-22", 13),
    ]);
    let far = derive_cross_tool_cluster_report(&[
        finding("one", "semgrep", "CWE-22", 10),
        finding("two", "codeql", "CWE-22", 14),
    ]);

    assert_eq!(
        close.candidate_clusters[0].strongest_basis,
        CrossToolClusterBasis::ClassProximity
    );
    assert!(far.candidate_clusters.is_empty());
}

#[test]
fn proximity_never_transitively_clusters_incompatible_endpoints() {
    let report = derive_cross_tool_cluster_report(&[
        finding("one", "semgrep", "CWE-22", 10),
        finding("two", "codeql", "CWE-22", 13),
        finding("three", "bandit", "CWE-22", 16),
    ]);

    assert_eq!(report.candidate_clusters.len(), 2);
    assert!(report
        .candidate_clusters
        .iter()
        .all(|cluster| cluster.members.len() == 2));
    assert!(!report.candidate_clusters.iter().any(|cluster| {
        cluster.members.iter().any(|member| member.start_line == 10)
            && cluster.members.iter().any(|member| member.start_line == 16)
    }));
}
