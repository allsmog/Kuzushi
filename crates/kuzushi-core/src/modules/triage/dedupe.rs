use super::*;
use crate::findings::ingest_contract::{assign_clusters, CLUSTER_WINDOW_LINES};
use std::collections::BTreeMap;

pub(in crate::modules) struct TriageCluster {
    pub(in crate::modules) representative: Finding,
    pub(in crate::modules) duplicates: Vec<Finding>,
}

/// Structured dedupe before the LLM stage: findings from the same tool and
/// rule whose lines fall inside one span-extended ±`CLUSTER_WINDOW_LINES`
/// window (the shared ingest-contract clustering) form one cluster. Only the
/// representative is triaged; members inherit its verdict with a
/// duplicate-of rationale instead of burning independent LLM calls.
pub(in crate::modules) fn cluster_triage_findings(findings: Vec<Finding>) -> Vec<TriageCluster> {
    // Attack-chain exemption: a chain composes multiple component bugs, and
    // its entry location intentionally collides with a component finding (or
    // another chain sharing the entry). Line proximity is therefore not a
    // duplication signal — chains never absorb and are never absorbed.
    let (chains, ordinary): (Vec<Finding>, Vec<Finding>) =
        findings.into_iter().partition(is_attack_chain_finding);
    let mut result: Vec<TriageCluster> = chains
        .into_iter()
        .map(|finding| TriageCluster {
            representative: finding,
            duplicates: Vec::new(),
        })
        .collect();
    let mut clusters: BTreeMap<(String, String, String), Vec<Finding>> = BTreeMap::new();
    for (finding, cluster_id) in with_cluster_ids(ordinary) {
        let key = (
            finding.tool.trim().to_ascii_lowercase(),
            finding.rule_id.trim().to_ascii_lowercase(),
            cluster_id,
        );
        clusters.entry(key).or_default().push(finding);
    }
    result.extend(clusters.into_values().map(into_triage_cluster));
    result
}

pub(in crate::modules) fn is_attack_chain_finding(finding: &Finding) -> bool {
    finding.tool.trim().eq_ignore_ascii_case("chains")
        || finding
            .rule_id
            .trim()
            .to_ascii_lowercase()
            .starts_with("exploit-chain/")
}

fn with_cluster_ids(findings: Vec<Finding>) -> Vec<(Finding, String)> {
    let rows: Vec<(String, u32)> = findings
        .iter()
        .map(|finding| (clustering_scope(finding), finding.start_line))
        .collect();
    let ids = assign_clusters(&rows);
    findings.into_iter().zip(ids).collect()
}

/// Cluster within (tool, rule, file) so unrelated rules on adjacent lines
/// never merge; the composite string keeps `assign_clusters` file-keyed.
fn clustering_scope(finding: &Finding) -> String {
    format!(
        "{}\u{1}{}\u{1}{}",
        finding.tool.trim().to_ascii_lowercase(),
        finding.rule_id.trim().to_ascii_lowercase(),
        finding.file_path.trim().trim_start_matches("./").replace('\\', "/").to_ascii_lowercase(),
    )
}

fn into_triage_cluster(mut members: Vec<Finding>) -> TriageCluster {
    let representative_index = members
        .iter()
        .enumerate()
        .max_by_key(|(index, finding)| (severity_rank(finding), evidence_weight(finding), usize::MAX - index))
        .map(|(index, _)| index)
        .unwrap_or(0);
    let representative = members.remove(representative_index);
    TriageCluster {
        representative,
        duplicates: members,
    }
}

fn severity_rank(finding: &Finding) -> u8 {
    match finding.severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
        Severity::Unknown => 0,
    }
}

fn evidence_weight(finding: &Finding) -> usize {
    finding.title.trim().len() + finding.message.trim().len()
}

pub(in crate::modules) fn duplicate_rationale(
    representative_fingerprint: &str,
    representative_rationale: &str,
) -> String {
    format!(
        "duplicate of {representative_fingerprint} (same tool+rule within {CLUSTER_WINDOW_LINES} lines): {representative_rationale}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, file: &str, line: u32, severity: Severity) -> Finding {
        Finding::new_tool("agentic-sast", rule, file, line, None, severity, "msg")
    }

    #[test]
    fn nearby_same_rule_findings_collapse_to_the_highest_severity_representative() {
        let clusters = cluster_triage_findings(vec![
            finding("cmd-injection", "execd_lib.cpp", 100, Severity::Medium),
            finding("cmd-injection", "execd_lib.cpp", 110, Severity::High),
            finding("cmd-injection", "execd_lib.cpp", 400, Severity::Medium),
        ]);

        assert_eq!(clusters.len(), 2);
        let near = clusters
            .iter()
            .find(|cluster| !cluster.duplicates.is_empty())
            .unwrap();
        assert_eq!(near.representative.severity, Severity::High);
        assert_eq!(near.duplicates.len(), 1);
        assert_eq!(near.duplicates[0].start_line, 100);
    }

    #[test]
    fn different_rules_or_files_never_merge() {
        let clusters = cluster_triage_findings(vec![
            finding("cmd-injection", "a.cpp", 10, Severity::High),
            finding("path-traversal", "a.cpp", 12, Severity::High),
            finding("cmd-injection", "b.cpp", 10, Severity::High),
        ]);

        assert_eq!(clusters.len(), 3);
        assert!(clusters.iter().all(|cluster| cluster.duplicates.is_empty()));
    }
}
