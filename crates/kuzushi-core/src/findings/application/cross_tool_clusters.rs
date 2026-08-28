//! Read-only candidate clustering across producer tools.
//!
//! These clusters are evidence for an operator to inspect. They never rekey,
//! inherit a verdict, suppress a row, or otherwise mutate finding truth.

use super::{extract_cwe, is_attack_chain_finding, normalize_cwe, Finding};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CrossToolClusterBasis {
    ValidatedSourceLocator,
    SymbolAndSourceSignature,
    OverlappingEvidenceSpan,
    ClassProximity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CrossToolClusterMember {
    pub finding_id: Option<i64>,
    pub fingerprint: String,
    pub tool: String,
    pub rule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol_locator: Option<String>,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CrossToolCandidateCluster {
    pub cluster_id: String,
    pub strongest_basis: CrossToolClusterBasis,
    pub observed_bases: Vec<CrossToolClusterBasis>,
    pub members: Vec<CrossToolClusterMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CrossToolClusterReport {
    pub report_only: bool,
    pub findings_scanned: usize,
    pub attack_chains_excluded: usize,
    pub candidate_clusters: Vec<CrossToolCandidateCluster>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct CandidateEdge {
    left: usize,
    right: usize,
    basis: CrossToolClusterBasis,
}

/// Proposes cross-tool clusters without changing either input findings or
/// their decisions. Attack chains are excluded before any pair is compared.
pub fn derive_cross_tool_cluster_report(findings: &[Finding]) -> CrossToolClusterReport {
    let eligible = eligible_findings(findings);
    let edges = candidate_edges(&eligible);
    let candidate_clusters = clusters_from_edges(&eligible, &edges);
    CrossToolClusterReport {
        report_only: true,
        findings_scanned: findings.len(),
        attack_chains_excluded: findings.len().saturating_sub(eligible.len()),
        candidate_clusters,
        limitations: cluster_schema_limitations(),
    }
}

fn eligible_findings(findings: &[Finding]) -> Vec<&Finding> {
    let mut eligible = findings
        .iter()
        .filter(|finding| !is_attack_chain_finding(finding))
        .collect::<Vec<_>>();
    eligible.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
    eligible
}

fn candidate_edges(findings: &[&Finding]) -> Vec<CandidateEdge> {
    let mut edges = Vec::new();
    for left in 0..findings.len() {
        for right in left + 1..findings.len() {
            if let Some(basis) = candidate_basis(findings[left], findings[right]) {
                edges.push(CandidateEdge { left, right, basis });
            }
        }
    }
    edges
}

fn candidate_basis(left: &Finding, right: &Finding) -> Option<CrossToolClusterBasis> {
    if same_tool(left, right) {
        return None;
    }
    strongest_candidate_basis(left, right)
}

fn strongest_candidate_basis(left: &Finding, right: &Finding) -> Option<CrossToolClusterBasis> {
    [
        (
            same_validated_locator(left, right),
            CrossToolClusterBasis::ValidatedSourceLocator,
        ),
        (
            same_symbol_and_source_signature(left, right),
            CrossToolClusterBasis::SymbolAndSourceSignature,
        ),
        (
            overlapping_evidence_span(left, right),
            CrossToolClusterBasis::OverlappingEvidenceSpan,
        ),
        (
            same_class_nearby(left, right),
            CrossToolClusterBasis::ClassProximity,
        ),
    ]
    .into_iter()
    .find_map(|(matches, basis)| matches.then_some(basis))
}

fn same_symbol_and_source_signature(left: &Finding, right: &Finding) -> bool {
    same_path(left, right)
        && matching_nonempty(
            left.normalized_symbol_locator(),
            right.normalized_symbol_locator(),
        )
        && matching_nonempty(
            normalized_optional(left.source_signature.as_deref()),
            normalized_optional(right.source_signature.as_deref()),
        )
}

fn normalized_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn matching_nonempty(left: Option<String>, right: Option<String>) -> bool {
    left.is_some() && left == right
}

fn same_tool(left: &Finding, right: &Finding) -> bool {
    left.tool.trim().eq_ignore_ascii_case(right.tool.trim())
}

fn same_validated_locator(left: &Finding, right: &Finding) -> bool {
    left.effective_identity_basis() == super::FindingIdentityBasis::SourceLocator
        && right.effective_identity_basis() == super::FindingIdentityBasis::SourceLocator
        && left.identity_id.as_deref().is_some()
        && left.identity_id == right.identity_id
}

fn overlapping_evidence_span(left: &Finding, right: &Finding) -> bool {
    if !same_path(left, right) || left.start_line == 0 || right.start_line == 0 {
        return false;
    }
    left.start_line <= finding_end_line(right) && right.start_line <= finding_end_line(left)
}

fn same_class_nearby(left: &Finding, right: &Finding) -> bool {
    if !same_path(left, right) || left.start_line == 0 || right.start_line == 0 {
        return false;
    }
    finding_class(left).is_some_and(|class| finding_class(right).as_deref() == Some(&class))
        && left.start_line.abs_diff(right.start_line) <= 3
}

fn same_path(left: &Finding, right: &Finding) -> bool {
    left.file_path.trim_start_matches("./") == right.file_path.trim_start_matches("./")
}

fn finding_class(finding: &Finding) -> Option<String> {
    extract_cwe(&finding.rule_id, &finding.title, &finding.message)
        .map(|cwe| format!("cwe:{}", normalize_cwe(&cwe)))
        .or_else(|| normalized_category(finding.category.as_deref()))
}

fn normalized_category(category: Option<&str>) -> Option<String> {
    category
        .map(crate::identity::finding_identity::normalize_token)
        .filter(|category| !category.is_empty())
        .map(|category| format!("category:{category}"))
}

fn finding_end_line(finding: &Finding) -> u32 {
    finding.end_line.unwrap_or(finding.start_line)
}

fn clusters_from_edges(
    findings: &[&Finding],
    edges: &[CandidateEdge],
) -> Vec<CrossToolCandidateCluster> {
    let mut sets = DisjointSets::new(findings.len());
    for edge in edges {
        sets.join(edge.left, edge.right);
    }
    let groups = grouped_members(&mut sets, findings.len());
    candidate_member_sets(&groups, edges)
        .into_iter()
        .enumerate()
        .map(|(index, members)| build_cluster(index, &members, findings, edges))
        .collect()
}

fn candidate_member_sets(
    groups: &BTreeMap<usize, Vec<usize>>,
    edges: &[CandidateEdge],
) -> Vec<Vec<usize>> {
    let mut candidates = Vec::new();
    for members in groups.values().filter(|members| members.len() > 1) {
        if is_complete_candidate_cluster(members, edges) {
            candidates.push(members.clone());
            continue;
        }
        candidates.extend(edges.iter().filter_map(|edge| {
            (members.contains(&edge.left) && members.contains(&edge.right))
                .then_some(vec![edge.left, edge.right])
        }));
    }
    candidates
}

fn is_complete_candidate_cluster(members: &[usize], edges: &[CandidateEdge]) -> bool {
    let expected = members.len() * members.len().saturating_sub(1) / 2;
    edges
        .iter()
        .filter(|edge| members.contains(&edge.left) && members.contains(&edge.right))
        .count()
        == expected
}

fn grouped_members(sets: &mut DisjointSets, count: usize) -> BTreeMap<usize, Vec<usize>> {
    let mut groups = BTreeMap::<usize, Vec<usize>>::new();
    for index in 0..count {
        groups.entry(sets.root(index)).or_default().push(index);
    }
    groups
}

fn build_cluster(
    index: usize,
    members: &[usize],
    findings: &[&Finding],
    edges: &[CandidateEdge],
) -> CrossToolCandidateCluster {
    let observed_bases = cluster_bases(members, edges);
    CrossToolCandidateCluster {
        cluster_id: format!("candidate-{:03}", index + 1),
        strongest_basis: observed_bases[0],
        observed_bases,
        members: members
            .iter()
            .map(|member| cluster_member(findings[*member]))
            .collect(),
    }
}

fn cluster_bases(members: &[usize], edges: &[CandidateEdge]) -> Vec<CrossToolClusterBasis> {
    let mut bases = edges
        .iter()
        .filter(|edge| members.contains(&edge.left) && members.contains(&edge.right))
        .map(|edge| edge.basis)
        .collect::<Vec<_>>();
    bases.sort();
    bases.dedup();
    bases
}

fn cluster_member(finding: &Finding) -> CrossToolClusterMember {
    CrossToolClusterMember {
        finding_id: finding.id,
        fingerprint: finding.fingerprint.clone(),
        tool: finding.tool.clone(),
        rule_id: finding.rule_id.clone(),
        symbol_locator: finding.symbol_locator.clone(),
        file_path: finding.file_path.clone(),
        start_line: finding.start_line,
        end_line: finding_end_line(finding),
    }
}

fn cluster_schema_limitations() -> Vec<String> {
    vec!["AST matching is limited to the persisted source-locator identity basis".to_string()]
}

struct DisjointSets {
    parents: Vec<usize>,
}

impl DisjointSets {
    fn new(count: usize) -> Self {
        Self {
            parents: (0..count).collect(),
        }
    }

    fn root(&mut self, mut index: usize) -> usize {
        while self.parents[index] != index {
            self.parents[index] = self.parents[self.parents[index]];
            index = self.parents[index];
        }
        index
    }

    fn join(&mut self, left: usize, right: usize) {
        let left = self.root(left);
        let right = self.root(right);
        if left != right {
            self.parents[right] = left;
        }
    }
}

#[cfg(test)]
mod tests;
