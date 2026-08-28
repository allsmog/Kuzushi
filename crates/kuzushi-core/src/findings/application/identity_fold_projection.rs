//! Policy-aware projection of emitted finding generations for operator views.

use super::{finding_projection_key, IdentityFoldPolicy};
use crate::findings::{
    is_attack_chain_finding, Finding, FindingEvidence, FindingSource, ProofConfidence, Severity,
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn project_finding_generations(
    findings: Vec<Finding>,
    policy: IdentityFoldPolicy,
) -> Vec<Finding> {
    let safe_context = SafeProjectionContext::from_findings(&findings, policy);
    let mut projected = Vec::<Finding>::new();
    let mut positions = BTreeMap::<String, usize>::new();
    for finding in findings {
        let key = safe_context.projection_key(&finding, policy);
        if let Some(position) = positions.get(&key).copied() {
            projected[position] = merge_findings(&projected[position], finding);
            continue;
        }
        positions.insert(key, projected.len());
        projected.push(finding);
    }
    projected
}

#[derive(Default)]
struct SafeProjectionContext {
    strong_evidence: BTreeMap<String, IdentityEvidence>,
}

impl SafeProjectionContext {
    fn from_findings(findings: &[Finding], policy: IdentityFoldPolicy) -> Self {
        let mut context = Self::default();
        if policy != IdentityFoldPolicy::Safe {
            return context;
        }
        for finding in findings {
            context.observe_strong(finding);
        }
        context
    }

    fn observe_strong(&mut self, finding: &Finding) {
        let Some(identity_id) = finding.identity_id.as_ref() else {
            return;
        };
        if !finding.effective_identity_basis().is_strong() {
            return;
        }
        self.strong_evidence
            .entry(identity_id.clone())
            .or_default()
            .observe(finding);
    }

    fn projection_key(&self, finding: &Finding, policy: IdentityFoldPolicy) -> String {
        if is_attack_chain_finding(finding) {
            return finding_projection_key(finding, policy);
        }
        if policy == IdentityFoldPolicy::Safe {
            if let Some(identity_id) = self.fallback_strong_identity(finding) {
                return format!("identity:{identity_id}");
            }
        }
        finding_projection_key(finding, policy)
    }

    /// Returns the identity the fold key is built from, so a finding without
    /// one can never reach the `identity:` branch. Answering `bool` here and
    /// re-reading `identity_id` at the call site allowed an absent identity to
    /// fold every such finding into one empty `identity:` bucket.
    fn fallback_strong_identity<'a>(&self, finding: &'a Finding) -> Option<&'a str> {
        if finding.effective_identity_basis().is_strong() {
            return None;
        }
        let identity_id = finding.identity_id.as_ref()?;
        let evidence = self.strong_evidence.get(identity_id)?;
        evidence.matches(finding).then_some(identity_id.as_str())
    }
}

#[derive(Default)]
struct IdentityEvidence {
    source_signatures: BTreeSet<String>,
    dedup_keys: BTreeSet<String>,
}

impl IdentityEvidence {
    fn observe(&mut self, finding: &Finding) {
        insert_nonempty(
            &mut self.source_signatures,
            finding.source_signature.as_deref(),
        );
        insert_nonempty(&mut self.dedup_keys, finding.dedup_key.as_deref());
    }

    fn matches(&self, finding: &Finding) -> bool {
        contains_nonempty(&self.source_signatures, finding.source_signature.as_deref())
            || contains_nonempty(&self.dedup_keys, finding.dedup_key.as_deref())
    }
}

fn insert_nonempty(values: &mut BTreeSet<String>, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        values.insert(value.to_string());
    }
}

fn contains_nonempty(values: &BTreeSet<String>, value: Option<&str>) -> bool {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|value| values.contains(value))
}

fn merge_findings(previous: &Finding, next: Finding) -> Finding {
    let next_sources = next.sources.clone();
    let next_evidence = next.evidence.clone();
    let next_count = next.corroboration_count;
    let mut representative = strongest_representative(previous, next);
    representative.sources = merged_sources(&previous.sources, &next_sources);
    representative.evidence = merged_evidence(&previous.evidence, &next_evidence);
    representative.corroboration_count = merged_corroboration_count(
        previous.corroboration_count,
        next_count,
        representative.sources.len(),
    );
    representative
}

fn strongest_representative(previous: &Finding, next: Finding) -> Finding {
    if finding_rank(&next) > finding_rank(previous) {
        next
    } else {
        previous.clone()
    }
}

fn finding_rank(finding: &Finding) -> (u8, u8) {
    (
        severity_rank(finding.severity),
        3u8.saturating_sub(ProofConfidence::classify(finding).rank()),
    )
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
        Severity::Unknown => 0,
    }
}

fn merged_sources(left: &[FindingSource], right: &[FindingSource]) -> Vec<FindingSource> {
    let mut by_key = BTreeMap::<String, FindingSource>::new();
    for source in left.iter().chain(right) {
        by_key.insert(source_key(source), source.clone());
    }
    by_key.into_values().collect()
}

fn source_key(source: &FindingSource) -> String {
    format!(
        "{}\0{}\0{}",
        source.tool, source.source_signature, source.last_scan_id
    )
}

fn merged_evidence(left: &[FindingEvidence], right: &[FindingEvidence]) -> Vec<FindingEvidence> {
    let mut merged = Vec::new();
    for evidence in left.iter().chain(right) {
        if !merged.contains(evidence) {
            merged.push(evidence.clone());
        }
    }
    merged
}

fn merged_corroboration_count(left: u32, right: u32, source_count: usize) -> u32 {
    if source_count > 0 {
        return source_count as u32;
    }
    left.max(1).saturating_add(right.max(1))
}
