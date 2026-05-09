use super::synthesize_candidate_for_finding;
use crate::capabilities::semgrep_rule_synthesis::domain::{
    SemgrepRuleFixture, SemgrepRuleSynthesisReport,
};
use crate::evidence::static_evidence::StaticEvidenceStore;
use crate::findings::{Finding, StaticProofState};
use anyhow::Result;

pub fn synthesize_candidate_semgrep_rules(
    findings: &[Finding],
    evidence_store: Option<&StaticEvidenceStore>,
    fixtures: &[SemgrepRuleFixture],
) -> Result<SemgrepRuleSynthesisReport> {
    let mut candidates = Vec::new();
    for finding in findings
        .iter()
        .filter(|finding| finding.static_proof_state == Some(StaticProofState::StaticallyConfirmed))
    {
        let evidence_nodes = match evidence_store {
            Some(store) => store.list_nodes_for_finding(&finding.fingerprint)?,
            None => Vec::new(),
        };
        let Some(candidate) = synthesize_candidate_for_finding(finding, &evidence_nodes, fixtures)
        else {
            continue;
        };
        candidates.push(candidate);
    }
    candidates.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.source_location.cmp(&right.source_location))
            .then_with(|| left.source_fingerprint.cmp(&right.source_fingerprint))
    });
    let validation_passed = candidates
        .iter()
        .filter(|candidate| candidate.validation.passed)
        .count();
    Ok(SemgrepRuleSynthesisReport {
        count: candidates.len(),
        validation_passed,
        candidates,
        deterministic: true,
    })
}
