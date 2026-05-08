use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SemgrepRuleFixture {
    pub name: String,
    pub body: String,
    pub should_match: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_fingerprint: Option<String>,
}

impl SemgrepRuleFixture {
    pub fn positive(name: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            body: body.into(),
            should_match: true,
            source_fingerprint: None,
        }
    }

    pub fn negative(name: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            body: body.into(),
            should_match: false,
            source_fingerprint: None,
        }
    }

    pub fn for_finding(mut self, fingerprint: impl Into<String>) -> Self {
        self.source_fingerprint = Some(fingerprint.into());
        self
    }
}

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
