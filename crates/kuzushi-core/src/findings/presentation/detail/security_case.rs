use super::*;

pub const SECURITY_CASE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecurityCaseProjection {
    pub schema_version: u32,
    pub case_id: String,
    pub disposition: String,
    pub claim: SecurityCaseClaim,
    pub source: SecurityCaseSource,
    pub observations: Vec<FindingSource>,
    pub evidence: Vec<FindingEvidence>,
    pub proof: SecurityCaseProof,
    pub decisions: Vec<ReviewDecisionRecord>,
    pub patches: Vec<PatchResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contradictions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved_questions: Vec<String>,
    pub next_action: FindingNextAction,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecurityCaseClaim {
    pub title: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exploit_scenario: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preconditions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecurityCaseSource {
    pub file_path: String,
    pub start_line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    pub fingerprint: String,
    pub identity_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_run_id: Option<String>,
    pub corroboration_count: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecurityCaseProof {
    pub static_state: String,
    pub runtime_state: String,
    pub ladder: ProofLadderState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<PersistedVerification>,
}

pub fn security_case_projection(
    finding: &Finding,
    proof_state: &str,
    runtime_validation: &str,
    proof_ladder: &ProofLadderState,
    next_action: FindingNextAction,
    decisions: Vec<ReviewDecisionRecord>,
    patches: Vec<PatchResult>,
) -> Option<SecurityCaseProjection> {
    let identity_id = finding.identity_id.clone()?;
    Some(SecurityCaseProjection {
        schema_version: SECURITY_CASE_SCHEMA_VERSION,
        case_id: format!("identity:{identity_id}"),
        disposition: security_case_disposition(finding, &decisions),
        claim: security_case_claim(finding),
        source: security_case_source(finding, identity_id),
        observations: finding.sources.clone(),
        evidence: finding.evidence.clone(),
        proof: security_case_proof(finding, proof_state, runtime_validation, proof_ladder),
        contradictions: decision_contradictions(&decisions),
        unresolved_questions: unresolved_case_questions(finding, &decisions, &patches),
        decisions,
        patches,
        next_action,
    })
}

fn security_case_claim(finding: &Finding) -> SecurityCaseClaim {
    SecurityCaseClaim {
        title: finding.title.clone(),
        message: finding.message.clone(),
        impact: finding.impact.clone(),
        category: finding.category.clone(),
        exploit_scenario: finding.exploit_scenario.clone(),
        preconditions: finding.preconditions.clone(),
        remediation: finding.remediation.clone(),
    }
}

fn security_case_source(finding: &Finding, identity_id: String) -> SecurityCaseSource {
    SecurityCaseSource {
        file_path: finding.file_path.clone(),
        start_line: finding.start_line,
        end_line: finding.end_line,
        fingerprint: finding.fingerprint.clone(),
        identity_id,
        source_signature: finding.source_signature.clone(),
        discovery_run_id: finding.scan_id.clone(),
        corroboration_count: finding.corroboration_count,
    }
}

fn security_case_proof(
    finding: &Finding,
    proof_state: &str,
    runtime_validation: &str,
    proof_ladder: &ProofLadderState,
) -> SecurityCaseProof {
    SecurityCaseProof {
        static_state: proof_state.to_string(),
        runtime_state: runtime_validation.to_string(),
        ladder: proof_ladder.clone(),
        verification: finding.verification.clone(),
    }
}

fn security_case_disposition(finding: &Finding, decisions: &[ReviewDecisionRecord]) -> String {
    if let Some(decision) = effective_decision(decisions) {
        return decision_disposition(
            decision.decision.verdict,
            finding_is_empirically_verified(finding),
        )
        .to_string();
    }
    if finding_is_empirically_verified(finding) {
        return "runtime_confirmed".to_string();
    }
    match finding.triage.as_ref().map(|triage| triage.verdict) {
        Some(TriageVerdict::TruePositive) => "machine_confirmed".to_string(),
        Some(TriageVerdict::FalsePositive) => "machine_rejected".to_string(),
        Some(TriageVerdict::ByDesign) => "machine_by_design".to_string(),
        Some(TriageVerdict::NeedsReview) | None => "open".to_string(),
    }
}

fn decision_disposition(verdict: ReviewDecisionVerdict, empirically_verified: bool) -> &'static str {
    match verdict {
        ReviewDecisionVerdict::Confirmed if empirically_verified => "runtime_confirmed",
        ReviewDecisionVerdict::Confirmed => "confirmed",
        ReviewDecisionVerdict::ToFix => "to_fix",
        ReviewDecisionVerdict::RejectedFalsePositive => "rejected_false_positive",
        ReviewDecisionVerdict::Suppressed => "suppressed",
        ReviewDecisionVerdict::Deferred => "deferred",
        ReviewDecisionVerdict::AcceptedRisk => "accepted_risk",
        ReviewDecisionVerdict::NeedsReview => "needs_review",
    }
}

fn effective_decision(decisions: &[ReviewDecisionRecord]) -> Option<&ReviewDecisionRecord> {
    decisions
        .iter()
        .rev()
        .find(|record| record.decision.author == TriageAuthor::Human)
        .or_else(|| decisions.last())
}

fn finding_is_empirically_verified(finding: &Finding) -> bool {
    finding
        .verification
        .as_ref()
        .is_some_and(PersistedVerification::is_empirically_verified)
}

fn decision_contradictions(decisions: &[ReviewDecisionRecord]) -> Vec<String> {
    let assessments: Vec<_> = decisions
        .iter()
        .filter(|record| record.decision.author == TriageAuthor::Human)
        .filter_map(|record| decision_claim_position(&record.decision).map(|position| (record, position)))
        .collect();
    assessments
        .windows(2)
        .filter(|window| window[0].1 != window[1].1)
        .map(|window| {
            format!(
                "human claim assessment changed from {} to {} at {}",
                window[0].1.as_str(),
                window[1].1.as_str(),
                window[1].0.created_at
            )
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DecisionClaimPosition {
    Affirmed,
    Rejected,
}

impl DecisionClaimPosition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Affirmed => "affirmed",
            Self::Rejected => "rejected",
        }
    }
}

fn decision_claim_position(decision: &ReviewDecision) -> Option<DecisionClaimPosition> {
    match decision.verdict {
        ReviewDecisionVerdict::Confirmed
        | ReviewDecisionVerdict::ToFix
        | ReviewDecisionVerdict::AcceptedRisk => Some(DecisionClaimPosition::Affirmed),
        ReviewDecisionVerdict::RejectedFalsePositive => Some(DecisionClaimPosition::Rejected),
        ReviewDecisionVerdict::Suppressed
        | ReviewDecisionVerdict::Deferred
        | ReviewDecisionVerdict::NeedsReview => None,
    }
}

fn unresolved_case_questions(
    finding: &Finding,
    decisions: &[ReviewDecisionRecord],
    patches: &[PatchResult],
) -> Vec<String> {
    [
        missing_evidence_question(finding),
        missing_human_review_question(decisions),
        missing_runtime_question(finding, decisions),
        missing_patch_question(decisions, patches),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn missing_evidence_question(finding: &Finding) -> Option<String> {
    (finding.evidence.is_empty() && finding.sources.is_empty())
        .then(|| "no source-grounded evidence or observation records are attached".to_string())
}

fn missing_human_review_question(decisions: &[ReviewDecisionRecord]) -> Option<String> {
    (!decisions
        .iter()
        .any(|record| record.decision.author == TriageAuthor::Human))
    .then(|| "no human review decision is recorded".to_string())
}

fn missing_runtime_question(
    finding: &Finding,
    decisions: &[ReviewDecisionRecord],
) -> Option<String> {
    let rejected = effective_decision(decisions)
        .and_then(|record| decision_claim_position(&record.decision))
        == Some(DecisionClaimPosition::Rejected);
    (!rejected && !finding_is_empirically_verified(finding))
        .then(|| "runtime exploitability has not been empirically established".to_string())
}

fn missing_patch_question(
    decisions: &[ReviewDecisionRecord],
    patches: &[PatchResult],
) -> Option<String> {
    let patch_requested = effective_decision(decisions)
        .is_some_and(|record| record.decision.verdict == ReviewDecisionVerdict::ToFix);
    (patch_requested && patches.is_empty())
        .then(|| "the to-fix decision has no recorded patch attempt".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_decision_and_runtime_proof_drive_case_disposition() {
        let mut finding = Finding::new_tool(
            "semgrep",
            "rule/cwe-89",
            "src/db.rs",
            12,
            None,
            Severity::High,
            "request data reaches a query sink",
        );
        finding.identity_id = Some("case-identity".to_string());
        let decisions = vec![decision(ReviewDecisionVerdict::Confirmed, "2026-08-01")];
        let case = security_case_projection(
            &finding,
            "source_linked",
            "not attempted",
            &ProofLadderState {
                stage: "static".to_string(),
                label: "static".to_string(),
                reason: "source path recorded".to_string(),
                next_step: "run empirical verification".to_string(),
            },
            FindingNextAction::Validate,
            decisions,
            Vec::new(),
        )
        .expect("persisted finding identity should produce a case");

        assert_eq!(case.case_id, "identity:case-identity");
        assert_eq!(case.disposition, "confirmed");
        assert!(case
            .unresolved_questions
            .iter()
            .any(|question| question.contains("empirically")));
    }

    #[test]
    fn changed_review_verdict_is_preserved_as_a_contradiction() {
        let mut finding = Finding::new_tool(
            "fixture",
            "rule",
            "src/lib.rs",
            1,
            None,
            Severity::Medium,
            "fixture",
        );
        finding.identity_id = Some("case-identity".to_string());
        let decisions = vec![
            decision(ReviewDecisionVerdict::Confirmed, "2026-08-01"),
            decision(ReviewDecisionVerdict::RejectedFalsePositive, "2026-08-02"),
        ];
        let case = security_case_projection(
            &finding,
            "candidate",
            "not attempted",
            &ProofLadderState {
                stage: "signal".to_string(),
                label: "signal".to_string(),
                reason: "scanner signal".to_string(),
                next_step: "inspect source".to_string(),
            },
            FindingNextAction::Review,
            decisions,
            Vec::new(),
        )
        .expect("persisted finding identity should produce a case");

        assert_eq!(case.disposition, "rejected_false_positive");
        assert_eq!(case.contradictions.len(), 1);
    }

    #[test]
    fn normal_review_progression_is_not_a_contradiction() {
        let decisions = vec![
            decision(ReviewDecisionVerdict::NeedsReview, "2026-08-01"),
            decision(ReviewDecisionVerdict::Confirmed, "2026-08-02"),
            decision(ReviewDecisionVerdict::ToFix, "2026-08-03"),
        ];

        assert!(decision_contradictions(&decisions).is_empty());
    }

    #[test]
    fn canonical_case_requires_a_durable_finding_identity() {
        let finding = Finding::new_tool(
            "fixture",
            "rule",
            "src/lib.rs",
            1,
            None,
            Severity::Medium,
            "fixture",
        );

        let projection = security_case_projection(
            &finding,
            "candidate",
            "not attempted",
            &ProofLadderState {
                stage: "signal".to_string(),
                label: "signal".to_string(),
                reason: "scanner signal".to_string(),
                next_step: "inspect source".to_string(),
            },
            FindingNextAction::Review,
            Vec::new(),
            Vec::new(),
        );

        assert!(projection.is_none());
    }

    fn decision(verdict: ReviewDecisionVerdict, created_at: &str) -> ReviewDecisionRecord {
        ReviewDecisionRecord {
            id: 1,
            finding_id: 1,
            identity_id: Some("case-identity".to_string()),
            decision: ReviewDecision {
                verdict,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "reviewed".to_string(),
                dismiss_reason: None,
                actor: Some("operator".to_string()),
            },
            triage_verdict: verdict.to_triage_verdict(),
            created_at: created_at.to_string(),
        }
    }
}
