use crate::findings::{FindingEvidence, FindingEvidenceOrigin};

pub fn evidence_origin_label(evidence: &FindingEvidence) -> &'static str {
    match evidence.origin_class() {
        FindingEvidenceOrigin::ModelGeneratedReasoning => "model-generated reasoning",
        FindingEvidenceOrigin::ReasoningAssertion => "reasoning assertion",
        FindingEvidenceOrigin::ObservedCapture => "observed capture evidence",
        FindingEvidenceOrigin::ObservedCode => "observed code evidence",
        FindingEvidenceOrigin::ObservedOther => "observed evidence",
    }
}
