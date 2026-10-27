pub(in crate::workspace::application) use crate::findings::presentation::evidence_origin_label as finding_evidence_origin_label;
use crate::findings::{FindingEvidence, FindingEvidenceOrigin};

#[derive(Debug, Default, PartialEq, Eq)]
pub(in crate::workspace::application) struct EvidenceOriginCounts {
    pub observed_count: usize,
    pub observed_code_count: usize,
    pub observed_capture_count: usize,
    pub observed_other_count: usize,
    pub model_generated_reasoning_count: usize,
    pub reasoning_assertion_count: usize,
}

pub(in crate::workspace::application) fn evidence_origin_counts(
    evidence: &[FindingEvidence],
) -> EvidenceOriginCounts {
    let mut counts = EvidenceOriginCounts::default();
    for row in evidence {
        increment_evidence_origin_counts(&mut counts, row);
    }
    counts
}

fn increment_evidence_origin_counts(counts: &mut EvidenceOriginCounts, evidence: &FindingEvidence) {
    match evidence.origin_class() {
        FindingEvidenceOrigin::ModelGeneratedReasoning => {
            counts.model_generated_reasoning_count += 1;
        }
        FindingEvidenceOrigin::ReasoningAssertion => {
            counts.reasoning_assertion_count += 1;
        }
        FindingEvidenceOrigin::ObservedCapture => {
            counts.observed_count += 1;
            counts.observed_capture_count += 1;
        }
        FindingEvidenceOrigin::ObservedCode => {
            counts.observed_count += 1;
            counts.observed_code_count += 1;
        }
        FindingEvidenceOrigin::ObservedOther => {
            counts.observed_count += 1;
            counts.observed_other_count += 1;
        }
    }
}

pub(in crate::workspace::application) fn evidence_state_label(
    counts: &EvidenceOriginCounts,
    has_multiple_sources: bool,
    has_source_link: bool,
) -> &'static str {
    if counts.observed_count > 0 {
        return "observed";
    }
    if counts.model_generated_reasoning_count > 0 {
        return "model_generated_reasoning";
    }
    if counts.reasoning_assertion_count > 0 {
        return "reasoning_assertion";
    }
    derived_evidence_state_label(has_multiple_sources, has_source_link)
}

fn derived_evidence_state_label(has_multiple_sources: bool, has_source_link: bool) -> &'static str {
    match (has_multiple_sources, has_source_link) {
        (true, _) => "corroborated",
        (_, true) => "source_linked",
        _ => "message_only",
    }
}

#[cfg(test)]
mod tests;
