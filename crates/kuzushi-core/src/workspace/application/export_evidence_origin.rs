use crate::findings::FindingEvidence;

#[derive(Debug, Default, PartialEq, Eq)]
pub(in crate::workspace::application) struct EvidenceOriginCounts {
    pub observed_count: usize,
    pub observed_code_count: usize,
    pub observed_capture_count: usize,
    pub observed_other_count: usize,
    pub model_generated_reasoning_count: usize,
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
    match finding_evidence_origin(evidence) {
        FindingEvidenceOrigin::ModelGeneratedReasoning => {
            counts.model_generated_reasoning_count += 1;
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

enum FindingEvidenceOrigin {
    ObservedCode,
    ObservedCapture,
    ObservedOther,
    ModelGeneratedReasoning,
}

fn finding_evidence_origin(evidence: &FindingEvidence) -> FindingEvidenceOrigin {
    if evidence.kind.trim().eq_ignore_ascii_case("reasoning") {
        return FindingEvidenceOrigin::ModelGeneratedReasoning;
    }
    if evidence.request_blob.is_some() || evidence.response_blob.is_some() {
        return FindingEvidenceOrigin::ObservedCapture;
    }
    if !evidence.file_path.trim().is_empty() || !evidence.snippet.trim().is_empty() {
        return FindingEvidenceOrigin::ObservedCode;
    }
    FindingEvidenceOrigin::ObservedOther
}

pub(in crate::workspace::application) fn finding_evidence_origin_label(
    evidence: &FindingEvidence,
) -> &'static str {
    match finding_evidence_origin(evidence) {
        FindingEvidenceOrigin::ObservedCode => "observed code evidence",
        FindingEvidenceOrigin::ObservedCapture => "observed capture evidence",
        FindingEvidenceOrigin::ObservedOther => "observed evidence",
        FindingEvidenceOrigin::ModelGeneratedReasoning => "model-generated reasoning",
    }
}

pub(in crate::workspace::application) fn evidence_state_label(
    has_observed: bool,
    has_model_generated_reasoning: bool,
    has_multiple_sources: bool,
    has_source_link: bool,
) -> &'static str {
    match (
        has_observed,
        has_model_generated_reasoning,
        has_multiple_sources,
        has_source_link,
    ) {
        (true, _, _, _) => "observed",
        (_, true, _, _) => "model_generated_reasoning",
        (_, _, true, _) => "corroborated",
        (_, _, _, true) => "source_linked",
        _ => "message_only",
    }
}
