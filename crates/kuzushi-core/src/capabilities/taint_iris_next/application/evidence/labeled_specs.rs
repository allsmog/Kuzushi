use super::*;

pub(super) fn build_labeled_specs(
    plan: &TaintIrisNextPlan,
    candidates: &[TaintIrisNextCandidate],
) -> Vec<TaintIrisNextLabeledSpec> {
    candidates
        .iter()
        .filter(|candidate| matches!(candidate.role.as_str(), "source" | "sink" | "sanitizer"))
        .take(plan.caps.max_specs_per_cwe * plan.catalog.len().max(1))
        .map(labeled_spec_from_candidate)
        .collect()
}

fn labeled_spec_from_candidate(candidate: &TaintIrisNextCandidate) -> TaintIrisNextLabeledSpec {
    TaintIrisNextLabeledSpec {
        id: format!("spec-{}", candidate.id),
        cwe: candidate.cwe.clone(),
        taint_class: candidate.taint_class.clone(),
        track: candidate.track.clone(),
        role: candidate.role.clone(),
        kind: candidate.kind.clone(),
        api_name: candidate.pattern.clone(),
        pattern: candidate.pattern.clone(),
        file_path: Some(candidate.file_path.clone()),
        line: Some(candidate.line),
        confidence: candidate.confidence.clone(),
        rationale: format!("Matched catalog {} signal", candidate.role),
        catalog_signal: candidate.catalog_signal.clone(),
    }
}
