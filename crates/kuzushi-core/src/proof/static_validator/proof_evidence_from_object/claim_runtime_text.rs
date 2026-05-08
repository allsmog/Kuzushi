use super::*;

pub(in crate::proof::static_validator) fn contains_forbidden_runtime_claim(
    claim: &StaticProofClaim,
) -> bool {
    let lower = forbidden_runtime_claim_text(claim).to_ascii_lowercase();
    [
        "runtime exploitable",
        "runtime exploitability",
        "confirmed exploit",
        "exploit executed",
        "poc executed",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn forbidden_runtime_claim_text(claim: &StaticProofClaim) -> String {
    let mut text = String::new();
    append_optional(&mut text, claim.path_explanation.as_deref());
    append_optional(&mut text, claim.local_direct_reason.as_deref());
    append_text(&mut text, &claim.sanitizer_assessment.explanation);
    append_text(&mut text, &claim.guard_assessment.explanation);
    append_evidence_text(&mut text, &claim.source_or_entrypoint_evidence);
    append_evidence_text(&mut text, &claim.sink_evidence);
    append_strings(&mut text, &claim.assumptions);
    append_strings(&mut text, &claim.missing_evidence);
    text
}

fn append_optional(text: &mut String, value: Option<&str>) {
    append_text(text, value.unwrap_or_default());
}

fn append_evidence_text(text: &mut String, evidence: &[StaticProofEvidence]) {
    for item in evidence {
        append_text(text, &item.label);
        append_text(text, &item.detail);
    }
}

fn append_strings(text: &mut String, values: &[String]) {
    for value in values {
        append_text(text, value);
    }
}

fn append_text(text: &mut String, value: &str) {
    text.push('\n');
    text.push_str(value);
}
