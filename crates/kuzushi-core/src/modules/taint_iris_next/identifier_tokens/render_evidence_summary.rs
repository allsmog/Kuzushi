use super::*;

pub(in crate::modules::taint_iris_next) fn push_taint_iris_next_evidence_summary(
    lines: &mut Vec<String>,
    evidence: &TaintIrisNextEvidenceResult,
) {
    lines.push(format!(
        "triage: findings={} candidates={} rejected={}",
        evidence_triage_count(evidence, "finding"),
        evidence_triage_count(evidence, "candidate"),
        evidence_triage_count(evidence, "rejected")
    ));
}

fn evidence_triage_count(evidence: &TaintIrisNextEvidenceResult, key: &str) -> u64 {
    evidence
        .triage_summary
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or(0)
}
