use super::FindingFacetValue;
use crate::ui_view_models::review_conflicts::effective_review_decision_conflict_label;
use crate::ui_view_models::review_state::{
    effective_review_confidence_label, lifecycle_status_label, EffectiveReviewStateIndex,
};
use kuzushi_core::findings::ReviewDecisionVerdict;
use kuzushi_core::{Finding, ProofConfidence};
use std::collections::BTreeSet;

pub(super) fn finding_facet_values(
    finding: &Finding,
    review_index: &EffectiveReviewStateIndex,
) -> Vec<FindingFacetValue> {
    let mut values = Vec::new();
    push_count_values(
        &mut values,
        "severity",
        vec![finding.severity.as_str().to_string()],
    );
    push_count_values(&mut values, "source", source_tool_values(finding));
    push_count_values(&mut values, "file", path_values(finding));
    push_count_values(&mut values, "actor", actor_labels(finding));
    push_count_values(
        &mut values,
        "confidence",
        vec![ProofConfidence::classify(finding).as_str().to_string()],
    );
    push_count_values(
        &mut values,
        "status",
        vec![canonical_finding_status(finding, review_index).to_string()],
    );
    values
}

fn push_count_values(
    destination: &mut Vec<FindingFacetValue>,
    facet: &'static str,
    values: Vec<String>,
) {
    destination.extend(
        values
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|value| FindingFacetValue { facet, value }),
    );
}

pub(super) fn severity_values(finding: &Finding) -> Vec<String> {
    let severity = finding.severity.as_str();
    let compact = severity
        .chars()
        .next()
        .map(String::from)
        .unwrap_or_default();
    vec![severity.to_string(), compact]
}

pub(super) fn source_values(finding: &Finding) -> Vec<String> {
    let mut values = source_tool_values(finding);
    values.extend(finding.sources.iter().flat_map(|source| {
        [
            source.source_signature.to_ascii_lowercase(),
            source
                .vuln_source
                .map(|v| v.as_str().to_string())
                .unwrap_or_default(),
        ]
    }));
    values
}

fn source_tool_values(finding: &Finding) -> Vec<String> {
    std::iter::once(finding.tool.to_ascii_lowercase())
        .chain(
            finding
                .sources
                .iter()
                .map(|source| source.tool.to_ascii_lowercase()),
        )
        .collect()
}

pub(super) fn path_values(finding: &Finding) -> Vec<String> {
    std::iter::once(finding.file_path.to_ascii_lowercase())
        .chain(
            finding
                .evidence
                .iter()
                .map(|evidence| evidence.file_path.to_ascii_lowercase()),
        )
        .filter(|path| !path.is_empty())
        .collect()
}

pub(super) fn actor_values(finding: &Finding) -> Vec<String> {
    finding
        .actor_fingerprint
        .as_deref()
        .map(str::to_ascii_lowercase)
        .into_iter()
        .collect()
}

fn actor_labels(finding: &Finding) -> Vec<String> {
    finding
        .actor_fingerprint
        .as_deref()
        .map(|actor| {
            actor
                .split(':')
                .nth(1)
                .unwrap_or(actor)
                .to_ascii_lowercase()
        })
        .into_iter()
        .collect()
}

pub(super) fn confidence_values(
    finding: &Finding,
    review_index: &EffectiveReviewStateIndex,
) -> Vec<String> {
    let proof = ProofConfidence::classify(finding);
    let review = review_index.effective_decision_for(finding);
    let label = effective_review_confidence_label(finding, review.as_ref()).to_ascii_lowercase();
    vec![
        proof.as_str().to_string(),
        proof.label().to_ascii_lowercase(),
        label.clone(),
        confidence_bucket(&label).to_string(),
    ]
}

fn confidence_bucket(label: &str) -> &'static str {
    let percent = label.trim_end_matches('%').parse::<u8>().ok();
    match percent {
        Some(80..=u8::MAX) => "high",
        Some(50..=79) => "medium",
        Some(_) => "low",
        None => "unknown",
    }
}

pub(super) fn status_values_match(wanted: &[String], actual: &str) -> bool {
    wanted.is_empty()
        || wanted
            .iter()
            .filter_map(|value| canonical_status_alias(value))
            .any(|wanted| wanted == actual)
}

fn canonical_status_alias(value: &str) -> Option<&'static str> {
    Some(match value {
        "confirmed" | "runtime" | "verified" => "verified",
        "dismissed" | "false-positive" | "false_positive" | "rejected" | "suppressed" => "rejected",
        "deferred" | "needs-review" | "needs_review" | "open" | "pending" => "open",
        _ => return None,
    })
}

pub(super) fn canonical_finding_status(
    finding: &Finding,
    review_index: &EffectiveReviewStateIndex,
) -> &'static str {
    let decision = review_index.effective_decision_for(finding);
    if effective_review_decision_conflict_label(finding, decision.as_ref()).is_some() {
        return "open";
    }
    match decision.map(|decision| decision.verdict()) {
        Some(ReviewDecisionVerdict::Confirmed | ReviewDecisionVerdict::ToFix) => "verified",
        Some(
            ReviewDecisionVerdict::RejectedFalsePositive
            | ReviewDecisionVerdict::Suppressed
            | ReviewDecisionVerdict::AcceptedRisk,
        ) => "rejected",
        _ => proof_status(finding),
    }
}

fn proof_status(finding: &Finding) -> &'static str {
    match lifecycle_status_label(finding).as_str() {
        "runtime_verified" | "verified_static" => "verified",
        "runtime_not_reproduced" | "statically_rejected" | "suppressed" => "rejected",
        _ => match ProofConfidence::classify(finding) {
            ProofConfidence::Confirmed => "verified",
            ProofConfidence::Dismissed => "rejected",
            ProofConfidence::Likely | ProofConfidence::Unverified => "open",
        },
    }
}

pub(super) fn searchable_fields(finding: &Finding) -> Vec<String> {
    let mut fields = vec![
        finding.title.to_ascii_lowercase(),
        finding.message.to_ascii_lowercase(),
        finding.rule_id.to_ascii_lowercase(),
        finding.file_path.to_ascii_lowercase(),
    ];
    fields.extend(finding.evidence.iter().flat_map(|evidence| {
        [
            evidence.snippet.to_ascii_lowercase(),
            evidence.rationale.to_ascii_lowercase(),
            evidence.file_path.to_ascii_lowercase(),
        ]
    }));
    fields.extend(finding.sources.iter().flat_map(|source| {
        [
            source.tool.to_ascii_lowercase(),
            source.source_signature.to_ascii_lowercase(),
            source
                .vuln_source
                .map(|value| value.as_str().to_string())
                .unwrap_or_default(),
        ]
    }));
    fields
}
