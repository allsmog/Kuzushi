use super::prelude::*;
use super::*;

pub(super) fn proof_evidence_from_object(
    object: Option<&Map<String, Value>>,
    fallback_label: &str,
) -> Vec<StaticProofEvidence> {
    let Some(object) = object else {
        return Vec::new();
    };
    let label = read_object_string(object, &["kind", "label"]).unwrap_or_else(|| {
        fallback_label
            .split('_')
            .next()
            .unwrap_or(fallback_label)
            .to_string()
    });
    let detail = read_object_string(object, &["description", "detail", "explanation"])
        .unwrap_or_else(|| label.clone());
    let mut evidence = StaticProofEvidence::new(label, detail);
    if let Some(citation) = proof_citation_from_object(object) {
        evidence = evidence.with_citation(citation);
    }
    vec![evidence]
}

pub(super) fn proof_assessment_from_object(
    object: Option<&Map<String, Value>>,
) -> StaticProofAssessment {
    let Some(object) = object else {
        return StaticProofAssessment::new(StaticProofAssessmentStatus::Unknown, "");
    };
    let status = read_object_string(object, &["status"])
        .as_deref()
        .map(parse_assessment_status)
        .unwrap_or(StaticProofAssessmentStatus::Unknown);
    let explanation = read_object_string(object, &["explanation", "description", "rationale"])
        .unwrap_or_default();
    StaticProofAssessment::new(status, explanation)
}

pub(super) fn parse_assessment_status(value: &str) -> StaticProofAssessmentStatus {
    match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "present" => StaticProofAssessmentStatus::Present,
        "absent" => StaticProofAssessmentStatus::Absent,
        "not_applicable" | "n/a" | "na" => StaticProofAssessmentStatus::NotApplicable,
        _ => StaticProofAssessmentStatus::Unknown,
    }
}

pub(super) fn proof_citations_from_array(items: Option<&Vec<Value>>) -> Vec<StaticProofCitation> {
    items
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter_map(proof_citation_from_object)
        .collect()
}

pub(super) fn proof_citation_from_object(
    object: &Map<String, Value>,
) -> Option<StaticProofCitation> {
    let file_path = read_object_string(object, &["filePath", "file_path"])?;
    let start_line = read_object_u64(object, &["startLine", "start_line"])?;
    let end_line = read_object_u64(object, &["endLine", "end_line"]).unwrap_or(start_line);
    if start_line == 0
        || end_line == 0
        || start_line > u32::MAX as u64
        || end_line > u32::MAX as u64
    {
        return None;
    }
    let mut citation = StaticProofCitation::new(file_path, start_line as u32, end_line as u32);
    if let Some(snippet) = read_object_string(object, &["snippet"]) {
        citation = citation.with_snippet(snippet);
    }
    if let Some(hash) = read_object_string(
        object,
        &[
            "snippetHash",
            "snippet_hash",
            "contentHash",
            "content_hash",
            "sourceContentHash",
        ],
    ) {
        citation = citation.with_snippet_hash(hash);
    }
    Some(citation)
}

pub(super) fn read_nested_object_string(
    object: &Map<String, Value>,
    nested_key: &str,
    keys: &[&str],
) -> Option<String> {
    object
        .get(nested_key)
        .and_then(Value::as_object)
        .and_then(|nested| read_object_string(nested, keys))
}

pub(super) fn read_object_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn read_object_u64(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        object.get(*key).and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str()?.trim().parse::<u64>().ok())
        })
    })
}

pub(super) fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub(super) fn contains_forbidden_runtime_claim(claim: &StaticProofClaim) -> bool {
    let mut text = String::new();
    text.push_str(claim.path_explanation.as_deref().unwrap_or_default());
    text.push('\n');
    text.push_str(claim.local_direct_reason.as_deref().unwrap_or_default());
    text.push('\n');
    text.push_str(&claim.sanitizer_assessment.explanation);
    text.push('\n');
    text.push_str(&claim.guard_assessment.explanation);
    for evidence in claim
        .source_or_entrypoint_evidence
        .iter()
        .chain(claim.sink_evidence.iter())
    {
        text.push('\n');
        text.push_str(&evidence.label);
        text.push('\n');
        text.push_str(&evidence.detail);
    }
    for item in claim
        .assumptions
        .iter()
        .chain(claim.missing_evidence.iter())
    {
        text.push('\n');
        text.push_str(item);
    }
    let lower = text.to_ascii_lowercase();
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

pub(super) fn nonempty_option(value: &Option<String>) -> bool {
    value
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
}

pub(super) fn has_nonempty(values: &[String]) -> bool {
    values.iter().any(|value| !value.trim().is_empty())
}

pub(super) fn normalize_snippet(value: &str) -> String {
    value.replace("\r\n", "\n").trim_end().to_string()
}
