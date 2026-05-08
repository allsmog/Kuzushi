use super::*;

pub(in crate::static_proof_validator) fn proof_assessment_from_object(
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

pub(in crate::static_proof_validator) fn parse_assessment_status(
    value: &str,
) -> StaticProofAssessmentStatus {
    match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "present" => StaticProofAssessmentStatus::Present,
        "absent" => StaticProofAssessmentStatus::Absent,
        "not_applicable" | "n/a" | "na" => StaticProofAssessmentStatus::NotApplicable,
        _ => StaticProofAssessmentStatus::Unknown,
    }
}
