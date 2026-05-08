use super::*;

pub(in crate::proof::static_validator) fn proof_evidence_from_object(
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
