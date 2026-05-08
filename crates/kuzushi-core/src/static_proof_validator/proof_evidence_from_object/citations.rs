use super::*;

pub(in crate::static_proof_validator) fn proof_citations_from_array(
    items: Option<&Vec<Value>>,
) -> Vec<StaticProofCitation> {
    items
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter_map(proof_citation_from_object)
        .collect()
}

pub(in crate::static_proof_validator) fn proof_citation_from_object(
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
