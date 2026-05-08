use super::prelude::*;
use super::*;

pub(crate) fn threat_affected_file_matches(threat: &Value, finding_file: &str) -> bool {
    threat
        .get("affectedFiles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|file| {
            file.get("filePath")
                .or_else(|| file.get("path"))
                .and_then(Value::as_str)
        })
        .any(|path| normalized_path(path) == normalized_path(finding_file))
}

pub(crate) fn threat_related_cwe_matches(threat: &Value, finding_cwe: Option<&str>) -> bool {
    let Some(finding_cwe) = finding_cwe else {
        return false;
    };
    threat
        .get("relatedCwe")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|cwe| cwe.to_ascii_lowercase() == finding_cwe)
}

pub(crate) fn threat_text_matches(threat: &Value, corpus: &str) -> bool {
    ["category", "title", "description", "attackVector"]
        .into_iter()
        .filter_map(|key| threat.get(key).and_then(Value::as_str))
        .map(|text| text.to_ascii_lowercase())
        .filter(|text| text.len() >= 6)
        .any(|text| {
            corpus.contains(&text)
                || text
                    .split_whitespace()
                    .any(|word| word.len() >= 8 && corpus.contains(word))
        })
}

pub(crate) fn normalized_path(path: &str) -> &str {
    path.trim_start_matches("./")
}

pub(crate) fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}
