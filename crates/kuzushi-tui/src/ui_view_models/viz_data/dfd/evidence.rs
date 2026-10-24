use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct SecurityEvidence {
    pub references: Vec<String>,
    pub files: Vec<String>,
}

#[derive(Default)]
struct EvidencePaths {
    references: BTreeSet<String>,
    files: BTreeSet<String>,
}

pub(super) fn security_evidence(value: &Value) -> SecurityEvidence {
    let mut paths = EvidencePaths::default();
    collect_direct_locators(value, &mut paths);
    for row in array_rows(value.get("affectedFiles")) {
        collect_literal_row(row, &mut paths);
    }
    collect_source_refs(value, &mut paths);
    for field in ["evidenceRefs", "evidence", "evidenceAnchors"] {
        collect_evidence_value(&value[field], &mut paths);
    }
    SecurityEvidence {
        references: paths.references.into_iter().collect(),
        files: paths.files.into_iter().collect(),
    }
}

pub(super) fn element_file_paths(document: &Value) -> BTreeMap<String, Vec<String>> {
    ["nodes", "flows", "trustBoundaries"]
        .into_iter()
        .flat_map(|field| array_rows(document.get("dfd").and_then(|dfd| dfd.get(field))))
        .filter_map(element_paths)
        .collect()
}

fn element_paths(value: &Value) -> Option<(String, Vec<String>)> {
    let id = value.get("id")?.as_str()?;
    let files = security_evidence(value).files;
    (!files.is_empty()).then_some((id.into(), files))
}

fn collect_source_refs(value: &Value, paths: &mut EvidencePaths) {
    for reference in array_rows(value.get("sourceRefs")).filter_map(Value::as_str) {
        if let Some(path) = literal_source_ref_path(reference) {
            paths.references.insert(reference.into());
            paths.files.insert(path.into());
        }
    }
}

fn literal_source_ref_path(reference: &str) -> Option<&str> {
    let (path, line) = reference.rsplit_once(':')?;
    let line = line.parse::<u32>().ok()?;
    (line > 0 && !path.trim().is_empty()).then_some(path)
}

fn array_rows(value: Option<&Value>) -> impl Iterator<Item = &Value> {
    value.and_then(Value::as_array).into_iter().flatten()
}

fn collect_literal_row(value: &Value, paths: &mut EvidencePaths) {
    if let Some(path) = value.as_str() {
        paths.literal(path);
    } else {
        collect_direct_locators(value, paths);
    }
}

fn collect_direct_locators(value: &Value, paths: &mut EvidencePaths) {
    for pointer in [
        "/path",
        "/filePath",
        "/sourcePath",
        "/sourceLocation/path",
        "/location/path",
        "/locator/path",
    ] {
        if let Some(path) = value.pointer(pointer).and_then(Value::as_str) {
            paths.literal(path);
        }
    }
}

fn collect_evidence_value(value: &Value, paths: &mut EvidencePaths) {
    if let Some(candidate) = value.as_str() {
        paths.citation(candidate);
    }
    for row in array_rows(Some(value)) {
        collect_evidence_row(row, paths);
    }
}

fn collect_evidence_row(row: &Value, paths: &mut EvidencePaths) {
    if let Some(candidate) = row.as_str() {
        paths.citation(candidate);
        return;
    }
    collect_direct_locators(row, paths);
    for field in ["ref", "source"] {
        if let Some(candidate) = row[field].as_str() {
            paths.citation(candidate);
        }
    }
}

impl EvidencePaths {
    fn literal(&mut self, path: &str) {
        if !path.trim().is_empty() {
            self.references.insert(path.into());
            self.files.insert(path.into());
        }
    }

    fn citation(&mut self, candidate: &str) {
        let reference = candidate.trim().trim_matches('`');
        let path = citation_path(reference);
        if !looks_like_path(path) {
            return;
        }
        if path.chars().any(char::is_whitespace) && !candidate.trim().starts_with('`') {
            return;
        }
        self.references.insert(reference.into());
        self.files.insert(path.into());
    }
}

fn looks_like_path(path: &str) -> bool {
    path.contains('/')
        || std::path::Path::new(path).extension().is_some()
        || matches!(path, "Dockerfile" | "Makefile" | "Rakefile")
}

fn citation_path(mut value: &str) -> &str {
    value = without_line_fragment(value);
    while let Some((head, suffix)) = value.rsplit_once(':') {
        if !suffix.split('-').all(numeric_line) {
            break;
        }
        value = head;
    }
    value
}

fn without_line_fragment(value: &str) -> &str {
    match value.rsplit_once("#L") {
        Some((path, fragment)) if fragment.split("-L").all(numeric_line) => path,
        _ => value,
    }
}

fn numeric_line(value: &str) -> bool {
    value.parse::<u32>().is_ok()
}

#[cfg(test)]
mod tests;
