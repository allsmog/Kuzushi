//! Threat-model verification: check a document's claims against the target.
//!
//! Threat models arrive from three unverified paths — hand-dropped files,
//! `userEdited` documents, and version restores — and every consumer trusts
//! the file absolutely. Verification grounds the document: cited paths must
//! exist (with sane line numbers), the documented revision is compared to
//! HEAD (tri-state; a non-git target is not a failure), and coverage is
//! re-measured against fresh grounding surfaces. The verdict is stamped on
//! the document; consumers warn, they never drop.

use super::*;
use anyhow::Result;
use serde::Serialize;
use std::path::Path;

const MAX_CHECKED_PATH_REFS: usize = 500;
const MAX_LISTED_MISSING: usize = 12;
const VERIFY_MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
const VERIFY_COVERAGE_MAX_ELEMENTS: usize = 40;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ThreatModelVerification {
    /// `verified` | `stale` (revision drift) | `failed` (missing citations).
    pub verdict: String,
    pub checked_paths: usize,
    pub missing_count: usize,
    /// Capped listing of missing/out-of-range citations for the operator.
    pub missing: Vec<String>,
    pub revision: RevisionCheck,
    pub coverage_considered: usize,
    pub coverage_gaps: usize,
    pub verified_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RevisionCheck {
    pub documented: Option<String>,
    pub current: Option<String>,
    pub dirty: Option<bool>,
    /// None when either side is unknown (non-git target or unstamped doc).
    pub matches: Option<bool>,
}

pub fn verify_threat_model_document(
    document: &Value,
    target: &Path,
) -> Result<ThreatModelVerification> {
    let refs = cited_path_refs(document);
    let missing = missing_citations(target, &refs);
    let revision = revision_check(document, target);
    let coverage = coverage_check(document, target)?;
    let verdict = if !missing.is_empty() {
        "failed"
    } else if revision.matches == Some(false) {
        "stale"
    } else {
        "verified"
    };
    Ok(ThreatModelVerification {
        verdict: verdict.to_string(),
        checked_paths: refs.len(),
        missing_count: missing.len(),
        missing: missing.into_iter().take(MAX_LISTED_MISSING).collect(),
        revision,
        coverage_considered: coverage.considered,
        coverage_gaps: coverage.gaps.len(),
        verified_at_ms: epoch_ms_now(),
    })
}

/// Merge the verification block into the document (replacing any prior one).
pub fn stamp_verification(document: &mut Value, verification: &ThreatModelVerification) {
    if let Some(root) = document.as_object_mut() {
        root.insert(
            "verification".to_string(),
            serde_json::to_value(verification).unwrap_or(Value::Null),
        );
    }
}

/// Cheap consumption warning: revision drift or a stamped non-verified
/// verdict. Never blocks — consumers prepend it and proceed.
pub fn verification_warning(document: &Value, target: &Path) -> Option<String> {
    let revision = revision_check(document, target);
    if revision.matches == Some(false) {
        return Some(format!(
            "threat-model warning: document was built at revision {} but the target is now at {} — cited paths and lines may be stale (run threat-model:verify)",
            short_sha(revision.documented.as_deref()),
            short_sha(revision.current.as_deref()),
        ));
    }
    match document.pointer("/verification/verdict").and_then(Value::as_str) {
        Some("failed") => Some(
            "threat-model warning: the last verification found cited paths missing from the target — treat file references as unreliable".to_string(),
        ),
        Some("stale") => Some(
            "threat-model warning: the last verification marked this document stale against the target revision".to_string(),
        ),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PathRef {
    path: String,
    line: Option<u32>,
}

/// Path-like citations from the shapes producers actually emit: bare
/// `affectedFiles` lists, `evidence` strings with a trailing `:line`, and
/// any object carrying `filePath` (+ optional `startLine`) — which covers
/// threat evidence anchors and DFD anchors wherever they nest.
fn cited_path_refs(document: &Value) -> Vec<PathRef> {
    let mut refs = Vec::new();
    collect_path_refs(document, &mut refs);
    refs.sort_by(|a, b| (&a.path, a.line).cmp(&(&b.path, b.line)));
    refs.dedup();
    refs.truncate(MAX_CHECKED_PATH_REFS);
    refs
}

fn collect_path_refs(value: &Value, refs: &mut Vec<PathRef>) {
    match value {
        Value::Object(object) => collect_object_refs(object, refs),
        Value::Array(items) => {
            for item in items {
                collect_path_refs(item, refs);
            }
        }
        _ => {}
    }
}

fn collect_object_refs(object: &serde_json::Map<String, Value>, refs: &mut Vec<PathRef>) {
    if let Some(path) = object.get("filePath").and_then(Value::as_str) {
        let line = object
            .get("startLine")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok());
        push_path_ref(refs, path, line);
    }
    for (key, child) in object {
        collect_keyed_refs(key, child, refs);
        collect_path_refs(child, refs);
    }
}

fn collect_keyed_refs(key: &str, child: &Value, refs: &mut Vec<PathRef>) {
    match key {
        "affectedFiles" | "affected_files" => {
            let paths = child.as_array().into_iter().flatten();
            for path in paths.filter_map(Value::as_str) {
                push_path_ref(refs, path, None);
            }
        }
        "evidence" => {
            if let Some(text) = child.as_str() {
                push_evidence_ref(refs, text);
            }
        }
        _ => {}
    }
}

fn push_evidence_ref(refs: &mut Vec<PathRef>, text: &str) {
    let (path, line) = match text.rsplit_once(':') {
        Some((path, digits)) if digits.chars().all(|c| c.is_ascii_digit()) && !digits.is_empty() => {
            (path, digits.parse().ok())
        }
        _ => (text, None),
    };
    if looks_like_path(path) {
        push_path_ref(refs, path, line);
    }
}

fn push_path_ref(refs: &mut Vec<PathRef>, path: &str, line: Option<u32>) {
    let path = path.trim();
    if path.is_empty() || path.contains("://") {
        return;
    }
    refs.push(PathRef {
        path: path.to_string(),
        line: line.filter(|line| *line > 0),
    });
}

/// Evidence strings are free text; only dotted relative paths count.
fn looks_like_path(candidate: &str) -> bool {
    let candidate = candidate.trim();
    !candidate.is_empty()
        && !candidate.contains(char::is_whitespace)
        && candidate.contains('.')
        && (candidate.contains('/') || Path::new(candidate).extension().is_some())
}

fn missing_citations(target: &Path, refs: &[PathRef]) -> Vec<String> {
    refs.iter()
        .filter_map(|path_ref| citation_problem(target, path_ref))
        .collect()
}

fn citation_problem(target: &Path, path_ref: &PathRef) -> Option<String> {
    let Some(resolved) = crate::findings::safe_target_path(target, &path_ref.path) else {
        return Some(format!("{} (escapes the target root)", path_ref.path));
    };
    // Directory citations are legitimate surface anchors (vendor trees,
    // workflow directories); only a wholly absent path is a failure.
    if !resolved.exists() {
        return Some(format!("{} (missing)", path_ref.path));
    }
    if !resolved.is_file() {
        return None;
    }
    let line = path_ref.line?;
    let source =
        crate::bounded_file::read_utf8_text_within(target, &resolved, VERIFY_MAX_FILE_BYTES)
            .ok()?;
    let count = source.lines().count() as u32;
    (line > count).then(|| format!("{}:{line} (file has {count} lines)", path_ref.path))
}

fn revision_check(document: &Value, target: &Path) -> RevisionCheck {
    let documented = document
        .pointer("/provenance/revision")
        .and_then(Value::as_str)
        .map(str::to_string);
    let metadata = crate::workspace::target_git_metadata(target);
    let current = metadata.as_ref().map(|meta| meta.sha.clone());
    let matches = match (documented.as_deref(), current.as_deref()) {
        (Some(documented), Some(current)) => Some(documented == current),
        _ => None,
    };
    RevisionCheck {
        documented,
        current,
        dirty: metadata.map(|meta| meta.dirty),
        matches,
    }
}

fn coverage_check(document: &Value, target: &Path) -> Result<CoverageReport> {
    let surfaces = grounding_surfaces(target, VERIFY_COVERAGE_MAX_ELEMENTS)?;
    Ok(check_coverage(document, &surfaces))
}

fn short_sha(sha: Option<&str>) -> String {
    sha.map(|sha| sha.chars().take(12).collect())
        .unwrap_or_else(|| "unknown".to_string())
}

fn epoch_ms_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod verify_tests;
