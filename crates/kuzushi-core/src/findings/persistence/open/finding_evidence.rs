use super::*;
use std::path::{Path, PathBuf};

impl FindingStore {
    pub(crate) fn verified_finding_evidence(
        &self,
        tx: &Connection,
        scan_id: &str,
        evidence: &[FindingEvidence],
    ) -> Result<Vec<FindingEvidence>> {
        let target_root = scan_target_root(tx, scan_id)?;
        Ok(verify_finding_evidence_for_insert(
            target_root.as_deref(),
            evidence,
        ))
    }
}

fn scan_target_root(tx: &Connection, scan_id: &str) -> Result<Option<PathBuf>> {
    let target: String = tx
        .query_row(
            "select target from run_states where run_id = ?1",
            params![scan_id],
            |row| row.get(0),
        )
        .with_context(|| {
            format!("scan run {scan_id:?} is required before finding evidence insert")
        })?;
    let root = PathBuf::from(target);
    Ok(root.is_dir().then_some(root))
}

fn verify_finding_evidence_for_insert(
    target_root: Option<&Path>,
    evidence: &[FindingEvidence],
) -> Vec<FindingEvidence> {
    let Some(target_root) = target_root else {
        return evidence.to_vec();
    };
    evidence
        .iter()
        .map(|item| verify_evidence_item(target_root, item))
        .collect()
}

fn verify_evidence_item(target_root: &Path, evidence: &FindingEvidence) -> FindingEvidence {
    if should_skip_disk_verification(evidence) || citation_matches_disk(target_root, evidence) {
        return evidence.clone();
    }

    let mut downgraded = evidence.clone();
    downgraded.kind = "reasoning".to_string();
    downgraded.confidence = downgraded.confidence.min(25);
    downgraded.rationale = append_unverified_citation_note(&downgraded.rationale);
    downgraded
}

fn should_skip_disk_verification(evidence: &FindingEvidence) -> bool {
    evidence.kind.trim().eq_ignore_ascii_case("reasoning")
        || evidence.request_blob.is_some()
        || evidence.response_blob.is_some()
        || evidence.file_path.trim().is_empty()
        || evidence.snippet.trim().is_empty()
}

fn citation_matches_disk(target_root: &Path, evidence: &FindingEvidence) -> bool {
    let Some(path) = safe_target_path(target_root, &evidence.file_path) else {
        return false;
    };
    let Ok(source) =
        crate::bounded_file::read_utf8_text_within(target_root, &path, 8 * 1024 * 1024)
    else {
        return false;
    };
    let snippet = normalize_evidence_text(&evidence.snippet);
    if snippet.is_empty() {
        return true;
    }
    let haystack = line_window_for_evidence(&source, evidence.line)
        .map(|window| normalize_evidence_text(&window))
        .unwrap_or_else(|| normalize_evidence_text(&source));
    haystack.contains(&snippet)
}

use crate::findings::domain::safe_target_path;

fn line_window_for_evidence(source: &str, line: u32) -> Option<String> {
    if line == 0 {
        return None;
    }
    let lines = source.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return Some(String::new());
    }
    let index = line.saturating_sub(1) as usize;
    if index >= lines.len() {
        return Some(String::new());
    }
    let start = index.saturating_sub(4);
    let end = (index + 5).min(lines.len());
    Some(lines[start..end].join("\n"))
}

fn normalize_evidence_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn append_unverified_citation_note(rationale: &str) -> String {
    const NOTE: &str = "citation-unverified: snippet was not found on disk at insertion time";
    if rationale.trim().is_empty() {
        NOTE.to_string()
    } else if rationale.contains(NOTE) {
        rationale.to_string()
    } else {
        format!("{}\n{NOTE}", rationale.trim())
    }
}
