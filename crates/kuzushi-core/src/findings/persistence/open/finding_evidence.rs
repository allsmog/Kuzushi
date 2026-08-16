use super::*;
use crate::findings::domain::safe_target_path;
use std::path::{Path, PathBuf};

const TARGET_ROOT_UNAVAILABLE_NOTE: &str =
    "citation-verification-unavailable: target root was unavailable at insertion time";
const SOURCE_FILE_UNAVAILABLE_NOTE: &str =
    "citation-verification-unavailable: source file was unavailable within the target at insertion time";
const UNSAFE_PATH_NOTE: &str =
    "citation-unverified: path was not a safe target-relative source path at insertion time";
const SNIPPET_MISMATCH_NOTE: &str =
    "citation-unverified: snippet was not found on disk at insertion time";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CitationVerification {
    NotApplicable,
    Verified,
    Unavailable(CitationUnavailableReason),
    Failed(CitationFailureReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CitationUnavailableReason {
    TargetRoot,
    SourceFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CitationFailureReason {
    UnsafePath,
    SnippetMismatch,
}

impl CitationVerification {
    fn downgrade_note(self) -> Option<&'static str> {
        match self {
            Self::NotApplicable | Self::Verified => None,
            Self::Unavailable(CitationUnavailableReason::TargetRoot) => {
                Some(TARGET_ROOT_UNAVAILABLE_NOTE)
            }
            Self::Unavailable(CitationUnavailableReason::SourceFile) => {
                Some(SOURCE_FILE_UNAVAILABLE_NOTE)
            }
            Self::Failed(CitationFailureReason::UnsafePath) => Some(UNSAFE_PATH_NOTE),
            Self::Failed(CitationFailureReason::SnippetMismatch) => Some(SNIPPET_MISMATCH_NOTE),
        }
    }
}

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
    evidence
        .iter()
        .map(|item| verify_evidence_item(target_root, item))
        .collect()
}

fn verify_evidence_item(
    target_root: Option<&Path>,
    evidence: &FindingEvidence,
) -> FindingEvidence {
    let Some(note) = citation_verification(target_root, evidence).downgrade_note() else {
        return evidence.clone();
    };

    let mut downgraded = evidence.clone();
    downgraded.kind = "reasoning".to_string();
    downgraded.confidence = downgraded.confidence.min(25);
    downgraded.rationale = append_citation_note(&downgraded.rationale, note);
    downgraded
}

fn citation_verification(
    target_root: Option<&Path>,
    evidence: &FindingEvidence,
) -> CitationVerification {
    if should_skip_disk_verification(evidence) {
        return CitationVerification::NotApplicable;
    }
    let Some(target_root) = target_root else {
        return CitationVerification::Unavailable(CitationUnavailableReason::TargetRoot);
    };
    let Some(path) = safe_target_path(target_root, &evidence.file_path) else {
        return CitationVerification::Failed(CitationFailureReason::UnsafePath);
    };
    let Ok(source) =
        crate::bounded_file::read_utf8_text_within(target_root, &path, 8 * 1024 * 1024)
    else {
        return CitationVerification::Unavailable(CitationUnavailableReason::SourceFile);
    };
    let snippet = normalize_evidence_text(&evidence.snippet);
    let haystack = line_window_for_evidence(&source, evidence.line)
        .map(|window| normalize_evidence_text(&window))
        .unwrap_or_else(|| normalize_evidence_text(&source));
    if haystack.contains(&snippet) {
        CitationVerification::Verified
    } else {
        CitationVerification::Failed(CitationFailureReason::SnippetMismatch)
    }
}

fn should_skip_disk_verification(evidence: &FindingEvidence) -> bool {
    evidence.kind.trim().eq_ignore_ascii_case("reasoning")
        || evidence.request_blob.is_some()
        || evidence.response_blob.is_some()
        || evidence.file_path.trim().is_empty()
        || evidence.snippet.trim().is_empty()
}

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

fn append_citation_note(rationale: &str, note: &str) -> String {
    if rationale.trim().is_empty() {
        note.to_string()
    } else if rationale.contains(note) {
        rationale.to_string()
    } else {
        format!("{}\n{note}", rationale.trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Finding, FindingStore, Severity};

    fn source_evidence(file_path: &str, line: u32, snippet: &str) -> FindingEvidence {
        FindingEvidence {
            kind: "code".to_string(),
            file_path: file_path.to_string(),
            line,
            snippet: snippet.to_string(),
            rationale: "producer supplied source citation".to_string(),
            confidence: 90,
            request_blob: None,
            response_blob: None,
        }
    }

    fn fixture_root() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(
            temp.path().join("src/app.rs"),
            "fn handler(user_input: &str) {\n    sink(user_input);\n}\n",
        )
        .unwrap();
        temp
    }

    fn assert_downgraded(evidence: &FindingEvidence, note: &str) {
        assert_eq!(evidence.kind, "reasoning");
        assert_eq!(evidence.confidence, 25);
        assert!(evidence.rationale.contains(note), "{}", evidence.rationale);
    }

    #[test]
    fn persisted_source_evidence_fails_closed_when_target_root_is_unavailable() {
        let store = FindingStore::open_in_memory().unwrap();
        let parent = tempfile::tempdir().unwrap();
        let missing_target = parent.path().join("target-that-does-not-exist");
        let run_id = "run-evidence-target-unavailable";
        store
            .record_run_started(run_id, &missing_target, "running")
            .unwrap();
        let finding = Finding::new_tool(
            "agentic-sast",
            "rules.cwe-89",
            "src/app.rs",
            2,
            Some(2),
            Severity::High,
            "SQL injection reaches a query sink, CWE-89",
        )
        .with_evidence(vec![source_evidence(
            "src/app.rs",
            2,
            "sink(user_input)",
        )]);

        store.insert_finding(run_id, &finding).unwrap();

        let persisted = store.list_findings_for_scan_id(run_id).unwrap();
        assert_eq!(persisted.len(), 1);
        assert_downgraded(&persisted[0].evidence[0], TARGET_ROOT_UNAVAILABLE_NOTE);
    }

    #[test]
    fn unavailable_target_does_not_reclassify_non_source_evidence() {
        let reasoning = FindingEvidence {
            kind: "reasoning".to_string(),
            file_path: "src/app.rs".to_string(),
            line: 2,
            snippet: "sink(user_input)".to_string(),
            rationale: "model explanation".to_string(),
            confidence: 80,
            request_blob: None,
            response_blob: None,
        };
        let http = FindingEvidence {
            kind: "http-request".to_string(),
            file_path: "captures/request.har".to_string(),
            line: 1,
            snippet: "POST /login".to_string(),
            rationale: "captured request".to_string(),
            confidence: 95,
            request_blob: Some("POST /login HTTP/1.1".to_string()),
            response_blob: None,
        };

        let verified = verify_finding_evidence_for_insert(None, &[reasoning.clone(), http.clone()]);

        assert_eq!(verified, vec![reasoning, http]);
    }

    #[test]
    fn unsafe_paths_are_rejected_with_a_specific_reason() {
        let root = fixture_root();
        let evidence = source_evidence("../outside.rs", 1, "secret");

        assert_eq!(
            citation_verification(Some(root.path()), &evidence),
            CitationVerification::Failed(CitationFailureReason::UnsafePath)
        );
        let verified = verify_finding_evidence_for_insert(Some(root.path()), &[evidence]);
        assert_downgraded(&verified[0], UNSAFE_PATH_NOTE);
    }

    #[test]
    fn missing_source_files_are_unavailable_not_mismatched() {
        let root = fixture_root();
        let evidence = source_evidence("src/missing.rs", 2, "sink(user_input)");

        assert_eq!(
            citation_verification(Some(root.path()), &evidence),
            CitationVerification::Unavailable(CitationUnavailableReason::SourceFile)
        );
        let verified = verify_finding_evidence_for_insert(Some(root.path()), &[evidence]);
        assert_downgraded(&verified[0], SOURCE_FILE_UNAVAILABLE_NOTE);
        assert!(!verified[0].rationale.contains(SNIPPET_MISMATCH_NOTE));
    }

    #[test]
    fn wrong_lines_and_wrong_snippets_are_reported_as_mismatches() {
        let root = fixture_root();
        let wrong_line = source_evidence("src/app.rs", 100, "sink(user_input)");
        let wrong_snippet = source_evidence("src/app.rs", 2, "exec(user_input)");

        for evidence in [wrong_line, wrong_snippet] {
            assert_eq!(
                citation_verification(Some(root.path()), &evidence),
                CitationVerification::Failed(CitationFailureReason::SnippetMismatch)
            );
            let verified = verify_finding_evidence_for_insert(Some(root.path()), &[evidence]);
            assert_downgraded(&verified[0], SNIPPET_MISMATCH_NOTE);
        }
    }

    #[test]
    fn matching_source_citations_keep_their_original_trust_metadata() {
        let root = fixture_root();
        let evidence = source_evidence("src/app.rs", 2, "sink(user_input)");

        assert_eq!(
            citation_verification(Some(root.path()), &evidence),
            CitationVerification::Verified
        );
        let verified = verify_finding_evidence_for_insert(
            Some(root.path()),
            std::slice::from_ref(&evidence),
        );
        assert_eq!(verified, vec![evidence]);
    }

    #[test]
    fn citation_downgrades_are_idempotent() {
        let evidence = source_evidence("src/app.rs", 2, "sink(user_input)");
        let first = verify_finding_evidence_for_insert(None, &[evidence]);
        let second = verify_finding_evidence_for_insert(None, &first);

        assert_eq!(second, first);
        assert_eq!(
            second[0]
                .rationale
                .matches(TARGET_ROOT_UNAVAILABLE_NOTE)
                .count(),
            1
        );
    }
}
