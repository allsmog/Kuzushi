use super::*;
use crate::findings::domain::safe_target_path;
use std::path::{Path, PathBuf};

const TARGET_ROOT_UNAVAILABLE_NOTE: &str =
    "citation-verification-unavailable: target root was unavailable at insertion time";
const SOURCE_FILE_UNAVAILABLE_NOTE: &str =
    "citation-verification-unavailable: source file was unavailable within the target at insertion time";
const UNSAFE_PATH_NOTE: &str =
    "citation-unverified: path was not a safe target-relative source path at insertion time";
const LINE_OUT_OF_RANGE_NOTE: &str =
    "citation-unverified: line was outside the source file at insertion time";
const SNIPPET_MISMATCH_NOTE: &str =
    "citation-unverified: snippet was not found on disk at insertion time";
const LIVE_CHAIN_STEP_KIND: &str = "live-chain-step";

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
    LineOutOfRange,
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
            Self::Failed(CitationFailureReason::LineOutOfRange) => Some(LINE_OUT_OF_RANGE_NOTE),
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
    if !is_target_source_citation(evidence) {
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
    let Some(window) = line_window_for_evidence(&source, evidence.line) else {
        return CitationVerification::Failed(CitationFailureReason::LineOutOfRange);
    };
    let snippet = normalize_evidence_text(&evidence.snippet);
    let haystack = normalize_evidence_text(&window);
    if snippet.is_empty() || haystack.contains(&snippet) {
        CitationVerification::Verified
    } else {
        CitationVerification::Failed(CitationFailureReason::SnippetMismatch)
    }
}

/// Disk verification applies only to evidence that structurally claims a
/// target-relative source location. This deliberately does not allowlist
/// source-role names: specialist scanners use kinds such as `template-input`
/// and `template-rendering`. A positive line anchor is the shared source
/// citation contract, matching `ground_finding_location`; runtime, URL, HTTP,
/// and reasoning evidence remain outside the filesystem trust boundary.
fn is_target_source_citation(evidence: &FindingEvidence) -> bool {
    let kind = evidence.kind.trim();
    let file_path = evidence.file_path.trim();
    !kind.eq_ignore_ascii_case("reasoning")
        && !kind.eq_ignore_ascii_case(LIVE_CHAIN_STEP_KIND)
        && evidence.request_blob.is_none()
        && evidence.response_blob.is_none()
        && !file_path.is_empty()
        && !file_path.contains("://")
        && evidence.line > 0
}

fn line_window_for_evidence(source: &str, line: u32) -> Option<String> {
    if line == 0 {
        return None;
    }
    let lines = source.lines().collect::<Vec<_>>();
    let index = line.saturating_sub(1) as usize;
    if index >= lines.len() {
        return None;
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
        let url = FindingEvidence {
            kind: "external-reference".to_string(),
            file_path: "https://example.test/advisory".to_string(),
            line: 1,
            snippet: "affected endpoint".to_string(),
            rationale: "external advisory".to_string(),
            confidence: 70,
            request_blob: None,
            response_blob: None,
        };

        let verified = verify_finding_evidence_for_insert(
            None,
            &[reasoning.clone(), http.clone(), url.clone()],
        );

        assert_eq!(verified, vec![reasoning, http, url]);
    }

    #[test]
    fn unavailable_target_preserves_empirical_live_chain_evidence() {
        let runtime = FindingEvidence {
            kind: LIVE_CHAIN_STEP_KIND.to_string(),
            file_path: "box.htb".to_string(),
            // Protect the runtime kind explicitly even if a future producer
            // adds an executed-step ordinal that looks like a source line.
            line: 7,
            snippet: "RCE step landed".to_string(),
            rationale: "command output matched the expected marker".to_string(),
            confidence: 100,
            request_blob: None,
            response_blob: None,
        };

        assert_eq!(
            citation_verification(None, &runtime),
            CitationVerification::NotApplicable
        );
        assert_eq!(
            verify_finding_evidence_for_insert(None, std::slice::from_ref(&runtime)),
            vec![runtime]
        );
    }

    #[test]
    fn arbitrary_line_anchored_source_roles_still_require_verification() {
        let mut evidence = source_evidence("src/app.rs", 2, "sink(user_input)");
        evidence.kind = "template-input".to_string();

        assert_eq!(
            citation_verification(None, &evidence),
            CitationVerification::Unavailable(CitationUnavailableReason::TargetRoot)
        );
        let verified = verify_finding_evidence_for_insert(None, &[evidence]);
        assert_downgraded(&verified[0], TARGET_ROOT_UNAVAILABLE_NOTE);
    }

    #[test]
    fn line_less_evidence_is_not_a_disk_citation() {
        let mut evidence = source_evidence("src/app.rs", 0, "sink(user_input)");
        evidence.kind = "trace-summary".to_string();

        assert_eq!(
            citation_verification(None, &evidence),
            CitationVerification::NotApplicable
        );
        assert_eq!(
            verify_finding_evidence_for_insert(None, std::slice::from_ref(&evidence)),
            vec![evidence]
        );
    }

    #[test]
    fn line_only_source_citations_require_a_target_and_existing_line() {
        let evidence = source_evidence("src/app.rs", 2, "   ");

        assert_eq!(
            citation_verification(None, &evidence),
            CitationVerification::Unavailable(CitationUnavailableReason::TargetRoot)
        );
        let unavailable = verify_finding_evidence_for_insert(None, std::slice::from_ref(&evidence));
        assert_downgraded(&unavailable[0], TARGET_ROOT_UNAVAILABLE_NOTE);

        let root = fixture_root();
        assert_eq!(
            citation_verification(Some(root.path()), &evidence),
            CitationVerification::Verified
        );
        assert_eq!(
            verify_finding_evidence_for_insert(
                Some(root.path()),
                std::slice::from_ref(&evidence),
            ),
            vec![evidence.clone()]
        );

        let outside = source_evidence("src/app.rs", 100, "");
        assert_eq!(
            citation_verification(Some(root.path()), &outside),
            CitationVerification::Failed(CitationFailureReason::LineOutOfRange)
        );
        let failed = verify_finding_evidence_for_insert(Some(root.path()), &[outside]);
        assert_downgraded(&failed[0], LINE_OUT_OF_RANGE_NOTE);
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
    fn out_of_range_lines_are_distinct_from_snippet_mismatches() {
        let root = fixture_root();
        let wrong_line = source_evidence("src/app.rs", 100, "sink(user_input)");

        assert_eq!(
            citation_verification(Some(root.path()), &wrong_line),
            CitationVerification::Failed(CitationFailureReason::LineOutOfRange)
        );
        let verified = verify_finding_evidence_for_insert(Some(root.path()), &[wrong_line]);
        assert_downgraded(&verified[0], LINE_OUT_OF_RANGE_NOTE);
        assert!(!verified[0].rationale.contains(SNIPPET_MISMATCH_NOTE));
    }

    #[test]
    fn wrong_snippets_are_reported_as_mismatches() {
        let root = fixture_root();
        let evidence = source_evidence("src/app.rs", 2, "exec(user_input)");

        assert_eq!(
            citation_verification(Some(root.path()), &evidence),
            CitationVerification::Failed(CitationFailureReason::SnippetMismatch)
        );
        let verified = verify_finding_evidence_for_insert(Some(root.path()), &[evidence]);
        assert_downgraded(&verified[0], SNIPPET_MISMATCH_NOTE);
        assert!(!verified[0].rationale.contains(LINE_OUT_OF_RANGE_NOTE));
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
