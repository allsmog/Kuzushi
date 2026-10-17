//! Import grounding: verify an externally-sourced finding's citation
//! against the target tree.
//!
//! Native scanner findings are born from the code they cite; imported
//! findings arrive as claims. Grounding checks the claim at ingest (and on
//! demand via `findings:ground`): does the cited file exist, and does the
//! cited snippet still sit near the cited line at the current revision?
//! The verdict is descriptive — grounding never retires a finding.

use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

use super::Finding;

const GROUNDING_MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
/// Snippet matching tolerates the same ±4-line window as the evidence
/// citation check at insert time (`citation_matches_disk`).
const GROUNDING_LINE_WINDOW: usize = 4;

/// Where an imported finding's citation stands against the target tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GroundingStatus {
    /// The cited file exists and the citation (line, and snippet when one
    /// was given) matches at `revision`.
    Grounded { revision: Option<String> },
    /// The file exists but the citation no longer sits where claimed.
    /// `nearest_line` is where the snippet (or file end) was found;
    /// 0 means the snippet was not found anywhere in the file.
    LineDrift {
        nearest_line: u32,
        revision: Option<String>,
    },
    /// The cited file does not exist under the target (or escapes it).
    FileMissing { revision: Option<String> },
    /// Nothing checkable: URL citation or no line anchor.
    NotApplicable,
    /// The primary anchor could not be checked at the persistence boundary.
    Unavailable { reason: String },
}

impl GroundingStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Grounded { .. } => "grounded",
            Self::LineDrift { .. } => "line_drift",
            Self::FileMissing { .. } => "file_missing",
            Self::NotApplicable => "not_applicable",
            Self::Unavailable { .. } => "unavailable",
        }
    }

    pub fn is_grounded(&self) -> bool {
        matches!(self, Self::Grounded { .. })
    }
}

/// Ground one citation against the target tree. `revision` is the target's
/// current HEAD (callers compute it once per batch via
/// `workspace::git_metadata::target_git_metadata`).
pub fn ground_finding_location(
    root: &Path,
    file_path: &str,
    line: u32,
    snippet: &str,
    revision: Option<&str>,
) -> GroundingStatus {
    if file_path.is_empty() || file_path.contains("://") || line == 0 {
        return GroundingStatus::NotApplicable;
    }
    let revision = revision.map(str::to_string);
    let Some(path) = safe_target_path(root, file_path) else {
        return GroundingStatus::FileMissing { revision };
    };
    let source =
        match crate::bounded_file::read_utf8_text_within(root, &path, GROUNDING_MAX_FILE_BYTES) {
            Ok(source) => source,
            Err(error) => return grounding_read_error(error, revision),
        };
    ground_against_source(&source, line, snippet, revision)
}

pub(crate) fn grounding_read_error(
    error: std::io::Error,
    revision: Option<String>,
) -> GroundingStatus {
    if error.kind() == std::io::ErrorKind::NotFound {
        return GroundingStatus::FileMissing { revision };
    }
    GroundingStatus::Unavailable {
        reason: format!("Citation source could not be inspected: {error}"),
    }
}

/// Resolve a cited (possibly hostile) relative path strictly inside the
/// target root. Absolute paths, prefixes, and `..` components are refused.
/// Shared with the evidence citation check at finding-insert time.
pub(crate) fn safe_target_path(target_root: &Path, raw_path: &str) -> Option<PathBuf> {
    let mut relative = PathBuf::new();
    for component in Path::new(raw_path).components() {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) | Component::ParentDir => return None,
        }
    }
    Some(target_root.join(relative))
}

pub(crate) fn ground_against_source(
    source: &str,
    line: u32,
    snippet: &str,
    revision: Option<String>,
) -> GroundingStatus {
    let lines = source.lines().collect::<Vec<_>>();
    let cited_index = line.saturating_sub(1) as usize;
    let snippet = normalize_grounding_text(snippet);
    if snippet.is_empty() {
        if cited_index < lines.len() {
            return GroundingStatus::Grounded { revision };
        }
        return GroundingStatus::LineDrift {
            nearest_line: lines.len() as u32,
            revision,
        };
    }
    if window_contains(&lines, cited_index, &snippet) {
        return GroundingStatus::Grounded { revision };
    }
    GroundingStatus::LineDrift {
        nearest_line: nearest_snippet_line(&lines, cited_index, &snippet),
        revision,
    }
}

fn window_contains(lines: &[&str], center: usize, normalized_snippet: &str) -> bool {
    if lines.is_empty() {
        return false;
    }
    let start = center.saturating_sub(GROUNDING_LINE_WINDOW);
    let end = (center + GROUNDING_LINE_WINDOW + 1).min(lines.len());
    if start >= end {
        return false;
    }
    normalize_grounding_text(&lines[start..end].join("\n")).contains(normalized_snippet)
}

/// 1-based line whose ±window contains the snippet, closest to the cited
/// line; 0 when the snippet is gone from the file entirely.
fn nearest_snippet_line(lines: &[&str], cited_index: usize, normalized_snippet: &str) -> u32 {
    if !normalize_grounding_text(&lines.join("\n")).contains(normalized_snippet) {
        return 0;
    }
    (0..lines.len())
        .filter(|index| window_contains(lines, *index, normalized_snippet))
        .min_by_key(|index| index.abs_diff(cited_index))
        .map(|index| index as u32 + 1)
        .unwrap_or(0)
}

fn normalize_grounding_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Honesty note for triage prompts: tell the model when an imported
/// finding's anchor is stale instead of letting it assume the citation
/// still holds. `None` for grounded/native findings.
pub fn grounding_prompt_note(finding: &Finding) -> Option<String> {
    match finding.grounding.as_ref()? {
        GroundingStatus::Grounded { .. } | GroundingStatus::NotApplicable => None,
        GroundingStatus::Unavailable { reason } => Some(format!("finding primary anchor unavailable: {reason}")),
        GroundingStatus::LineDrift {
            nearest_line,
            revision,
        } => Some(format!(
            "imported finding: the cited line has drifted at revision {} — the snippet now sits nearest line {}; re-anchor before judging the code path",
            revision_label(revision.as_deref()),
            nearest_line,
        )),
        GroundingStatus::FileMissing { revision } => Some(format!(
            "imported finding: the cited file is missing at revision {} — confirm the code truly no longer exists rather than assuming line drift",
            revision_label(revision.as_deref()),
        )),
    }
}

fn revision_label(revision: Option<&str>) -> String {
    let Some(revision) = revision.map(str::trim).filter(|value| !value.is_empty()) else {
        return "unknown (not a git checkout)".to_string();
    };
    revision.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(
            temp.path().join("src/app.py"),
            "import os\n\ndef download(path):\n    full = os.path.join(base, path)\n    return open(full).read()\n",
        )
        .unwrap();
        temp
    }

    #[test]
    fn oversized_existing_citation_is_unavailable_and_remains_on_disk() {
        let root = fixture_root();
        let path = root.path().join("src/app.py");
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len((GROUNDING_MAX_FILE_BYTES + 1) as u64).unwrap();
        let status = ground_finding_location(root.path(), "src/app.py", 1, "", None);
        assert!(matches!(status, GroundingStatus::Unavailable { .. }));
        assert!(path.is_file());
    }

    #[test]
    fn citation_read_errors_distinguish_absence_from_uninspectable_source() {
        assert!(matches!(
            grounding_read_error(std::io::Error::from(std::io::ErrorKind::NotFound), None),
            GroundingStatus::FileMissing { .. }
        ));
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::InvalidData,
        ] {
            assert!(matches!(
                grounding_read_error(std::io::Error::from(kind), None),
                GroundingStatus::Unavailable { .. }
            ));
        }
    }

    #[test]
    fn grounded_when_snippet_sits_within_the_window() {
        let root = fixture_root();
        let status = ground_finding_location(
            root.path(),
            "src/app.py",
            4,
            "os.path.join(base, path)",
            Some("abc123"),
        );
        assert_eq!(
            status,
            GroundingStatus::Grounded {
                revision: Some("abc123".to_string())
            }
        );
        assert!(status.is_grounded());
    }

    #[test]
    fn line_drift_reports_the_nearest_matching_line() {
        let root = fixture_root();
        // Cited line 40 is far from the real join on line 4 (window is ±4).
        let status = ground_finding_location(
            root.path(),
            "src/app.py",
            40,
            "os.path.join(base, path)",
            None,
        );
        match status {
            GroundingStatus::LineDrift { nearest_line, .. } => {
                assert!(
                    (1..=5).contains(&nearest_line),
                    "nearest window line should bracket the real line 4, got {nearest_line}"
                );
            }
            other => panic!("expected line drift, got {other:?}"),
        }
    }

    #[test]
    fn missing_file_and_traversal_paths_are_file_missing() {
        let root = fixture_root();
        let missing =
            ground_finding_location(root.path(), "src/deleted.py", 3, "anything", Some("r1"));
        assert_eq!(
            missing,
            GroundingStatus::FileMissing {
                revision: Some("r1".to_string())
            }
        );
        for hostile in ["../../etc/passwd", "/etc/passwd"] {
            assert_eq!(
                ground_finding_location(root.path(), hostile, 1, "root:x", None),
                GroundingStatus::FileMissing { revision: None },
                "{hostile} must not escape the target root"
            );
        }
    }

    #[test]
    fn urls_and_zero_lines_are_not_applicable() {
        let root = fixture_root();
        assert_eq!(
            ground_finding_location(root.path(), "https://example.com/x", 3, "s", None),
            GroundingStatus::NotApplicable
        );
        assert_eq!(
            ground_finding_location(root.path(), "src/app.py", 0, "s", None),
            GroundingStatus::NotApplicable
        );
    }

    #[test]
    fn prompt_note_speaks_only_for_stale_anchors() {
        let mut finding = Finding::default();
        assert_eq!(grounding_prompt_note(&finding), None, "native finding");
        finding.grounding = Some(GroundingStatus::Grounded { revision: None });
        assert_eq!(grounding_prompt_note(&finding), None);
        finding.grounding = Some(GroundingStatus::FileMissing {
            revision: Some("deadbeefcafe0123".to_string()),
        });
        let note = grounding_prompt_note(&finding).unwrap();
        assert!(note.contains("cited file is missing"));
        assert!(
            note.contains("deadbeefcafe"),
            "revision is truncated in: {note}"
        );
        finding.grounding = Some(GroundingStatus::LineDrift {
            nearest_line: 7,
            revision: None,
        });
        let drift = grounding_prompt_note(&finding).unwrap();
        assert!(drift.contains("nearest line 7"));
    }
}

#[cfg(test)]
mod literal_path_tests {
    use super::*;

    #[test]
    fn source_paths_preserve_literal_whitespace_and_still_reject_traversal() {
        let root = Path::new("/owned-repository");
        assert_eq!(
            safe_target_path(root, " owned.c "),
            Some(root.join(" owned.c "))
        );
        assert!(safe_target_path(root, "../outside.c").is_none());
        assert!(safe_target_path(root, "/outside.c").is_none());
    }
}

#[cfg(test)]
mod literal_grounding_paths {
    use super::*;

    #[test]
    fn grounding_does_not_redirect_a_literal_whitespace_filename() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("owned.c"), "other content\n").unwrap();
        std::fs::write(root.path().join(" owned.c "), "literal source marker\n").unwrap();
        assert!(ground_finding_location(
            root.path(),
            " owned.c ",
            1,
            "literal source marker",
            None
        )
        .is_grounded());
        assert!(
            !ground_finding_location(root.path(), "owned.c", 1, "literal source marker", None)
                .is_grounded()
        );
    }
}
