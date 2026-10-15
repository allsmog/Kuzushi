//! Paths a scan engine's traversal reached but could not read.
//!
//! A walker that drops an unreadable directory silently reports a clean tree
//! it never opened: the subtree contributes no findings, no `filesScanned`,
//! and no `filesSkipped`, so nothing in the report distinguishes "nothing is
//! there" from "we could not look". Engines that tolerate an I/O failure
//! rather than aborting the whole scan record it here, and their reports
//! disclose it beside the counts.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

/// How many gaps a report names individually. An unreadable tree can hold
/// arbitrarily many, and the disclosure is a receipt, not an inventory.
const MAX_NAMED_GAPS: usize = 50;

/// How many named gaps the human-readable output prints before summarizing.
const MAX_RENDERED_GAPS: usize = 5;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageGapKind {
    /// A directory that could not be listed. Its whole subtree is unexamined.
    Directory,
    /// A directory entry whose name or type could not be read.
    Entry,
    /// A file the walk selected but the engine could not read.
    File,
}

impl CoverageGapKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::Entry => "entry",
            Self::File => "file",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoverageGap {
    /// Target-relative where possible, absolute when the path sits outside
    /// the scanned root.
    pub path: String,
    pub kind: CoverageGapKind,
    pub reason: String,
}

/// The unread paths of one traversal, plus a count of the ones past the
/// naming cap so the total stays truthful.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoverageGaps {
    pub gaps: Vec<CoverageGap>,
    /// Gaps counted but not named, because `gaps` reached its cap.
    pub unnamed: usize,
}

impl CoverageGaps {
    pub(crate) fn record(
        &mut self,
        root: &Path,
        path: &Path,
        kind: CoverageGapKind,
        error: &io::Error,
    ) {
        if self.gaps.len() >= MAX_NAMED_GAPS {
            self.unnamed += 1;
            return;
        }
        self.gaps.push(CoverageGap {
            path: relative_display(root, path),
            kind,
            reason: error.to_string(),
        });
    }

    pub fn total(&self) -> usize {
        self.gaps.len() + self.unnamed
    }

    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// Report lines disclosing the gap, or nothing when the walk read
    /// everything it reached. Callers append these to their header block.
    pub(crate) fn disclosure_lines(&self) -> Vec<String> {
        if self.is_empty() {
            return Vec::new();
        }
        let mut lines = vec![format!(
            "  Unread paths: {} (coverage is incomplete)",
            self.total()
        )];
        lines.extend(self.gaps.iter().take(MAX_RENDERED_GAPS).map(gap_line));
        let rendered = self.gaps.len().min(MAX_RENDERED_GAPS);
        if self.total() > rendered {
            lines.push(format!("    ... and {} more", self.total() - rendered));
        }
        lines
    }
}

impl CoverageGaps {
    /// One entry per unread path, for `ScanEngineOutput::scan_errors`. The
    /// aggregate scan counts these as parts of the target that went
    /// unanalyzed, so the paths past the naming cap contribute an entry of
    /// their own rather than dropping out of that count.
    pub(crate) fn scan_error_lines(&self) -> Vec<String> {
        let mut lines = self
            .gaps
            .iter()
            .map(|gap| format!("unread {}", gap_description(gap)))
            .collect::<Vec<_>>();
        if self.unnamed > 0 {
            lines.push(format!("{} further unread path(s) not named", self.unnamed));
        }
        lines
    }
}

fn gap_line(gap: &CoverageGap) -> String {
    format!("    - {}", gap_description(gap))
}

fn gap_description(gap: &CoverageGap) -> String {
    format!("{} {}: {}", gap.kind.as_str(), gap.path, gap.reason)
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn denied() -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, "Permission denied")
    }

    fn root() -> PathBuf {
        PathBuf::from("/srv/target")
    }

    #[test]
    fn an_empty_walk_discloses_nothing() {
        assert!(CoverageGaps::default().disclosure_lines().is_empty());
    }

    #[test]
    fn a_recorded_gap_is_named_relative_to_the_root() {
        let mut gaps = CoverageGaps::default();
        gaps.record(
            &root(),
            Path::new("/srv/target/config"),
            CoverageGapKind::Directory,
            &denied(),
        );

        assert_eq!(gaps.total(), 1);
        assert_eq!(
            gaps.disclosure_lines(),
            vec![
                "  Unread paths: 1 (coverage is incomplete)".to_string(),
                "    - directory config: Permission denied".to_string(),
            ]
        );
    }

    #[test]
    fn a_path_outside_the_root_keeps_its_absolute_name() {
        let mut gaps = CoverageGaps::default();
        gaps.record(
            &root(),
            Path::new("/etc/shadow"),
            CoverageGapKind::File,
            &denied(),
        );

        assert_eq!(gaps.gaps[0].path, "/etc/shadow");
    }

    /// `kuzushi scan` has no coverage field, so it fails when an engine
    /// reports any unanalyzed part. Every gap has to reach that list, the
    /// unnamed remainder included, or the umbrella run counts wrong.
    #[test]
    fn every_gap_reaches_the_aggregate_scan_error_list() {
        let mut gaps = CoverageGaps::default();
        for index in 0..MAX_NAMED_GAPS + 2 {
            gaps.record(
                &root(),
                &root().join(format!("dir{index}")),
                CoverageGapKind::Directory,
                &denied(),
            );
        }

        let lines = gaps.scan_error_lines();

        assert_eq!(lines.len(), MAX_NAMED_GAPS + 1);
        assert_eq!(lines[0], "unread directory dir0: Permission denied");
        assert_eq!(lines.last().unwrap(), "2 further unread path(s) not named");
    }

    #[test]
    fn a_complete_walk_reports_no_aggregate_scan_error() {
        assert!(CoverageGaps::default().scan_error_lines().is_empty());
    }

    #[test]
    fn gaps_past_the_naming_cap_stay_counted() {
        let mut gaps = CoverageGaps::default();
        for index in 0..MAX_NAMED_GAPS + 7 {
            gaps.record(
                &root(),
                &root().join(format!("dir{index}")),
                CoverageGapKind::Directory,
                &denied(),
            );
        }

        assert_eq!(gaps.gaps.len(), MAX_NAMED_GAPS);
        assert_eq!(gaps.unnamed, 7);
        assert_eq!(gaps.total(), MAX_NAMED_GAPS + 7);
        let lines = gaps.disclosure_lines();
        assert_eq!(
            lines[0],
            format!(
                "  Unread paths: {} (coverage is incomplete)",
                MAX_NAMED_GAPS + 7
            )
        );
        assert_eq!(
            lines.last().unwrap(),
            &format!("    ... and {} more", MAX_NAMED_GAPS + 7 - MAX_RENDERED_GAPS)
        );
    }
}
