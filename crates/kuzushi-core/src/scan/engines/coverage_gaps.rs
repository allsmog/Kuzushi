//! Paths a scan engine's traversal reached but could not read.
//!
//! A walker that drops an unreadable directory silently reports a clean tree
//! it never opened: the subtree contributes no findings, no `filesScanned`,
//! and no `filesSkipped`, so nothing in the report distinguishes "nothing is
//! there" from "we could not look". Engines that tolerate an I/O failure
//! rather than aborting the whole scan record it here, and their reports
//! disclose it beside the counts.

use serde::{Deserialize, Serialize};
use std::fs;
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

/// List `dir`, recording the failures a walk would otherwise swallow: the
/// directory itself when it cannot be opened, and each entry the iterator
/// cannot yield. `None` means the directory was never listed, so the caller
/// has no entries to visit — not that it was empty.
pub(crate) fn read_dir_entries(
    root: &Path,
    dir: &Path,
    gaps: &mut CoverageGaps,
) -> Option<Vec<fs::DirEntry>> {
    let read_dir = match fs::read_dir(dir) {
        Ok(read_dir) => read_dir,
        Err(error) => {
            gaps.record(root, dir, CoverageGapKind::Directory, &error);
            return None;
        }
    };
    let mut entries = Vec::new();
    for entry in read_dir {
        match entry {
            Ok(entry) => entries.push(entry),
            // The failing entry has no name to report, so the directory
            // holding it is what the disclosure can honestly name.
            Err(error) => gaps.record(root, dir, CoverageGapKind::Entry, &error),
        }
    }
    Some(entries)
}

fn gap_line(gap: &CoverageGap) -> String {
    format!("    - {} {}: {}", gap.kind.as_str(), gap.path, gap.reason)
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

    #[test]
    fn an_unlistable_directory_yields_no_entries_and_one_gap() {
        let temp = tempfile::tempdir().unwrap();
        let mut gaps = CoverageGaps::default();

        let entries = read_dir_entries(temp.path(), &temp.path().join("vanished"), &mut gaps);

        assert!(entries.is_none());
        assert_eq!(gaps.gaps[0].kind, CoverageGapKind::Directory);
        assert_eq!(gaps.gaps[0].path, "vanished");
    }

    #[test]
    fn a_listable_directory_records_nothing() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.tf"), "").unwrap();
        let mut gaps = CoverageGaps::default();

        let entries = read_dir_entries(temp.path(), temp.path(), &mut gaps).unwrap();

        assert_eq!(entries.len(), 1);
        assert!(gaps.is_empty());
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
