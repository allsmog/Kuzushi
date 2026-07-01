//! SOURCE pane model for the Workbench command center: the finding-bearing
//! files arranged as a nested directory tree with a per-file finding count.
//! The builder is pure over the paths it is handed; the `app`-facing wrapper
//! reads `app.findings` (the IO edge) and relativizes against the target.

use super::findings::{relativize_location, target_base};
use crate::ShellApp;
use std::collections::BTreeMap;

/// Cap the rendered rows so a sprawling result can't blow the pane height.
const MAX_ROWS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceTreeModel {
    pub(crate) rows: Vec<SourceTreeRow>,
    pub(crate) file_count: usize,
    pub(crate) finding_count: usize,
    /// One guidance line shown when there are no finding-bearing files, instead
    /// of an empty pane or invented sample paths.
    pub(crate) empty_hint: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceTreeRow {
    pub(crate) depth: usize,
    pub(crate) name: String,
    pub(crate) is_dir: bool,
    /// Findings under this row: a file's own count, or a directory's subtree sum.
    pub(crate) finding_count: usize,
}

/// Build the SOURCE tree from the active findings, relativized against the
/// target so paths read `crates/foo.rs` rather than an absolute `/Users/...`.
pub(crate) fn source_tree_model(app: &ShellApp) -> SourceTreeModel {
    let base = target_base(app);
    build_source_tree(
        app.findings
            .iter()
            .map(|finding| relativize_location(finding.file_path.clone(), base.as_deref())),
    )
}

/// Pure tree builder over an iterator of repo-relative path strings (one per
/// finding; duplicate paths aggregate into a per-file count).
pub(crate) fn build_source_tree(paths: impl Iterator<Item = String>) -> SourceTreeModel {
    let mut root = TrieNode::default();
    let mut finding_count = 0;
    for path in paths {
        if insert_path(&mut root, &path) {
            finding_count += 1;
        }
    }
    let mut rows = Vec::new();
    emit_children(&root, 0, &mut rows);
    let file_count = rows.iter().filter(|row| !row.is_dir).count();
    rows.truncate(MAX_ROWS);
    SourceTreeModel {
        empty_hint: empty_hint(file_count),
        rows,
        file_count,
        finding_count,
    }
}

#[derive(Default)]
struct TrieNode {
    children: BTreeMap<String, TrieNode>,
    direct_findings: usize,
}

/// Insert one path's components into the trie, bumping the leaf's finding count.
/// Returns `false` for an empty path (nothing to count).
fn insert_path(root: &mut TrieNode, path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    let Some((last, dirs)) = parts.split_last() else {
        return false;
    };
    let mut node = root;
    for dir in dirs {
        node = node.children.entry((*dir).to_string()).or_default();
    }
    node.children
        .entry((*last).to_string())
        .or_default()
        .direct_findings += 1;
    true
}

/// Emit rows for a node's children in name order, returning the subtree count.
fn emit_children(node: &TrieNode, depth: usize, rows: &mut Vec<SourceTreeRow>) -> usize {
    let mut total = 0;
    for (name, child) in &node.children {
        total += emit_node(name, child, depth, rows);
    }
    total
}

fn emit_node(name: &str, node: &TrieNode, depth: usize, rows: &mut Vec<SourceTreeRow>) -> usize {
    if node.children.is_empty() {
        rows.push(file_row(name, depth, node.direct_findings));
        return node.direct_findings;
    }
    let index = rows.len();
    rows.push(dir_row(name, depth));
    let total = node.direct_findings + emit_children(node, depth + 1, rows);
    rows[index].finding_count = total;
    total
}

fn file_row(name: &str, depth: usize, finding_count: usize) -> SourceTreeRow {
    SourceTreeRow {
        depth,
        name: name.to_string(),
        is_dir: false,
        finding_count,
    }
}

fn dir_row(name: &str, depth: usize) -> SourceTreeRow {
    SourceTreeRow {
        depth,
        name: name.to_string(),
        is_dir: true,
        finding_count: 0,
    }
}

fn empty_hint(file_count: usize) -> Option<&'static str> {
    (file_count == 0).then_some("no finding-bearing files yet — run `scan` to populate the tree.")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(model: &SourceTreeModel) -> Vec<(usize, String, bool, usize)> {
        model
            .rows
            .iter()
            .map(|row| (row.depth, row.name.clone(), row.is_dir, row.finding_count))
            .collect()
    }

    #[test]
    fn flat_paths_nest_into_a_tree_with_per_file_counts() {
        let paths = [
            "crates/a/foo.rs",
            "crates/a/foo.rs",
            "crates/a/bar.rs",
            "crates/b/baz.rs",
        ];
        let model = build_source_tree(paths.into_iter().map(str::to_string));

        assert_eq!(model.file_count, 3, "three distinct files");
        assert_eq!(model.finding_count, 4, "four findings total");
        assert_eq!(model.empty_hint, None);

        let rows = names(&model);
        // crates(dir, subtree=4) → a(dir, 3) → bar.rs(1), foo.rs(2) → b(dir,1) → baz.rs(1)
        assert_eq!(rows[0], (0, "crates".to_string(), true, 4));
        assert_eq!(rows[1], (1, "a".to_string(), true, 3));
        assert!(rows
            .iter()
            .any(|row| row == &(2, "foo.rs".to_string(), false, 2)));
        assert!(rows
            .iter()
            .any(|row| row == &(2, "bar.rs".to_string(), false, 1)));
        assert!(rows.iter().any(|row| row == &(1, "b".to_string(), true, 1)));
    }

    #[test]
    fn no_paths_yield_an_empty_hint() {
        let model = build_source_tree(std::iter::empty());
        assert!(model.rows.is_empty());
        assert_eq!(model.file_count, 0);
        assert!(model.empty_hint.is_some());
    }

    #[test]
    fn bare_filename_has_no_directory_row() {
        let model = build_source_tree(["main.rs"].into_iter().map(str::to_string));
        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].depth, 0);
        assert!(!model.rows[0].is_dir);
    }
}
