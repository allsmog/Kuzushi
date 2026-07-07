//! SOURCE pane model for the Workbench command center: the finding-bearing
//! files arranged as a nested directory tree with a per-file finding count.
//! The builder is pure over the paths it is handed; the `app`-facing wrapper
//! reads the Workbench-visible finding projection and relativizes against the target.

use super::findings::{projected_visible_findings, relativize_location, target_base};
use super::recommendation_components;
use crate::app::ProjectScopeTreeState;
use crate::ShellApp;
use kuzushi_core::{NestedProjectKind, NestedProjectScope, NestedProjectScopeTree};
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
    pub(crate) component: Option<SourceTreeComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceTreeComponent {
    pub(crate) label: String,
    pub(crate) tier: SourceTreeComponentTier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceTreeComponentTier {
    High,
    Medium,
    Low,
}

/// Build the SOURCE tree from the active findings, relativized against the
/// target so paths read `crates/foo.rs` rather than an absolute `/Users/...`.
pub(crate) fn source_tree_model(app: &ShellApp) -> SourceTreeModel {
    let base = target_base(app);
    build_source_tree_with_components(
        projected_visible_findings(app)
            .into_iter()
            .map(|projected| {
                relativize_location(projected.finding.file_path.clone(), base.as_deref())
            }),
        component_roots(app),
    )
}

/// Pure tree builder over an iterator of repo-relative path strings (one per
/// finding; duplicate paths aggregate into a per-file count).
#[cfg(test)]
pub(crate) fn build_source_tree(paths: impl Iterator<Item = String>) -> SourceTreeModel {
    build_source_tree_with_components(paths, Vec::new())
}

pub(crate) fn build_source_tree_with_components(
    paths: impl Iterator<Item = String>,
    components: Vec<SourceTreeComponentRoot>,
) -> SourceTreeModel {
    let mut root = TrieNode::default();
    let mut finding_count = 0;
    for path in paths {
        if insert_path(&mut root, &path) {
            finding_count += 1;
        }
    }
    for component in components {
        insert_component(&mut root, component);
    }
    let mut rows = Vec::new();
    emit_children(&root, 0, &mut rows);
    let file_count = rows.iter().filter(|row| !row.is_dir).count();
    let empty_hint = empty_hint(rows.is_empty());
    rows.truncate(MAX_ROWS);
    SourceTreeModel {
        empty_hint,
        rows,
        file_count,
        finding_count,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceTreeComponentRoot {
    rel_path: String,
    marker: SourceTreeComponent,
}

#[derive(Default)]
struct TrieNode {
    children: BTreeMap<String, TrieNode>,
    direct_findings: usize,
    component: Option<SourceTreeComponent>,
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

fn insert_component(root: &mut TrieNode, component: SourceTreeComponentRoot) -> bool {
    let parts = component
        .rel_path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return false;
    }
    let mut node = root;
    for part in parts {
        node = node.children.entry(part.to_string()).or_default();
    }
    node.component = Some(component.marker);
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
        if node.direct_findings == 0 && node.component.is_some() {
            rows.push(dir_row(name, depth, node.component.clone()));
            return 0;
        }
        rows.push(file_row(
            name,
            depth,
            node.direct_findings,
            node.component.clone(),
        ));
        return node.direct_findings;
    }
    let index = rows.len();
    rows.push(dir_row(name, depth, node.component.clone()));
    let total = node.direct_findings + emit_children(node, depth + 1, rows);
    rows[index].finding_count = total;
    total
}

fn file_row(
    name: &str,
    depth: usize,
    finding_count: usize,
    component: Option<SourceTreeComponent>,
) -> SourceTreeRow {
    SourceTreeRow {
        depth,
        name: name.to_string(),
        is_dir: false,
        finding_count,
        component,
    }
}

fn dir_row(name: &str, depth: usize, component: Option<SourceTreeComponent>) -> SourceTreeRow {
    SourceTreeRow {
        depth,
        name: name.to_string(),
        is_dir: true,
        finding_count: 0,
        component,
    }
}

fn empty_hint(no_rows: bool) -> Option<&'static str> {
    no_rows.then_some("no finding-bearing files yet — run `scan` to populate the tree.")
}

fn component_roots(app: &ShellApp) -> Vec<SourceTreeComponentRoot> {
    let mut roots = recommendation_component_roots(app);
    let scope_state = app
        .workbench_cache()
        .borrow_mut()
        .project_scope_tree(app.target());
    if let Some(scope_state) = scope_state {
        roots.extend(scope_component_roots(&scope_state, &roots));
    }
    roots
}

fn recommendation_component_roots(app: &ShellApp) -> Vec<SourceTreeComponentRoot> {
    recommendation_components(app)
        .into_iter()
        .map(|row| SourceTreeComponentRoot {
            rel_path: row.rel_path,
            marker: SourceTreeComponent {
                label: row.class_label,
                tier: component_tier_from_label(&row.tier_label),
            },
        })
        .collect()
}

fn scope_component_roots(
    state: &ProjectScopeTreeState,
    existing: &[SourceTreeComponentRoot],
) -> Vec<SourceTreeComponentRoot> {
    let Some(tree) = scope_tree(state) else {
        return Vec::new();
    };
    tree.non_root_scopes()
        .filter(|scope| source_component_scope(scope.kind))
        .filter(|scope| {
            !existing
                .iter()
                .any(|component| component.rel_path == scope.rel_path)
        })
        .map(scope_component_root)
        .collect()
}

fn scope_tree(state: &ProjectScopeTreeState) -> Option<&NestedProjectScopeTree> {
    match state {
        ProjectScopeTreeState::Persisted(tree) => Some(tree),
        ProjectScopeTreeState::RootOnly | ProjectScopeTreeState::Unreadable(_) => None,
    }
}

fn source_component_scope(kind: NestedProjectKind) -> bool {
    matches!(
        kind,
        NestedProjectKind::Submodule
            | NestedProjectKind::PackageRoot
            | NestedProjectKind::EntrypointCluster
    )
}

fn scope_component_root(scope: &NestedProjectScope) -> SourceTreeComponentRoot {
    SourceTreeComponentRoot {
        rel_path: scope.rel_path.clone(),
        marker: SourceTreeComponent {
            label: source_component_label(scope.kind).to_string(),
            tier: SourceTreeComponentTier::Low,
        },
    }
}

fn source_component_label(kind: NestedProjectKind) -> &'static str {
    match kind {
        NestedProjectKind::EntrypointCluster => "cli",
        NestedProjectKind::PackageRoot => "package",
        NestedProjectKind::Submodule => "submodule",
        _ => "component",
    }
}

fn component_tier_from_label(label: &str) -> SourceTreeComponentTier {
    match label {
        "high" => SourceTreeComponentTier::High,
        "medium" => SourceTreeComponentTier::Medium,
        _ => SourceTreeComponentTier::Low,
    }
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
    fn component_roots_render_without_findings() {
        let model = build_source_tree_with_components(
            std::iter::empty(),
            vec![SourceTreeComponentRoot {
                rel_path: "web/app".to_string(),
                marker: SourceTreeComponent {
                    label: "web-app".to_string(),
                    tier: SourceTreeComponentTier::High,
                },
            }],
        );

        assert_eq!(model.file_count, 0);
        assert_eq!(model.empty_hint, None);
        assert!(model.rows.iter().any(|row| {
            row.name == "app"
                && row
                    .component
                    .as_ref()
                    .is_some_and(|component| component.label == "web-app")
        }));
    }

    #[test]
    fn bare_filename_has_no_directory_row() {
        let model = build_source_tree(["main.rs"].into_iter().map(str::to_string));
        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].depth, 0);
        assert!(!model.rows[0].is_dir);
    }
}
