use super::{ALL_LEAF_SCOPES, ALL_SCOPES_HARD_CAP};
use anyhow::Result;
use kuzushi_core::{NestedProjectKind, NestedProjectScope, NestedProjectScopeTree};
use std::path::{Component, Path};

pub(crate) fn eligible_leaf_scopes(tree: &NestedProjectScopeTree) -> Vec<&NestedProjectScope> {
    let mut scopes = tree
        .non_root_scopes()
        .filter(|scope| selectable_scope(scope))
        .filter(|scope| !has_selectable_child(tree, &scope.id))
        .collect::<Vec<_>>();
    scopes.sort_by(|left, right| (&left.rel_path, &left.id).cmp(&(&right.rel_path, &right.id)));
    scopes
}

#[cfg(test)]
pub(crate) fn owning_leaf_scope<'a>(
    tree: &'a NestedProjectScopeTree,
    evidence_paths: &[String],
) -> Option<&'a NestedProjectScope> {
    eligible_leaf_scopes(tree)
        .into_iter()
        .filter_map(|scope| owner_match_score(scope, evidence_paths).map(|score| (score, scope)))
        .max_by(|(left_score, left), (right_score, right)| {
            left_score
                .cmp(right_score)
                .then_with(|| right.id.cmp(&left.id))
        })
        .map(|(_, scope)| scope)
}

pub(super) fn selected_scope_count(scope: Option<&str>, leaf_count: usize) -> usize {
    if scope == Some(ALL_LEAF_SCOPES) {
        leaf_count
    } else {
        1
    }
}

pub(super) fn scope_label(scope: Option<&str>, leaves: &[NestedProjectScope]) -> String {
    match scope {
        None => "whole repository".to_string(),
        Some(ALL_LEAF_SCOPES) => format!("all eligible leaves ({})", leaves.len()),
        Some(value) => leaves
            .iter()
            .find(|scope| value == format!("id:{}", scope.id))
            .map(|scope| scope.rel_path.clone())
            .unwrap_or_else(|| value.to_string()),
    }
}

pub(super) fn scope_selection_error(scope: Option<&str>, leaf_count: usize) -> Option<String> {
    if scope != Some(ALL_LEAF_SCOPES) {
        return None;
    }
    match leaf_count {
        0 => Some("all scopes needs a persisted decomposition with eligible leaves".to_string()),
        count if count > ALL_SCOPES_HARD_CAP => Some(format!(
            "{count} eligible leaves exceeds the hard cap of {ALL_SCOPES_HARD_CAP}"
        )),
        _ => None,
    }
}

pub(super) fn validate_all_scope_count(count: usize) -> Result<()> {
    anyhow::ensure!(
        count > 0,
        "all scopes needs at least one eligible leaf scope"
    );
    anyhow::ensure!(
        count <= ALL_SCOPES_HARD_CAP,
        "{count} eligible leaf scopes exceeds the hard cap of {ALL_SCOPES_HARD_CAP}"
    );
    Ok(())
}

fn selectable_scope(scope: &NestedProjectScope) -> bool {
    matches!(
        scope.kind,
        NestedProjectKind::Submodule
            | NestedProjectKind::PackageRoot
            | NestedProjectKind::EntrypointCluster
    ) && !generated_or_dependency_path(&scope.rel_path)
}

fn has_selectable_child(tree: &NestedProjectScopeTree, parent: &str) -> bool {
    tree.scopes
        .iter()
        .any(|scope| scope.parent.as_deref() == Some(parent) && selectable_scope(scope))
}

fn generated_or_dependency_path(path: &str) -> bool {
    const EXCLUDED: [&str; 13] = [
        ".git",
        ".kuzushi",
        "node_modules",
        "vendor",
        "vendored",
        "target",
        "dist",
        "build",
        "out",
        "generated",
        ".generated",
        "coverage",
        ".next",
    ];
    Path::new(path).components().any(|component| {
        let Component::Normal(value) = component else {
            return false;
        };
        EXCLUDED.contains(&value.to_string_lossy().to_ascii_lowercase().as_str())
    })
}

#[cfg(test)]
fn owner_match_score(scope: &NestedProjectScope, evidence_paths: &[String]) -> Option<usize> {
    let scope_path = normalized_repo_path(&scope.rel_path)?;
    evidence_paths
        .iter()
        .filter_map(|evidence| normalized_evidence_path(evidence))
        .filter(|evidence| path_is_within(evidence, &scope_path))
        .map(|_| scope_path.split('/').count())
        .max()
}

#[cfg(test)]
fn normalized_evidence_path(value: &str) -> Option<String> {
    let first = value
        .split_whitespace()
        .next()?
        .trim_matches(|ch| matches!(ch, '`' | '"' | '\''));
    let without_fragment = first.split_once("#L").map_or(first, |(path, _)| path);
    normalized_repo_path(strip_numeric_line_suffix(without_fragment))
}

#[cfg(test)]
fn strip_numeric_line_suffix(value: &str) -> &str {
    let Some((head, tail)) = value.rsplit_once(':') else {
        return value;
    };
    if tail.split('-').all(|part| part.parse::<u32>().is_ok()) {
        strip_numeric_line_suffix(head)
    } else {
        value
    }
}

#[cfg(test)]
fn normalized_repo_path(value: &str) -> Option<String> {
    let normalized = value.trim().replace('\\', "/");
    let normalized = normalized.trim_start_matches("./").trim_matches('/');
    (!normalized.is_empty()).then(|| normalized.to_string())
}

#[cfg(test)]
fn path_is_within(path: &str, scope: &str) -> bool {
    path == scope
        || path
            .strip_prefix(scope)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_scopes_uses_only_non_generated_leaves() {
        let tree = tree(vec![
            scope("api", None, "services/api", NestedProjectKind::PackageRoot),
            scope(
                "api-routes",
                Some("api"),
                "services/api/routes",
                NestedProjectKind::EntrypointCluster,
            ),
            scope("web", None, "apps/web", NestedProjectKind::PackageRoot),
            scope(
                "generated",
                None,
                "apps/generated",
                NestedProjectKind::PackageRoot,
            ),
            scope(
                "vendor",
                None,
                "vendor/lib",
                NestedProjectKind::VendoredRoot,
            ),
        ]);
        let paths = eligible_leaf_scopes(&tree)
            .into_iter()
            .map(|scope| scope.rel_path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(paths, vec!["apps/web", "services/api/routes"]);
    }

    #[test]
    fn evidence_owner_uses_longest_leaf_prefix() {
        let tree = tree(vec![
            scope("root-api", None, "services", NestedProjectKind::PackageRoot),
            scope(
                "api",
                Some("root-api"),
                "services/api",
                NestedProjectKind::PackageRoot,
            ),
            scope("web", None, "apps/web", NestedProjectKind::PackageRoot),
        ]);
        let evidence = vec!["services/api/src/auth.rs:42-48".to_string()];
        assert_eq!(owning_leaf_scope(&tree, &evidence).unwrap().id, "api");
    }

    #[test]
    fn all_scope_count_has_a_hard_cap() {
        assert!(validate_all_scope_count(ALL_SCOPES_HARD_CAP).is_ok());
        assert!(validate_all_scope_count(ALL_SCOPES_HARD_CAP + 1).is_err());
        assert!(validate_all_scope_count(0).is_err());
    }

    fn tree(mut scopes: Vec<NestedProjectScope>) -> NestedProjectScopeTree {
        scopes.push(scope("root", None, ".", NestedProjectKind::Root));
        NestedProjectScopeTree {
            schema_version: 2,
            root: "root".into(),
            scopes,
        }
    }

    fn scope(
        id: &str,
        parent: Option<&str>,
        path: &str,
        kind: NestedProjectKind,
    ) -> NestedProjectScope {
        NestedProjectScope {
            id: id.into(),
            parent: parent.map(str::to_string),
            kind,
            rel_path: path.into(),
            inherited_sections: Vec::new(),
        }
    }
}
