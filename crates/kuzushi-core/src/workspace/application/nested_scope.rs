use crate::fs_atomic::write_atomic;
use crate::workspace::inventory::{vendor_dir_kind, VendorDirKind};
use crate::workspace::domain::{
    inherited_sections_for_child_scope, normalize_relative_path, project_model_scopes_path,
    scope_id, scope_sort_key, NestedProjectKind, NestedProjectScope, NestedProjectScopeTree,
    ROOT_SCOPE_ID,
};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub fn discover_nested_project_scopes(root: impl AsRef<Path>) -> NestedProjectScopeTree {
    let root = root.as_ref();
    let mut scopes = BTreeMap::new();
    let root_scope = NestedProjectScope {
        id: ROOT_SCOPE_ID.to_string(),
        parent: None,
        kind: NestedProjectKind::Root,
        rel_path: ".".to_string(),
        inherited_sections: Vec::new(),
    };
    scopes.insert(root_scope.id.clone(), root_scope);
    for rel_path in discover_gitmodule_paths(root) {
        insert_scope(&mut scopes, root, NestedProjectKind::Submodule, rel_path);
    }
    for (kind, rel_path) in discover_dependency_roots(root) {
        insert_scope(&mut scopes, root, kind, rel_path);
    }
    let mut ordered_scopes = scopes.into_values().collect::<Vec<_>>();
    ordered_scopes.sort_by(|left, right| {
        scope_sort_key(left)
            .cmp(&scope_sort_key(right))
            .then_with(|| left.rel_path.cmp(&right.rel_path))
    });
    NestedProjectScopeTree {
        schema_version: 1,
        root: ROOT_SCOPE_ID.to_string(),
        scopes: ordered_scopes,
    }
}

pub fn load_nested_project_scopes(root: impl AsRef<Path>) -> Result<Option<NestedProjectScopeTree>> {
    let path = project_model_scopes_path(root);
    if !path.exists() {
        return Ok(None);
    }
    let body =
        fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
    let tree = serde_json::from_str(&body)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    Ok(Some(tree))
}

pub fn save_nested_project_scopes(
    root: impl AsRef<Path>,
    tree: &NestedProjectScopeTree,
) -> Result<PathBuf> {
    let path = project_model_scopes_path(root);
    let body = serde_json::to_string_pretty(tree).context("Could not serialize scope tree")?;
    write_atomic(&path, &body).with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

pub fn discover_and_save_nested_project_scopes(
    root: impl AsRef<Path>,
) -> Result<NestedProjectScopeTree> {
    let root = root.as_ref();
    let tree = discover_nested_project_scopes(root);
    save_nested_project_scopes(root, &tree)?;
    Ok(tree)
}

fn insert_scope(
    scopes: &mut BTreeMap<String, NestedProjectScope>,
    root: &Path,
    kind: NestedProjectKind,
    rel_path: String,
) {
    if !root.join(&rel_path).is_dir() {
        return;
    }
    let id = scope_id(kind, &rel_path);
    scopes.entry(id.clone()).or_insert_with(|| NestedProjectScope {
        id,
        parent: Some(ROOT_SCOPE_ID.to_string()),
        kind,
        rel_path,
        inherited_sections: inherited_sections_for_child_scope(),
    });
}

fn discover_gitmodule_paths(root: &Path) -> Vec<String> {
    let Ok(body) = fs::read_to_string(root.join(".gitmodules")) else {
        return Vec::new();
    };
    body.lines()
        .filter_map(gitmodule_path_line)
        .filter_map(|line| normalize_relative_path(&line))
        .collect()
}

fn gitmodule_path_line(line: &str) -> Option<String> {
    let (key, value) = line.trim().split_once('=')?;
    (key.trim() == "path")
        .then(|| trim_gitmodule_value(value))
        .filter(|value| !value.is_empty())
}

fn trim_gitmodule_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string()
}

fn discover_dependency_roots(root: &Path) -> Vec<(NestedProjectKind, String)> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut roots = entries
        .flatten()
        .filter_map(|entry| dependency_scope_for_entry(&entry.path()))
        .collect::<Vec<_>>();
    roots.sort();
    roots
}

fn dependency_scope_for_entry(path: &Path) -> Option<(NestedProjectKind, String)> {
    if !path.is_dir() {
        return None;
    }
    let name = path.file_name()?.to_string_lossy();
    let kind = match vendor_dir_kind(&name) {
        Some(VendorDirKind::DependencyRoot) => NestedProjectKind::DependencyRoot,
        Some(VendorDirKind::VendoredRoot) => NestedProjectKind::VendoredRoot,
        _ => return None,
    };
    Some((kind, name.to_string()))
}

#[cfg(test)]
mod tests;
