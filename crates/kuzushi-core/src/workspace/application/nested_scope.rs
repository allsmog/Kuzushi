use crate::workspace::domain::{
    inherited_sections_for_child_scope, normalize_relative_path, project_model_scopes_path,
    scope_id, scope_sort_key, valid_scope_id, validated_workspace_descendant,
    write_workspace_state_file, NestedProjectKind, NestedProjectScope, NestedProjectScopeTree,
    ROOT_SCOPE_ID, SCOPE_TREE_SCHEMA_VERSION,
};
use crate::workspace::inventory::{
    generated_vendor_path, ignored_dir, language_for_path, manifest_kind, vendor_dir_kind,
    VendorDirKind,
};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const PACKAGE_ROOT_SCAN_BUDGET: usize = 50_000;
const ENTRYPOINT_CLUSTER_BUDGET: usize = 512;
const MAX_WORKSPACE_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_SCOPE_TREE_BYTES: usize = 32 * 1024 * 1024;
const CONVENTIONAL_ENTRYPOINT_PARENTS: &[&str] = &["cmd", "services", "apps"];

pub fn discover_nested_project_scopes(root: impl AsRef<Path>) -> NestedProjectScopeTree {
    let root = root.as_ref();
    let mut scopes = root_scope_map();
    for (kind, rel_path) in discover_scope_candidates(root) {
        insert_scope(&mut scopes, root, kind, rel_path);
    }
    ordered_scope_tree(scopes)
}

fn root_scope_map() -> BTreeMap<String, NestedProjectScope> {
    let root_scope = NestedProjectScope {
        id: ROOT_SCOPE_ID.to_string(),
        parent: None,
        kind: NestedProjectKind::Root,
        rel_path: ".".to_string(),
        inherited_sections: Vec::new(),
    };
    BTreeMap::from([(root_scope.id.clone(), root_scope)])
}

fn discover_scope_candidates(root: &Path) -> Vec<(NestedProjectKind, String)> {
    let mut candidates = Vec::new();
    candidates.extend(
        discover_gitmodule_paths(root)
            .into_iter()
            .map(|path| (NestedProjectKind::Submodule, path)),
    );
    candidates.extend(
        discover_workspace_member_paths(root)
            .into_iter()
            .map(|path| (NestedProjectKind::PackageRoot, path)),
    );
    candidates.extend(discover_dependency_roots(root));
    candidates.extend(
        discover_package_roots(root)
            .into_iter()
            .map(|path| (NestedProjectKind::PackageRoot, path)),
    );
    candidates.extend(
        discover_entrypoint_clusters(root)
            .into_iter()
            .map(|path| (NestedProjectKind::EntrypointCluster, path)),
    );
    candidates
}

fn ordered_scope_tree(scopes: BTreeMap<String, NestedProjectScope>) -> NestedProjectScopeTree {
    let mut ordered_scopes = scopes.into_values().collect::<Vec<_>>();
    ordered_scopes.sort_by(|left, right| {
        scope_sort_key(left)
            .cmp(&scope_sort_key(right))
            .then_with(|| left.rel_path.cmp(&right.rel_path))
    });
    NestedProjectScopeTree {
        schema_version: SCOPE_TREE_SCHEMA_VERSION,
        root: ROOT_SCOPE_ID.to_string(),
        scopes: ordered_scopes,
    }
}

pub fn load_nested_project_scopes(
    root: impl AsRef<Path>,
) -> Result<Option<NestedProjectScopeTree>> {
    let root = root.as_ref();
    let path = project_model_scopes_path(root);
    let Some(body) =
        crate::workspace::read_optional_workspace_text(root, &path, MAX_SCOPE_TREE_BYTES)?
    else {
        return Ok(None);
    };
    let tree = serde_json::from_str(&body)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    Ok(Some(tree))
}

pub fn save_nested_project_scopes(
    root: impl AsRef<Path>,
    tree: &NestedProjectScopeTree,
) -> Result<PathBuf> {
    let root = root.as_ref();
    let path = project_model_scopes_path(root);
    let body = serde_json::to_string_pretty(tree).context("Could not serialize scope tree")?;
    let relative = path
        .strip_prefix(root)
        .context("Project scope path escaped the workspace")?;
    write_workspace_state_file(root, relative, body.as_bytes())
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

pub fn discover_and_save_nested_project_scopes(
    root: impl AsRef<Path>,
) -> Result<NestedProjectScopeTree> {
    let root = root.as_ref();
    let mut tree = discover_nested_project_scopes(root);
    if let Some(previous) = load_nested_project_scopes(root)? {
        preserve_exact_scope_ids(&mut tree, &previous);
    }
    save_nested_project_scopes(root, &tree)?;
    Ok(tree)
}

fn preserve_exact_scope_ids(
    discovered: &mut NestedProjectScopeTree,
    previous: &NestedProjectScopeTree,
) {
    let mut used = BTreeSet::from([ROOT_SCOPE_ID.to_string()]);
    for scope in discovered.non_root_scopes().cloned().collect::<Vec<_>>() {
        let Some(prior) = exact_prior_scope(previous, &scope) else {
            continue;
        };
        if valid_scope_id(&prior.id) && used.insert(prior.id.clone()) {
            if let Some(current) = discovered
                .scopes
                .iter_mut()
                .find(|current| current.rel_path == scope.rel_path && current.kind == scope.kind)
            {
                current.id = prior.id.clone();
            }
        }
    }
}

fn exact_prior_scope<'a>(
    previous: &'a NestedProjectScopeTree,
    scope: &NestedProjectScope,
) -> Option<&'a NestedProjectScope> {
    let mut matches = previous
        .non_root_scopes()
        .filter(|prior| prior.kind == scope.kind && prior.rel_path == scope.rel_path);
    let selected = matches.next()?;
    matches.next().is_none().then_some(selected)
}

fn insert_scope(
    scopes: &mut BTreeMap<String, NestedProjectScope>,
    root: &Path,
    kind: NestedProjectKind,
    rel_path: String,
) {
    if rel_path == "." {
        return;
    }
    if !is_workspace_directory(root, Path::new(&rel_path)) {
        return;
    }
    if scopes.values().any(|scope| scope.rel_path == rel_path) {
        return;
    }
    let id = scope_id(kind, &rel_path);
    scopes
        .entry(id.clone())
        .or_insert_with(|| NestedProjectScope {
            id,
            parent: Some(ROOT_SCOPE_ID.to_string()),
            kind,
            rel_path,
            inherited_sections: inherited_sections_for_child_scope(),
        });
}

fn discover_workspace_member_paths(root: &Path) -> Vec<String> {
    let mut members = BTreeSet::new();
    members.extend(discover_go_work_members(root));
    members.extend(discover_cargo_workspace_members(root));
    members.extend(discover_node_workspace_members(root));
    members.extend(discover_pnpm_workspace_members(root));
    members.into_iter().collect()
}

fn discover_go_work_members(root: &Path) -> Vec<String> {
    let Some(body) = read_workspace_manifest(root, "go.work") else {
        return Vec::new();
    };
    let mut in_use_block = false;
    let mut members = Vec::new();
    for raw_line in body.lines() {
        let line = strip_line_comment(raw_line).trim();
        absorb_go_work_line(line, &mut in_use_block, &mut members);
    }
    existing_member_paths(root, members)
}

fn absorb_go_work_line(line: &str, in_use_block: &mut bool, members: &mut Vec<String>) {
    if update_go_work_block_state(line, in_use_block) {
        return;
    }
    members.extend(go_work_line_paths(line, *in_use_block));
}

fn update_go_work_block_state(line: &str, in_use_block: &mut bool) -> bool {
    if line == "use (" {
        *in_use_block = true;
        return true;
    }
    if *in_use_block && line == ")" {
        *in_use_block = false;
        return true;
    }
    false
}

fn go_work_line_paths(line: &str, in_use_block: bool) -> Vec<String> {
    if let Some(rest) = line.strip_prefix("use ") {
        return parse_go_work_paths(rest);
    }
    in_use_block
        .then(|| parse_go_work_paths(line))
        .unwrap_or_default()
}

fn parse_go_work_paths(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .filter_map(|part| local_workspace_member_path(part.trim_matches('"')))
        .collect()
}

fn strip_line_comment(line: &str) -> &str {
    line.split_once("//").map_or(line, |(before, _)| before)
}

fn discover_cargo_workspace_members(root: &Path) -> Vec<String> {
    let Some(body) = read_workspace_manifest(root, "Cargo.toml") else {
        return Vec::new();
    };
    let Ok(value) = toml::from_str::<toml::Value>(&body) else {
        return Vec::new();
    };
    let members = value
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .flat_map(|member| expand_workspace_member_pattern(root, member))
        .collect::<Vec<_>>();
    existing_member_paths(root, members)
}

fn discover_node_workspace_members(root: &Path) -> Vec<String> {
    let Some(body) = read_workspace_manifest(root, "package.json") else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) else {
        return Vec::new();
    };
    let mut patterns = Vec::new();
    match value.get("workspaces") {
        Some(serde_json::Value::Array(items)) => {
            patterns.extend(items.iter().filter_map(serde_json::Value::as_str));
        }
        Some(serde_json::Value::Object(object)) => {
            patterns.extend(
                object
                    .get("packages")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str),
            );
        }
        _ => {}
    }
    let members = patterns
        .into_iter()
        .flat_map(|pattern| expand_workspace_member_pattern(root, pattern))
        .collect::<Vec<_>>();
    existing_member_paths(root, members)
}

fn discover_pnpm_workspace_members(root: &Path) -> Vec<String> {
    let Some(body) = read_workspace_manifest(root, "pnpm-workspace.yaml") else {
        return Vec::new();
    };
    let Ok(value) = crate::yaml::parse_value(&body) else {
        return Vec::new();
    };
    let members = value
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .flat_map(|pattern| expand_workspace_member_pattern(root, pattern))
        .collect::<Vec<_>>();
    existing_member_paths(root, members)
}

fn local_workspace_member_path(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('"').trim_matches('\'');
    if trimmed.is_empty() || trimmed.starts_with('!') || trimmed.contains("://") {
        return None;
    }
    normalize_relative_path(trimmed.trim_start_matches("./"))
}

fn expand_workspace_member_pattern(root: &Path, pattern: &str) -> Vec<String> {
    let Some(normalized) = local_workspace_member_path(pattern) else {
        return Vec::new();
    };
    if !normalized.contains('*') {
        return vec![normalized];
    }
    expand_simple_child_glob(root, &normalized)
}

fn expand_simple_child_glob(root: &Path, pattern: &str) -> Vec<String> {
    let Some(prefix) = pattern.strip_suffix("/*") else {
        return Vec::new();
    };
    let Some(entries) = sorted_workspace_dir_entries(root, Path::new(prefix)) else {
        return Vec::new();
    };
    entries
        .into_iter()
        .filter_map(|entry| child_workspace_member(prefix, entry))
        .collect()
}

fn child_workspace_member(prefix: &str, entry: fs::DirEntry) -> Option<String> {
    entry.file_type().ok()?.is_dir().then(|| {
        format!(
            "{}/{}",
            prefix.trim_end_matches('/'),
            entry.file_name().to_string_lossy()
        )
    })
}

fn existing_member_paths(root: &Path, members: Vec<String>) -> Vec<String> {
    members
        .into_iter()
        .filter(|member| is_workspace_directory(root, Path::new(member)))
        .collect()
}

fn read_workspace_manifest(root: &Path, relative: &str) -> Option<String> {
    crate::workspace::read_optional_workspace_text(
        root,
        &root.join(relative),
        MAX_WORKSPACE_MANIFEST_BYTES,
    )
    .ok()
    .flatten()
}

fn is_workspace_directory(root: &Path, relative: &Path) -> bool {
    validated_workspace_descendant(root, relative)
        .and_then(|path| {
            fs::symlink_metadata(&path)
                .with_context(|| format!("Could not inspect {}", path.display()))
        })
        .is_ok_and(|metadata| metadata.is_dir())
}

fn discover_package_roots(root: &Path) -> Vec<String> {
    let mut roots = Vec::new();
    let mut budget = PACKAGE_ROOT_SCAN_BUDGET;
    collect_package_roots(root, Path::new(""), &mut roots, &mut budget);
    roots.sort();
    roots.dedup();
    roots
}

fn collect_package_roots(
    root: &Path,
    rel_dir: &Path,
    roots: &mut Vec<String>,
    budget: &mut usize,
) -> bool {
    if *budget == 0 {
        return false;
    }
    let Some(entries) = sorted_dir_entries(&root.join(rel_dir)) else {
        return false;
    };
    let mut summary = PackageDirSummary::default();
    absorb_package_entries(entries, rel_dir, &mut summary, budget);
    absorb_child_package_roots(root, roots, budget, &mut summary);
    record_package_root(rel_dir, roots, &summary);
    summary.has_source
}

fn absorb_package_entries(
    entries: Vec<fs::DirEntry>,
    rel_dir: &Path,
    summary: &mut PackageDirSummary,
    budget: &mut usize,
) {
    for entry in entries {
        absorb_package_entry(entry, rel_dir, summary, budget);
    }
}

fn absorb_child_package_roots(
    root: &Path,
    roots: &mut Vec<String>,
    budget: &mut usize,
    summary: &mut PackageDirSummary,
) {
    for child in &summary.child_dirs {
        summary.has_source |= collect_package_roots(root, child, roots, budget);
    }
}

fn record_package_root(rel_dir: &Path, roots: &mut Vec<String>, summary: &PackageDirSummary) {
    if summary.is_package_root() {
        push_package_root(rel_dir, roots);
    }
}

#[derive(Default)]
struct PackageDirSummary {
    has_manifest: bool,
    has_source: bool,
    child_dirs: Vec<PathBuf>,
}

impl PackageDirSummary {
    fn is_package_root(&self) -> bool {
        self.has_manifest && self.has_source
    }
}

fn sorted_dir_entries(dir: &Path) -> Option<Vec<fs::DirEntry>> {
    let read_dir = fs::read_dir(dir).ok()?;
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    Some(entries)
}

fn sorted_workspace_dir_entries(root: &Path, relative: &Path) -> Option<Vec<fs::DirEntry>> {
    let path = validated_workspace_descendant(root, relative).ok()?;
    fs::symlink_metadata(&path).ok()?.is_dir().then_some(())?;
    sorted_dir_entries(&path)
}

fn absorb_package_entry(
    entry: fs::DirEntry,
    rel_dir: &Path,
    summary: &mut PackageDirSummary,
    budget: &mut usize,
) {
    if !spend_package_budget(budget) {
        return;
    }
    let path = entry.path();
    let name = entry.file_name().to_string_lossy().to_string();
    let rel_path = join_relative_path(rel_dir, &name);
    let Ok(file_type) = entry.file_type() else {
        return;
    };
    if file_type.is_dir() {
        push_child_package_dir(&name, rel_path, summary);
    } else if file_type.is_file() {
        summary.has_manifest |= is_package_manifest(&rel_path, &name);
        summary.has_source |= language_for_path(&path).is_some();
    }
}

fn spend_package_budget(budget: &mut usize) -> bool {
    if *budget == 0 {
        return false;
    }
    *budget -= 1;
    true
}

fn push_child_package_dir(name: &str, rel_path: PathBuf, summary: &mut PackageDirSummary) {
    if !skip_package_root_dir(name) {
        summary.child_dirs.push(rel_path);
    }
}

fn join_relative_path(rel_dir: &Path, name: &str) -> PathBuf {
    if rel_dir.as_os_str().is_empty() {
        PathBuf::from(name)
    } else {
        rel_dir.join(name)
    }
}

fn is_package_manifest(rel_path: &Path, name: &str) -> bool {
    let rel = rel_path.to_string_lossy();
    manifest_kind(&rel, name).is_some()
}

fn push_package_root(rel_dir: &Path, roots: &mut Vec<String>) {
    let rel = rel_dir.to_string_lossy();
    if let Some(normalized) = normalize_relative_path(&rel) {
        roots.push(normalized);
    }
}

fn skip_package_root_dir(name: &str) -> bool {
    ignored_dir(name) || generated_vendor_path(name, name, true).is_some()
}

fn discover_gitmodule_paths(root: &Path) -> Vec<String> {
    let Some(body) = read_workspace_manifest(root, ".gitmodules") else {
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
        .filter_map(|entry| dependency_scope_for_entry(&entry))
        .collect::<Vec<_>>();
    roots.sort();
    roots
}

fn discover_entrypoint_clusters(root: &Path) -> Vec<String> {
    let mut clusters = CONVENTIONAL_ENTRYPOINT_PARENTS
        .iter()
        .flat_map(|parent| direct_entrypoint_clusters(root, parent))
        .take(ENTRYPOINT_CLUSTER_BUDGET)
        .collect::<Vec<_>>();
    clusters.sort();
    clusters.dedup();
    clusters
}

fn direct_entrypoint_clusters(root: &Path, parent: &str) -> Vec<String> {
    let Some(entries) = sorted_workspace_dir_entries(root, Path::new(parent)) else {
        return Vec::new();
    };
    entries
        .into_iter()
        .filter_map(|entry| entrypoint_cluster_for_entry(parent, &entry))
        .collect()
}

fn entrypoint_cluster_for_entry(parent: &str, entry: &fs::DirEntry) -> Option<String> {
    if !entry.file_type().ok()?.is_dir() {
        return None;
    }
    let child = entry.file_name().to_string_lossy().to_string();
    if child.starts_with('.') || ignored_dir(&child) {
        return None;
    }
    normalize_relative_path(&format!("{parent}/{child}"))
}

fn dependency_scope_for_entry(entry: &fs::DirEntry) -> Option<(NestedProjectKind, String)> {
    if !entry.file_type().ok()?.is_dir() {
        return None;
    }
    let name = entry.file_name().to_string_lossy().to_string();
    let kind = match vendor_dir_kind(&name) {
        Some(VendorDirKind::DependencyRoot) => NestedProjectKind::DependencyRoot,
        Some(VendorDirKind::VendoredRoot) => NestedProjectKind::VendoredRoot,
        _ => return None,
    };
    Some((kind, name))
}

#[cfg(test)]
mod tests;
