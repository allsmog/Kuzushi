use super::{ShardCandidate, NON_SHIPPED_SEGMENTS, TARGET_SCOPE_FILES};
use crate::workspace::{InventorySourceFile, RepositoryInventory};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const MAX_SPLIT_DEPTH: usize = 6;
pub(super) const MAX_PROPOSED_SCOPES: usize = 8;

pub(super) struct InventoryCandidates {
    pub candidates: Vec<ShardCandidate>,
    pub excluded: Vec<String>,
}

struct CandidateGroup<'a> {
    path: String,
    files: Vec<&'a InventorySourceFile>,
    depth: usize,
}

pub(super) fn from_inventory(inventory: &RepositoryInventory) -> InventoryCandidates {
    let mut excluded = inventory.generated_vendor_paths.iter()
        .map(|item| item.path.clone()).collect::<BTreeSet<_>>();
    let files = included_files(inventory, &mut excluded);
    let members = included_members(inventory, &excluded);
    let candidates = partition_inventory(files, &members).into_iter()
        .map(|group| candidate_from_group(group, inventory)).collect();
    InventoryCandidates { candidates, excluded: excluded.into_iter().collect() }
}

fn included_members<'a>(inventory: &'a RepositoryInventory, excluded: &BTreeSet<String>) -> Vec<&'a str> {
    let Some(inspection) = &inventory.inspection else { return Vec::new(); };
    inspection.files.iter().map(String::as_str).filter(|path| {
        !excluded.iter().any(|excluded| path == excluded || path.starts_with(&scope_prefix(excluded)))
    }).collect()
}

fn included_files<'a>(
    inventory: &'a RepositoryInventory,
    excluded: &mut BTreeSet<String>,
) -> Vec<&'a InventorySourceFile> {
    let mut files = Vec::new();
    for file in &inventory.source_files {
        if let Some(path) = excluded_parent(&file.path) {
            excluded.insert(path);
        } else {
            files.push(file);
        }
    }
    files
}

fn excluded_parent(path: &str) -> Option<String> {
    let mut parent = Vec::new();
    let (directories, _) = path.rsplit_once('/')?;
    for segment in directories.split('/') {
        parent.push(segment);
        if NON_SHIPPED_SEGMENTS.contains(&segment.to_ascii_lowercase().as_str()) {
            return Some(parent.join("/"));
        }
    }
    None
}

fn partition_inventory<'a>(files: Vec<&'a InventorySourceFile>, members: &[&str]) -> Vec<CandidateGroup<'a>> {
    if files.is_empty() {
        return Vec::new();
    }
    let mut pending = vec![CandidateGroup { path: ".".into(), files, depth: 0 }];
    let mut accepted = Vec::new();
    while let Some(group) = pending.pop() {
        let children = split_group(&group, members);
        if !children.is_empty() && accepted.len() + pending.len() + children.len() <= MAX_PROPOSED_SCOPES {
            pending.extend(children);
        } else {
            accepted.push(group);
        }
    }
    accepted
}

fn split_group<'a>(group: &CandidateGroup<'a>, members: &[&str]) -> Vec<CandidateGroup<'a>> {
    if group.files.len() <= TARGET_SCOPE_FILES || group.depth >= MAX_SPLIT_DEPTH {
        return Vec::new();
    }
    let Some(groups) = child_groups(group) else { return Vec::new() };
    if !children_cover_members(group, &groups, members) { return Vec::new(); }
    groups.into_iter().map(|(path, files)| CandidateGroup {
        path, files, depth: group.depth + 1,
    }).collect()
}

fn children_cover_members(
    group: &CandidateGroup<'_>, children: &BTreeMap<String, Vec<&InventorySourceFile>>, members: &[&str],
) -> bool {
    if members.is_empty() { return false; }
    let prefix = scope_prefix(&group.path);
    let covered = |path: &&str| children.keys().any(|child| path.starts_with(&scope_prefix(child)));
    members.iter().filter(|path| path.starts_with(&prefix)).all(covered)
}

/// Keep a parent intact when subdivision would lose its loose files. The
/// operator can later propose explicit file membership in the scope editor.
fn child_groups<'a>(group: &CandidateGroup<'a>) -> Option<BTreeMap<String, Vec<&'a InventorySourceFile>>> {
    let prefix = scope_prefix(&group.path);
    let mut children = BTreeMap::<String, Vec<_>>::new();
    for file in &group.files {
        let relative = file.path.strip_prefix(&prefix)?;
        let (child, _) = relative.split_once('/')?;
        children.entry(format!("{prefix}{child}")).or_default().push(*file);
    }
    Some(children)
}

fn scope_prefix(path: &str) -> String {
    if path == "." { String::new() } else { format!("{path}/") }
}

fn candidate_from_group(group: CandidateGroup<'_>, inventory: &RepositoryInventory) -> ShardCandidate {
    let mut languages = BTreeMap::new();
    for file in &group.files {
        let language = Path::new(&file.path).extension().unwrap_or_default().to_string_lossy();
        *languages.entry(language.to_string()).or_default() += 1;
    }
    let members = group.files.iter().map(|file| file.path.as_str()).collect::<BTreeSet<_>>();
    let entrypoints = inventory.entrypoints.iter().filter(|entry| members.contains(entry.path.as_str())).count();
    ShardCandidate {
        relative_path: group.path,
        file_count: group.files.len(),
        oversized: group.files.len() > TARGET_SCOPE_FILES,
        languages,
        signals: BTreeMap::from([("entrypoints", entrypoints)]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources(paths: &[String]) -> Vec<InventorySourceFile> {
        paths.iter().map(|path| InventorySourceFile { path: path.clone(), language: "Rust".into() }).collect()
    }

    #[test]
    fn loose_parent_files_keep_the_parent_instead_of_disappearing() {
        let mut paths = (0..60).map(|i| format!("src/a/f{i}.rs")).collect::<Vec<_>>();
        paths.push("root.rs".into());
        let files = sources(&paths);
        let members = files.iter().map(|file| file.path.as_str()).collect::<Vec<_>>();
        let groups = partition_inventory(files.iter().collect(), &members);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].path, ".");
        assert_eq!(groups[0].files.len(), 61);
    }

    #[test]
    fn a_small_repository_stays_whole() {
        let files = sources(&["src/a.rs".into(), "src/b.rs".into()]);
        let members = files.iter().map(|file| file.path.as_str()).collect::<Vec<_>>();
        let groups = partition_inventory(files.iter().collect(), &members);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].path, ".");
    }

    #[test]
    fn candidate_limit_preserves_every_file_without_expanding_the_queue() {
        let paths = (0..100).map(|i| format!("package{i}/src.rs")).collect::<Vec<_>>();
        let files = sources(&paths);
        let members = files.iter().map(|file| file.path.as_str()).collect::<Vec<_>>();
        let groups = partition_inventory(files.iter().collect(), &members);
        assert!(groups.len() <= MAX_PROPOSED_SCOPES);
        assert_eq!(groups.iter().map(|group| group.files.len()).sum::<usize>(), 100);
    }
}
