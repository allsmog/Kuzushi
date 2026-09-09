use super::super::BuildInput;
use super::model::{Candidate, Selection};
use crate::attack_surface::AttackSurface;
use crate::repository_inventory::RepositoryInventory;
use anyhow::{Context, Result};
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;

pub(super) fn select_files(
    input: &BuildInput,
    inventory: RepositoryInventory,
    surfaces: &[AttackSurface],
) -> Result<Selection> {
    let scope = input
        .analysis_root()
        .strip_prefix(input.workspace_root())
        .context("source-code analysis scope is outside its workspace")?;
    let mut files: BTreeMap<_, _> = inventory
        .source_files
        .into_iter()
        .map(|file| {
            (
                file.path.clone(),
                Candidate {
                    citation_path: scope.join(&file.path).to_string_lossy().replace('\\', "/"),
                    path: file.path,
                    language: file.language,
                    anchors: Vec::new(),
                },
            )
        })
        .collect();
    let eligible = files.len();
    let mut priority = prioritized_files(input, &mut files, surfaces);
    priority.extend(balanced_files(files));
    priority.truncate(input.context_limit.min(2_000));
    Ok(Selection {
        scope_path: scope.to_string_lossy().replace('\\', "/"),
        eligible,
        files: priority,
    })
}

fn prioritized_files(
    input: &BuildInput,
    files: &mut BTreeMap<String, Candidate>,
    surfaces: &[AttackSurface],
) -> Vec<Candidate> {
    let mut ordered_paths = Vec::new();
    for surface in surfaces {
        record_anchor(input, files, surface, &mut ordered_paths);
    }
    ordered_paths
        .into_iter()
        .filter_map(|path| files.remove(&path))
        .collect()
}

fn record_anchor(
    input: &BuildInput,
    files: &mut BTreeMap<String, Candidate>,
    surface: &AttackSurface,
    ordered: &mut Vec<String>,
) {
    let Some(path) = scoped_surface_path(input, surface) else {
        return;
    };
    let Some(candidate) = files.get_mut(&path) else {
        return;
    };
    candidate
        .anchors
        .push(surface.line.unwrap_or(1).saturating_sub(1) as usize);
    if !ordered.contains(&path) {
        ordered.push(path);
    }
}

fn scoped_surface_path(input: &BuildInput, surface: &AttackSurface) -> Option<String> {
    input
        .workspace_root()
        .join(&surface.path)
        .strip_prefix(input.analysis_root())
        .ok()
        .map(|path| path.to_string_lossy().replace('\\', "/"))
}

fn balanced_files(files: BTreeMap<String, Candidate>) -> Vec<Candidate> {
    let mut groups: BTreeMap<String, VecDeque<Candidate>> = BTreeMap::new();
    for file in files.into_values() {
        groups
            .entry(component_group(&file.path))
            .or_default()
            .push_back(file);
    }
    let mut selected = Vec::new();
    while groups.values().any(|group| !group.is_empty()) {
        selected.extend(groups.values_mut().filter_map(VecDeque::pop_front));
    }
    selected
}

fn component_group(path: &str) -> String {
    Path::new(path)
        .parent()
        .unwrap_or(Path::new(""))
        .components()
        .take(2)
        .map(|part| part.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}
