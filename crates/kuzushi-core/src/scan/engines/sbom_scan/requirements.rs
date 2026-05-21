use super::python_dependency::{python_component, python_dependency_name};
use super::{SbomComponent, SbomDependencyEdge, relative_display};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub(super) fn is_requirements_manifest(name: &str) -> bool {
    name == "requirements.txt" || name.ends_with("-requirements.txt")
}

pub(super) fn requirements_components(
    target: &Path,
    path: &Path,
    scope: &str,
    text: &str,
) -> Vec<SbomComponent> {
    text.lines()
        .filter_map(requirement_line)
        .map(|raw| python_component(target, path, scope, raw))
        .collect()
}

pub(super) fn requirements_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(text
        .lines()
        .filter_map(requirement_line)
        .map(python_dependency_name)
        .filter(|name| !name.is_empty())
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to: to.to_string(),
            source: source.clone(),
        })
        .collect())
}

fn requirement_line(line: &str) -> Option<&str> {
    let line = line.split('#').next().unwrap_or(line).trim();
    if line.is_empty() || line.starts_with(['-', '.']) {
        return None;
    }
    Some(line)
}
