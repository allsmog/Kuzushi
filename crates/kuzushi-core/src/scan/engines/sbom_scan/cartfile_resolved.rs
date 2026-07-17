use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn is_cartfile_resolved(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "Cartfile.resolved")
}

pub(super) fn cartfile_resolved_edges(
    target: &Path,
    path: &Path,
) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(text
        .lines()
        .filter_map(cartfile_dependency_name)
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect())
}

pub(super) fn cartfile_resolved_components(
    target: &Path,
    path: &Path,
) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(text
        .lines()
        .filter_map(|line| cartfile_component(target, path, &source, line))
        .collect())
}

fn cartfile_dependency_name(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    quoted_fields(line)
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn cartfile_component(
    target: &Path,
    path: &Path,
    source: &str,
    line: &str,
) -> Option<SbomComponent> {
    let mut fields = quoted_fields(line);
    let name = fields.next()?.trim();
    let version = fields.next()?.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some(component(
        target,
        path,
        "carthage",
        source,
        name,
        Some(version),
    ))
}

fn quoted_fields(line: &str) -> impl Iterator<Item = &str> {
    line.split('"').skip(1).step_by(2)
}
