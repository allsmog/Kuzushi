use super::{component, relative_display, SbomComponent};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub(super) use super::dependency_graph::is_go_sum;

pub(super) fn go_sum_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(text
        .lines()
        .filter_map(|line| go_sum_component(target, path, &source, line))
        .collect())
}

fn go_sum_component(target: &Path, path: &Path, source: &str, line: &str) -> Option<SbomComponent> {
    let mut parts = line.split_whitespace();
    let name = parts.next()?.trim();
    let raw_version = parts.next()?.trim();
    let version = raw_version.strip_suffix("/go.mod").unwrap_or(raw_version);
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some(component(target, path, "go", source, name, Some(version)))
}
