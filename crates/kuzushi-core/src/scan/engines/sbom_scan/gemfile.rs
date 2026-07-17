use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn gemfile_components(target: &Path, path: &Path, text: &str) -> Vec<SbomComponent> {
    text.lines()
        .filter_map(gem_declaration)
        .map(|(name, version)| component(target, path, "gem", "gem", name, version))
        .collect()
}

pub(super) fn is_gemfile(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "Gemfile")
}

pub(super) fn gemfile_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(text
        .lines()
        .filter_map(gem_declaration)
        .map(|(to, _)| SbomDependencyEdge {
            from: "root".to_string(),
            to: to.to_string(),
            source: source.clone(),
        })
        .collect())
}

fn gem_declaration(line: &str) -> Option<(&str, Option<&str>)> {
    let line = line.trim_start();
    let rest = line.strip_prefix("gem ")?;
    let mut parts = rest.split(',').map(str::trim);
    let name = quoted_value(parts.next()?)?;
    Some((name, parts.find_map(quoted_value)))
}

fn quoted_value(value: &str) -> Option<&str> {
    value
        .strip_prefix('"')
        .and_then(|value| value.split('"').next())
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.split('\'').next())
        })
}
