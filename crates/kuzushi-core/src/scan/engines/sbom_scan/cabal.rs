use super::{SbomComponent, SbomDependencyEdge, component, relative_display};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub(super) fn is_cabal_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "cabal")
}

pub(super) fn cabal_components(target: &Path, path: &Path, text: &str) -> Vec<SbomComponent> {
    dependency_names(text)
        .into_iter()
        .map(|name| component(target, path, "hackage", "build-depends", &name, None))
        .collect()
}

pub(super) fn cabal_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(dependency_names(&text)
        .into_iter()
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect())
}

fn dependency_names(text: &str) -> Vec<String> {
    let mut in_build_depends = false;
    text.lines()
        .filter_map(|line| dependencies_from_line(line, &mut in_build_depends))
        .flatten()
        .collect()
}

fn dependencies_from_line(line: &str, in_build_depends: &mut bool) -> Option<Vec<String>> {
    let line = strip_comment(line);
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Some(Vec::new());
    }
    if let Some(rest) = trimmed.strip_prefix("build-depends:") {
        *in_build_depends = true;
        return Some(parse_dependencies(rest));
    }
    if dependency_continuation(line, trimmed, *in_build_depends) {
        return Some(parse_dependencies(trimmed));
    }
    *in_build_depends = false;
    Some(Vec::new())
}

fn dependency_continuation(line: &str, trimmed: &str, in_build_depends: bool) -> bool {
    in_build_depends && line.starts_with([' ', '\t']) && !trimmed.contains(':')
}

fn parse_dependencies(text: &str) -> Vec<String> {
    text.split(',')
        .filter_map(dependency_name)
        .collect()
}

fn dependency_name(text: &str) -> Option<String> {
    let name = text
        .trim()
        .split([' ', '<', '>', '=', '^', '~'])
        .next()
        .unwrap_or_default();
    (!name.is_empty()).then(|| name.to_string())
}

fn strip_comment(line: &str) -> &str {
    line.split("--").next().unwrap_or(line)
}
