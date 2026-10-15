use super::bounded_fs as fs;
use super::SbomInputs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn is_opam_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "opam")
}

pub(super) fn opam_components(target: &Path, path: &Path, text: &str) -> Vec<SbomComponent> {
    dependency_names(text)
        .into_iter()
        .map(|name| component(target, path, "opam", "depends", &name, None))
        .collect()
}

pub(super) fn opam_edges(target: &SbomInputs, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text = fs::read_to_string(target, path)
        .with_context(|| format!("sbom-scan: read {}", path.display()))?;
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
    text.lines()
        .scan(false, dependencies_line)
        .flatten()
        .collect()
}

fn dependencies_line(in_depends: &mut bool, line: &str) -> Option<Vec<String>> {
    let line = line.split('#').next().unwrap_or(line).trim();
    if !*in_depends {
        *in_depends = line.starts_with("depends:");
    }
    if !*in_depends {
        return Some(Vec::new());
    }
    let names = first_quoted_name(line).into_iter().collect();
    if line.contains(']') {
        *in_depends = false;
    }
    Some(names)
}

fn first_quoted_name(line: &str) -> Option<String> {
    quoted_value(line).map(str::to_string)
}

fn quoted_value(text: &str) -> Option<&str> {
    let start = text.find('"')?;
    let rest = &text[start + 1..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}
