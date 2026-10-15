use super::bounded_fs as fs;
use super::SbomInputs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn is_conanfile_txt(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "conanfile.txt")
}

pub(super) fn conanfile_components(target: &Path, path: &Path, text: &str) -> Vec<SbomComponent> {
    requirements(text)
        .into_iter()
        .map(|requirement| {
            component(
                target,
                path,
                "conan",
                "requires",
                &requirement.name,
                Some(&requirement.version),
            )
        })
        .collect()
}

pub(super) fn conanfile_edges(target: &SbomInputs, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text = fs::read_to_string(target, path)
        .with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(requirements(&text)
        .into_iter()
        .map(|requirement| SbomDependencyEdge {
            from: "root".to_string(),
            to: requirement.name,
            source: source.clone(),
        })
        .collect())
}

fn requirements(text: &str) -> Vec<ConanRequirement> {
    let mut in_requires = false;
    text.lines()
        .filter_map(|line| requirement_from_line(line, &mut in_requires))
        .collect()
}

fn requirement_from_line(line: &str, in_requires: &mut bool) -> Option<ConanRequirement> {
    let line = strip_comment(line).trim();
    if line.is_empty() {
        return None;
    }
    if let Some(name) = section_name(line) {
        *in_requires = name == "requires";
        return None;
    }
    (*in_requires).then(|| parse_requirement(line)).flatten()
}

fn parse_requirement(line: &str) -> Option<ConanRequirement> {
    let reference = line.split_whitespace().next()?;
    let (name, rest) = reference.split_once('/')?;
    let version = rest.split(['@', '#']).next()?.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some(ConanRequirement {
        name: name.to_string(),
        version: version.to_string(),
    })
}

fn strip_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or(line)
}

fn section_name(line: &str) -> Option<&str> {
    line.strip_prefix('[')?.strip_suffix(']')
}

struct ConanRequirement {
    name: String,
    version: String,
}
