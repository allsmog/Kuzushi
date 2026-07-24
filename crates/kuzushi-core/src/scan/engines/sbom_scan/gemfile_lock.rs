use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn is_gemfile_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "Gemfile.lock")
}

pub(super) fn gemfile_lock_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(target, path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(GemfileLockParser::new(&source).parse(&text))
}

pub(super) fn gemfile_lock_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(target, path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    Ok(text
        .lines()
        .filter_map(|line| spec_component(target, path, line))
        .collect())
}

fn spec_component(target: &Path, path: &Path, line: &str) -> Option<SbomComponent> {
    if !is_spec_line(line) {
        return None;
    }
    let (name, version) = spec_name_and_version(line)?;
    Some(component(
        target,
        path,
        "gem",
        "Gemfile.lock",
        name,
        version,
    ))
}

struct GemfileLockParser<'a> {
    source: &'a str,
    in_specs: bool,
    in_dependencies: bool,
    current_spec: Option<String>,
}

impl<'a> GemfileLockParser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            in_specs: false,
            in_dependencies: false,
            current_spec: None,
        }
    }

    fn parse(&mut self, text: &str) -> Vec<SbomDependencyEdge> {
        text.lines()
            .filter_map(|line| self.edge_from_line(line))
            .collect()
    }

    fn edge_from_line(&mut self, line: &str) -> Option<SbomDependencyEdge> {
        if line == "  specs:" {
            self.in_specs = true;
            self.current_spec = None;
            return None;
        }
        if line == "DEPENDENCIES" {
            self.in_specs = false;
            self.in_dependencies = true;
            self.current_spec = None;
            return None;
        }
        if section_header(line) {
            self.in_specs = false;
            self.in_dependencies = false;
            self.current_spec = None;
            return None;
        }
        self.spec_edge(line).or_else(|| self.dependency_edge(line))
    }

    fn spec_edge(&mut self, line: &str) -> Option<SbomDependencyEdge> {
        if !self.in_specs {
            return None;
        }
        if is_spec_line(line) {
            self.current_spec = dependency_name(line);
            return None;
        }
        if !is_spec_dependency_line(line) {
            return None;
        }
        Some(SbomDependencyEdge {
            from: self.current_spec.clone()?,
            to: dependency_name(line)?,
            source: self.source.to_string(),
        })
    }

    fn dependency_edge(&self, line: &str) -> Option<SbomDependencyEdge> {
        if !self.in_dependencies {
            return None;
        }
        Some(SbomDependencyEdge {
            from: "root".to_string(),
            to: dependency_name(line)?,
            source: self.source.to_string(),
        })
    }
}

fn section_header(line: &str) -> bool {
    !line.starts_with(' ') && line.chars().any(char::is_alphabetic)
}

fn is_spec_line(line: &str) -> bool {
    line.starts_with("    ") && !line.starts_with("      ")
}

fn is_spec_dependency_line(line: &str) -> bool {
    line.starts_with("      ")
}

fn dependency_name(line: &str) -> Option<String> {
    let name = line
        .trim()
        .split([' ', '!', '('])
        .next()
        .unwrap_or_default();
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

fn spec_name_and_version(line: &str) -> Option<(&str, Option<&str>)> {
    let trimmed = line.trim();
    let name = trimmed.split_whitespace().next()?.trim();
    if name.is_empty() {
        return None;
    }
    Some((name, version_between_parentheses(trimmed)))
}

fn version_between_parentheses(value: &str) -> Option<&str> {
    let start = value.find('(')? + 1;
    let end = value[start..].find(')')? + start;
    Some(value[start..end].trim()).filter(|version| !version.is_empty())
}
