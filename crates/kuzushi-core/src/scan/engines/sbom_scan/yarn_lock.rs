use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

const DEPENDENCY_BLOCKS: &[&str] = &["dependencies:", "optionalDependencies:"];

pub(super) fn is_yarn_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "yarn.lock")
}

pub(super) fn yarn_lock_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(YarnLockParser::new(&source).parse(&text))
}

pub(super) fn yarn_lock_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(YarnComponentParser::new(target, path, &source).parse(&text))
}

struct YarnLockParser<'a> {
    source: &'a str,
    current: Option<String>,
    in_dependencies: bool,
}

impl<'a> YarnLockParser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            current: None,
            in_dependencies: false,
        }
    }

    fn parse(&mut self, text: &str) -> Vec<SbomDependencyEdge> {
        text.lines()
            .filter_map(|line| self.edge_from_line(line))
            .collect()
    }

    fn edge_from_line(&mut self, line: &str) -> Option<SbomDependencyEdge> {
        if let Some(package) = package_header(line) {
            self.current = Some(package);
            self.in_dependencies = false;
            return None;
        }
        if dependency_block(line) {
            self.in_dependencies = true;
            return None;
        }
        self.dependency_edge(line)
    }

    fn dependency_edge(&self, line: &str) -> Option<SbomDependencyEdge> {
        if !self.in_dependencies {
            return None;
        }
        let from = self.current.as_ref()?;
        let to = dependency_name(line)?;
        Some(SbomDependencyEdge {
            from: from.clone(),
            to,
            source: self.source.to_string(),
        })
    }
}

struct YarnComponentParser<'a> {
    target: &'a Path,
    path: &'a Path,
    source: &'a str,
    current: Option<String>,
}

impl<'a> YarnComponentParser<'a> {
    fn new(target: &'a Path, path: &'a Path, source: &'a str) -> Self {
        Self {
            target,
            path,
            source,
            current: None,
        }
    }

    fn parse(&mut self, text: &str) -> Vec<SbomComponent> {
        text.lines()
            .filter_map(|line| self.component_from_line(line))
            .collect()
    }

    fn component_from_line(&mut self, line: &str) -> Option<SbomComponent> {
        if let Some(package) = package_header(line) {
            self.current = Some(package);
            return None;
        }
        let version = yarn_version(line)?;
        let name = self.current.as_ref()?;
        Some(component(
            self.target,
            self.path,
            "npm",
            self.source,
            name,
            Some(version),
        ))
    }
}

fn dependency_block(line: &str) -> bool {
    DEPENDENCY_BLOCKS.contains(&line.trim())
}

fn package_header(line: &str) -> Option<String> {
    if line.starts_with(' ') || !line.ends_with(':') {
        return None;
    }
    let descriptor = line.trim_end_matches(':').split(',').next()?.trim();
    package_name_from_descriptor(unquote(descriptor))
}

fn dependency_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if !line.starts_with("    ") || trimmed.is_empty() {
        return None;
    }
    trimmed.split_whitespace().next().map(unquote).map(str::to_string)
}

fn yarn_version(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    let version = trimmed.strip_prefix("version ")?;
    Some(unquote(version).trim())
}

fn package_name_from_descriptor(descriptor: &str) -> Option<String> {
    if descriptor.starts_with('@') {
        return scoped_name_from_descriptor(descriptor);
    }
    descriptor
        .split('@')
        .next()
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn scoped_name_from_descriptor(descriptor: &str) -> Option<String> {
    let at = descriptor.rfind('@')?;
    descriptor
        .get(..at)
        .filter(|name| name.contains('/'))
        .map(str::to_string)
}

fn unquote(value: &str) -> &str {
    value.trim_matches('"')
}
