use super::{SbomComponent, SbomDependencyEdge, component, relative_display};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub(super) fn go_mod_components(target: &Path, path: &Path, text: &str) -> Vec<SbomComponent> {
    let mut parser = GoModParser::default();
    text.lines()
        .filter_map(|line| parser.dependency(line))
        .map(|(name, version)| component(target, path, "go", "require", name, Some(version)))
        .collect()
}

pub(super) fn is_go_mod(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "go.mod")
}

pub(super) fn go_mod_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    let mut parser = GoModParser::default();
    Ok(text
        .lines()
        .filter_map(|line| parser.dependency(line))
        .map(|(name, _)| SbomDependencyEdge {
            from: "root".to_string(),
            to: name.to_string(),
            source: source.clone(),
        })
        .collect())
}

#[derive(Default)]
struct GoModParser {
    in_require_block: bool,
}

impl GoModParser {
    fn dependency<'a>(&mut self, line: &'a str) -> Option<(&'a str, &'a str)> {
        let line = line.trim();
        if self.enter_require_block(line) || self.exit_require_block(line) {
            return None;
        }
        go_requirement_line(line, self.in_require_block).and_then(go_dependency_parts)
    }

    fn enter_require_block(&mut self, line: &str) -> bool {
        if line != "require (" {
            return false;
        }
        self.in_require_block = true;
        true
    }

    fn exit_require_block(&mut self, line: &str) -> bool {
        if !self.in_require_block || line != ")" {
            return false;
        }
        self.in_require_block = false;
        true
    }
}

fn go_requirement_line(line: &str, in_require_block: bool) -> Option<&str> {
    if in_require_block {
        return Some(line);
    }
    line.strip_prefix("require ").map(str::trim)
}

fn go_dependency_parts(line: &str) -> Option<(&str, &str)> {
    let line = line.split("//").next().unwrap_or(line).trim();
    let mut parts = line.split_whitespace();
    Some((parts.next()?, parts.next()?))
}
