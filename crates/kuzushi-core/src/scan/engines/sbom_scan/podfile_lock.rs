use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn is_podfile_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "Podfile.lock")
}

pub(super) fn podfile_lock_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(target, path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(PodfileLockParser::new(&source).parse(&text))
}

pub(super) fn podfile_lock_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(target, path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(PodfileComponentParser::new(target, path, &source).parse(&text))
}

struct PodfileLockParser<'a> {
    source: &'a str,
    section: Option<LockSection>,
    current_pod: Option<String>,
}

impl<'a> PodfileLockParser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            section: None,
            current_pod: None,
        }
    }

    fn parse(&mut self, text: &str) -> Vec<SbomDependencyEdge> {
        text.lines()
            .filter_map(|line| self.edge_from_line(line))
            .collect()
    }

    fn edge_from_line(&mut self, line: &str) -> Option<SbomDependencyEdge> {
        if is_section_header(line) {
            self.section = lock_section(line);
            self.current_pod = None;
            return None;
        }
        match self.section {
            Some(LockSection::Pods) => self.pod_edge(line),
            Some(LockSection::Dependencies) => self.root_edge(line),
            None => None,
        }
    }

    fn pod_edge(&mut self, line: &str) -> Option<SbomDependencyEdge> {
        if let Some(name) = pod_line_name(line) {
            self.current_pod = Some(name);
            return None;
        }
        let to = pod_child_name(line)?;
        Some(SbomDependencyEdge {
            from: self.current_pod.clone()?,
            to,
            source: self.source.to_string(),
        })
    }

    fn root_edge(&self, line: &str) -> Option<SbomDependencyEdge> {
        let to = pod_line_name(line)?;
        Some(SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: self.source.to_string(),
        })
    }
}

struct PodfileComponentParser<'a> {
    target: &'a Path,
    path: &'a Path,
    source: &'a str,
    in_pods: bool,
}

impl<'a> PodfileComponentParser<'a> {
    fn new(target: &'a Path, path: &'a Path, source: &'a str) -> Self {
        Self {
            target,
            path,
            source,
            in_pods: false,
        }
    }

    fn parse(&mut self, text: &str) -> Vec<SbomComponent> {
        text.lines()
            .filter_map(|line| self.component_from_line(line))
            .collect()
    }

    fn component_from_line(&mut self, line: &str) -> Option<SbomComponent> {
        if is_section_header(line) {
            self.in_pods = matches!(lock_section(line), Some(LockSection::Pods));
            return None;
        }
        if !self.in_pods || !line.starts_with("  - ") {
            return None;
        }
        let pod = locked_pod(line)?;
        Some(component(
            self.target,
            self.path,
            "cocoapods",
            self.source,
            &pod.name,
            pod.version.as_deref(),
        ))
    }
}

#[derive(Clone, Copy)]
enum LockSection {
    Pods,
    Dependencies,
}

fn is_section_header(line: &str) -> bool {
    !line.starts_with(' ') && line.ends_with(':')
}

fn lock_section(line: &str) -> Option<LockSection> {
    match line {
        "PODS:" => Some(LockSection::Pods),
        "DEPENDENCIES:" => Some(LockSection::Dependencies),
        _ => None,
    }
}

fn pod_line_name(line: &str) -> Option<String> {
    if !line.starts_with("  - ") {
        return None;
    }
    pod_dependency_name(line)
}

fn pod_child_name(line: &str) -> Option<String> {
    if !line.starts_with("    - ") {
        return None;
    }
    pod_dependency_name(line)
}

fn pod_dependency_name(line: &str) -> Option<String> {
    let name = line
        .trim()
        .strip_prefix("- ")?
        .split([' ', '(', ':'])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())?;
    Some(name.to_string())
}

fn locked_pod(line: &str) -> Option<LockedPod> {
    let entry = line.trim().strip_prefix("- ")?.trim_end_matches(':');
    let (raw_name, raw_version) = entry.split_once(" (")?;
    let version = raw_version.strip_suffix(')')?.trim();
    let name = raw_name.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some(LockedPod {
        name: name.to_string(),
        version: Some(version.to_string()),
    })
}

struct LockedPod {
    name: String,
    version: Option<String>,
}
