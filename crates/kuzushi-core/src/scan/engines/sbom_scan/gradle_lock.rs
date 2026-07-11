use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn is_gradle_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "gradle.lockfile")
}

pub(super) fn gradle_lock_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(text
        .lines()
        .filter_map(gradle_dependency)
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to: to.name,
            source: source.clone(),
        })
        .collect())
}

pub(super) fn gradle_lock_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(text
        .lines()
        .filter_map(gradle_dependency)
        .map(|dependency| dependency.to_component(target, path, &source))
        .collect())
}

fn gradle_dependency(line: &str) -> Option<GradleDependency> {
    let dependency = line.split_once('=')?.0.trim();
    if dependency.is_empty() || dependency.starts_with('#') {
        return None;
    }
    let parts = dependency.split(':').collect::<Vec<_>>();
    match parts.as_slice() {
        [group, artifact, version]
            if !group.is_empty() && !artifact.is_empty() && !version.is_empty() =>
        {
            Some(GradleDependency {
                name: format!("{group}/{artifact}"),
                version: version.to_string(),
            })
        }
        _ => None,
    }
}

struct GradleDependency {
    name: String,
    version: String,
}

impl GradleDependency {
    fn to_component(&self, target: &Path, path: &Path, source: &str) -> SbomComponent {
        component(
            target,
            path,
            "maven",
            source,
            &self.name,
            Some(&self.version),
        )
    }
}
