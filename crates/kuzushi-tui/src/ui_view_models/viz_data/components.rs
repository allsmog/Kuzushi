use super::ShellApp;
use crate::app::TargetCandidateFacts;
use kuzushi_core::{SbomComponent, SbomScanReport};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ComponentStack {
    pub target: String,
    pub languages: Vec<String>,
    pub build_systems: Vec<String>,
    pub sources: Vec<ComponentSource>,
    pub manifest_count: usize,
    pub lockfile_count: usize,
    pub declared_count: usize,
    pub resolved_count: usize,
    pub ecosystems: Vec<String>,
    pub empty_hint: Option<String>,
    pub from_tool: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ComponentSource {
    pub path: String,
    pub ecosystem: String,
    pub kind: ComponentSourceKind,
    pub scopes: Vec<ComponentScope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ComponentScope {
    pub name: String,
    pub components: Vec<ComponentItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ComponentItem {
    pub name: String,
    pub declared: Option<String>,
    /// Exact versions observed anywhere in the target's lockfiles. These are
    /// repository-wide evidence, not a claim that one manifest selected each
    /// version.
    pub repository_versions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ComponentSourceKind {
    Manifest,
    Lockfile,
}

type ResolutionIndex = BTreeMap<(String, String), BTreeSet<String>>;
type SourceKey = (ComponentSourceKind, String, String);
type ScopeMap = BTreeMap<String, Vec<ComponentItem>>;

pub(crate) fn component_stack(app: &ShellApp) -> ComponentStack {
    let Some(facts) = app.active_target_facts() else {
        return ComponentStack {
            empty_hint: Some(component_inventory_waiting_hint(app)),
            ..Default::default()
        };
    };
    component_stack_from_facts(facts)
}

fn component_inventory_waiting_hint(app: &ShellApp) -> String {
    if app.target().is_none() {
        "No active target. Select a repository before inspecting components.".to_string()
    } else if app.active_target_facts_loading() {
        "component inventory is still loading from repository manifests".to_string()
    } else {
        "No component inventory is available. Run `run sbom-scan:scan`.".to_string()
    }
}

fn component_stack_from_facts(facts: &TargetCandidateFacts) -> ComponentStack {
    let Some(report) = facts.component_inventory.as_ref() else {
        let detail = facts
            .component_inventory_error
            .as_deref()
            .unwrap_or("inventory unavailable");
        return ComponentStack {
            target: target_label(facts),
            empty_hint: Some(format!(
                "Component inventory failed: {detail}. Review `options sbom-scan:scan`, then run `run sbom-scan:scan` for a full receipt."
            )),
            ..Default::default()
        };
    };
    component_stack_from_report(facts, report)
}

fn component_stack_from_report(
    facts: &TargetCandidateFacts,
    report: &SbomScanReport,
) -> ComponentStack {
    let lock_paths = report
        .lockfiles
        .iter()
        .map(|lockfile| lockfile.path.as_str())
        .collect::<BTreeSet<_>>();
    let resolutions = resolution_index(&report.components, &lock_paths);
    let sources = component_sources(&report.components, &lock_paths, &resolutions);
    let declared_count = report
        .components
        .iter()
        .filter(|component| !lock_paths.contains(component.manifest_path.as_str()))
        .count();
    let resolved_count = report.components.len().saturating_sub(declared_count);
    ComponentStack {
        target: target_label(facts),
        languages: facts.languages.clone(),
        build_systems: facts.build_systems.clone(),
        sources,
        manifest_count: report.manifests_scanned,
        lockfile_count: report.lockfiles.len(),
        declared_count,
        resolved_count,
        ecosystems: report.by_ecosystem.keys().cloned().collect(),
        empty_hint: None,
        from_tool: facts.component_inventory_from_tool,
    }
}

fn target_label(facts: &TargetCandidateFacts) -> String {
    facts
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("target")
        .to_string()
}

fn resolution_index(components: &[SbomComponent], lock_paths: &BTreeSet<&str>) -> ResolutionIndex {
    let mut index = ResolutionIndex::new();
    for component in components
        .iter()
        .filter(|component| lock_paths.contains(component.manifest_path.as_str()))
    {
        let Some(version) = component.version.as_ref() else {
            continue;
        };
        index
            .entry((component.ecosystem.clone(), component.name.clone()))
            .or_default()
            .insert(version.clone());
    }
    index
}

fn component_sources(
    components: &[SbomComponent],
    lock_paths: &BTreeSet<&str>,
    resolutions: &ResolutionIndex,
) -> Vec<ComponentSource> {
    let mut grouped = BTreeMap::<SourceKey, ScopeMap>::new();
    for component in components {
        let kind = source_kind(component, lock_paths);
        let source = (
            kind,
            component.ecosystem.clone(),
            component.manifest_path.clone(),
        );
        let scope = component_scope(component, kind);
        grouped
            .entry(source)
            .or_default()
            .entry(scope)
            .or_default()
            .push(component_item(component, kind, resolutions));
    }
    grouped
        .into_iter()
        .map(|((kind, ecosystem, path), scopes)| ComponentSource {
            path,
            ecosystem,
            kind,
            scopes: sorted_scopes(scopes),
        })
        .collect()
}

fn source_kind(component: &SbomComponent, lock_paths: &BTreeSet<&str>) -> ComponentSourceKind {
    if lock_paths.contains(component.manifest_path.as_str()) {
        ComponentSourceKind::Lockfile
    } else {
        ComponentSourceKind::Manifest
    }
}

fn component_scope(component: &SbomComponent, kind: ComponentSourceKind) -> String {
    match kind {
        ComponentSourceKind::Manifest => component.scope.clone(),
        ComponentSourceKind::Lockfile => "resolved transitive inventory".to_string(),
    }
}

fn component_item(
    component: &SbomComponent,
    kind: ComponentSourceKind,
    resolutions: &ResolutionIndex,
) -> ComponentItem {
    let repository_versions = match kind {
        ComponentSourceKind::Manifest => resolutions
            .get(&(component.ecosystem.clone(), component.name.clone()))
            .map(|versions| versions.iter().cloned().collect())
            .unwrap_or_default(),
        ComponentSourceKind::Lockfile => component.version.iter().cloned().collect(),
    };
    ComponentItem {
        name: component.name.clone(),
        declared: (kind == ComponentSourceKind::Manifest)
            .then(|| component.version.clone())
            .flatten(),
        repository_versions,
    }
}

fn sorted_scopes(scopes: ScopeMap) -> Vec<ComponentScope> {
    scopes
        .into_iter()
        .map(|(name, mut components)| {
            components.sort_by(|left, right| {
                left.name
                    .cmp(&right.name)
                    .then_with(|| left.declared.cmp(&right.declared))
            });
            components.dedup();
            ComponentScope { name, components }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{SbomDependencyEdge, SbomLockfile};
    use std::path::PathBuf;

    #[test]
    fn stack_keeps_declared_ranges_distinct_from_lockfile_versions() {
        let facts = TargetCandidateFacts {
            path: PathBuf::from("/repo/demo"),
            repository_kind: "git repository".into(),
            branch: None,
            revision: None,
            dirty: None,
            languages: vec!["TypeScript".into()],
            build_systems: vec!["Node".into()],
            nested_scopes: Vec::new(),
            file_count: 2,
            file_count_capped: false,
            prior_artifact_count: 0,
            prior_artifacts: Vec::new(),
            component_inventory: Some(report()),
            component_inventory_error: None,
            component_inventory_from_tool: false,
        };

        let stack = component_stack_from_facts(&facts);

        assert_eq!(stack.target, "demo");
        assert_eq!(stack.declared_count, 1);
        assert_eq!(stack.resolved_count, 2);
        assert_eq!(stack.sources.len(), 2);
        let manifest = &stack.sources[0];
        assert_eq!(manifest.kind, ComponentSourceKind::Manifest);
        assert_eq!(
            manifest.scopes[0].components[0].declared.as_deref(),
            Some("^1")
        );
        assert_eq!(
            manifest.scopes[0].components[0].repository_versions,
            vec!["1.4.2".to_string(), "1.5.0".to_string()]
        );
    }

    fn report() -> SbomScanReport {
        SbomScanReport {
            target: "/repo/demo".into(),
            manifests_scanned: 1,
            lockfiles: vec![SbomLockfile {
                path: "bun.lock".into(),
                sha256: "abc".into(),
            }],
            dependencies: Vec::<SbomDependencyEdge>::new(),
            components: vec![
                component("package.json", "dependencies", "^1"),
                component("bun.lock", "bun.lock", "1.4.2"),
                component("bun.lock", "bun.lock", "1.5.0"),
            ],
            by_ecosystem: BTreeMap::from([("npm".into(), 3)]),
        }
    }

    fn component(path: &str, scope: &str, version: &str) -> SbomComponent {
        SbomComponent {
            name: "framework".into(),
            version: Some(version.into()),
            package_url: None,
            ecosystem: "npm".into(),
            manifest_path: path.into(),
            scope: scope.into(),
        }
    }
}
