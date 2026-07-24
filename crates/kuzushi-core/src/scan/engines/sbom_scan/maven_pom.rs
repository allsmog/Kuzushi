use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use roxmltree::Node;
use std::path::Path;

pub(super) fn is_maven_pom(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "pom.xml")
}

pub(super) fn maven_pom_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<SbomComponent>> {
    let document = roxmltree::Document::parse(text).context("sbom-scan: parse Maven pom.xml")?;
    let project = document.root_element();
    let components = child_elements(project, "dependencies")
        .flat_map(|dependencies| child_elements(dependencies, "dependency"))
        .filter_map(|dependency| dependency_component(target, path, dependency))
        .collect();
    Ok(components)
}

pub(super) fn maven_pom_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(target, path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let document = roxmltree::Document::parse(&text).context("sbom-scan: parse Maven pom.xml")?;
    let source = relative_display(target, path);
    let edges = child_elements(document.root_element(), "dependencies")
        .flat_map(|dependencies| child_elements(dependencies, "dependency"))
        .filter_map(|dependency| dependency_name(dependency))
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect();
    Ok(edges)
}

fn dependency_component(
    target: &Path,
    path: &Path,
    dependency: Node<'_, '_>,
) -> Option<SbomComponent> {
    let name = dependency_name(dependency)?;
    let scope = dependency_scope(dependency);
    Some(component(
        target,
        path,
        "maven",
        &scope,
        &name,
        child_text(dependency, "version"),
    ))
}

fn dependency_name(dependency: Node<'_, '_>) -> Option<String> {
    let group_id = child_text(dependency, "groupId")?;
    let artifact_id = child_text(dependency, "artifactId")?;
    Some(format!("{group_id}/{artifact_id}"))
}

fn dependency_scope(dependency: Node<'_, '_>) -> String {
    match child_text(dependency, "scope") {
        Some(scope) => format!("dependencies.{scope}"),
        None => "dependencies".to_string(),
    }
}

fn child_elements<'a>(
    node: Node<'a, 'a>,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'a>> {
    node.children()
        .filter(move |child| child.is_element() && child.tag_name().name() == name)
}

fn child_text<'a>(node: Node<'a, 'a>, name: &'static str) -> Option<&'a str> {
    child_elements(node, name)
        .find_map(|child| child.text())
        .map(str::trim)
        .filter(|text| !text.is_empty())
}
