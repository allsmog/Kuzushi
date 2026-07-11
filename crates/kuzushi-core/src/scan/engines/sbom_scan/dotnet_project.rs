use super::bounded_fs as fs;
use super::{component, relative_display, SbomComponent, SbomDependencyEdge};
use anyhow::{Context, Result};
use roxmltree::Node;
use std::path::Path;

pub(super) fn is_dotnet_project(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches_dotnet_project_extension(extension))
}

fn matches_dotnet_project_extension(extension: &str) -> bool {
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "csproj" | "fsproj" | "vbproj"
    )
}

pub(super) fn dotnet_project_components(
    target: &Path,
    path: &Path,
    text: &str,
) -> Result<Vec<SbomComponent>> {
    let document =
        roxmltree::Document::parse(text).context("sbom-scan: parse .NET project file")?;
    let components = package_references(document.root_element())
        .filter_map(|reference| package_reference_component(target, path, reference))
        .collect();
    Ok(components)
}

pub(super) fn dotnet_project_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let document =
        roxmltree::Document::parse(&text).context("sbom-scan: parse .NET project file")?;
    let source = relative_display(target, path);
    let edges = package_references(document.root_element())
        .filter_map(package_reference_name)
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect();
    Ok(edges)
}

fn package_reference_component(
    target: &Path,
    path: &Path,
    reference: Node<'_, '_>,
) -> Option<SbomComponent> {
    let name = package_reference_name(reference)?;
    Some(component(
        target,
        path,
        "nuget",
        "PackageReference",
        &name,
        package_reference_version(reference),
    ))
}

fn package_references<'a>(root: Node<'a, 'a>) -> impl Iterator<Item = Node<'a, 'a>> {
    root.descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "PackageReference")
}

fn package_reference_name(reference: Node<'_, '_>) -> Option<String> {
    reference
        .attribute("Include")
        .or_else(|| reference.attribute("Update"))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn package_reference_version<'a>(reference: Node<'a, 'a>) -> Option<&'a str> {
    reference
        .attribute("Version")
        .or_else(|| child_text(reference, "Version"))
}

fn child_text<'a>(node: Node<'a, 'a>, name: &'static str) -> Option<&'a str> {
    node.children()
        .filter(|child| child.is_element() && child.tag_name().name() == name)
        .find_map(|child| child.text())
        .map(str::trim)
        .filter(|text| !text.is_empty())
}
