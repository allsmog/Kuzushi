use super::*;
use roxmltree::Node;

pub(in crate::scan::engines::dep_hygiene) fn analyze_dotnet_project(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    let Ok(document) = roxmltree::Document::parse(raw) else {
        return Vec::new();
    };
    package_references(document.root_element())
        .filter_map(|reference| dotnet_finding(file_path, reference))
        .collect()
}

fn dotnet_finding(file_path: &Path, reference: Node<'_, '_>) -> Option<DepHygieneFinding> {
    let name = package_name(reference)?;
    let version = package_version(reference)?;
    if is_floating_dotnet_version(version) {
        return Some(DepHygieneFinding::new(
            ManifestKind::DotnetProject,
            file_path,
            name,
            version,
            DepHygieneSeverity::High,
            "PackageReference: floating version - accepts any future package release without review",
        ));
    }
    if is_floor_only_dotnet_version(version) {
        return Some(DepHygieneFinding::new(
            ManifestKind::DotnetProject,
            file_path,
            name,
            version,
            DepHygieneSeverity::Medium,
            "PackageReference: floor-only range; add an upper bound to fix the supply-chain surface",
        ));
    }
    None
}

fn package_references<'a>(root: Node<'a, 'a>) -> impl Iterator<Item = Node<'a, 'a>> {
    root.descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "PackageReference")
}

fn package_name<'a>(reference: Node<'a, 'a>) -> Option<&'a str> {
    reference
        .attribute("Include")
        .or_else(|| reference.attribute("Update"))
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn package_version<'a>(reference: Node<'a, 'a>) -> Option<&'a str> {
    reference
        .attribute("Version")
        .or_else(|| child_text(reference, "Version"))
        .map(str::trim)
        .filter(|version| !version.is_empty())
}

fn child_text<'a>(node: Node<'a, 'a>, name: &'static str) -> Option<&'a str> {
    node.children()
        .filter(|child| child.is_element() && child.tag_name().name() == name)
        .find_map(|child| child.text())
}

fn is_floating_dotnet_version(version: &str) -> bool {
    version == "*" || version.eq_ignore_ascii_case("latest") || version.contains('*')
}

fn is_floor_only_dotnet_version(version: &str) -> bool {
    is_floor_only_nonempty_range(version) || is_open_ended_nuget_range(version)
}

fn is_open_ended_nuget_range(version: &str) -> bool {
    let version = version.trim();
    version.starts_with('[')
        && version.ends_with(",)")
        && version
            .trim_start_matches('[')
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_digit())
}
