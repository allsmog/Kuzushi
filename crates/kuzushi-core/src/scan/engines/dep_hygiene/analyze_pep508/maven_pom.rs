use super::*;
use roxmltree::Node;

pub(in crate::scan::engines::dep_hygiene) fn analyze_maven_pom(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    let Ok(document) = roxmltree::Document::parse(raw) else {
        return Vec::new();
    };
    dependency_elements(document.root_element())
        .filter_map(|dependency| maven_finding(file_path, dependency))
        .collect()
}

fn maven_finding(file_path: &Path, dependency: Node<'_, '_>) -> Option<DepHygieneFinding> {
    let name = dependency_name(dependency)?;
    let version = child_text(dependency, "version")?;
    if is_floating_maven_version(version) {
        return Some(DepHygieneFinding::new(
            ManifestKind::MavenPom,
            file_path,
            name,
            version,
            DepHygieneSeverity::High,
            "Maven dependency: floating version - accepts any future package release without review",
        ));
    }
    if is_open_ended_maven_range(version) {
        return Some(DepHygieneFinding::new(
            ManifestKind::MavenPom,
            file_path,
            name,
            version,
            DepHygieneSeverity::Medium,
            "Maven dependency: open-ended range; add an upper bound to fix the supply-chain surface",
        ));
    }
    None
}

fn dependency_elements<'a>(root: Node<'a, 'a>) -> impl Iterator<Item = Node<'a, 'a>> {
    child_elements(root, "dependencies")
        .flat_map(|dependencies| child_elements(dependencies, "dependency"))
}

fn dependency_name(dependency: Node<'_, '_>) -> Option<String> {
    let group_id = child_text(dependency, "groupId")?;
    let artifact_id = child_text(dependency, "artifactId")?;
    Some(format!("{group_id}/{artifact_id}"))
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

fn is_floating_maven_version(version: &str) -> bool {
    version == "*"
        || version.eq_ignore_ascii_case("latest")
        || version.eq_ignore_ascii_case("release")
}

fn is_open_ended_maven_range(version: &str) -> bool {
    let version = version.trim();
    let Some(inner) = version
        .strip_prefix('[')
        .or_else(|| version.strip_prefix('('))
        .and_then(|range| range.strip_suffix(')'))
    else {
        return false;
    };
    inner
        .split_once(',')
        .is_some_and(|(lower, upper)| !lower.trim().is_empty() && upper.trim().is_empty())
}
