use super::*;

const GRADLE_SCOPES: &[&str] = &[
    "api",
    "compileOnly",
    "implementation",
    "runtimeOnly",
    "testCompileOnly",
    "testImplementation",
    "testRuntimeOnly",
];

pub(in crate::scan::engines::dep_hygiene) fn analyze_gradle_build(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    raw.lines()
        .filter_map(gradle_dependency)
        .filter_map(|dependency| gradle_finding(file_path, dependency))
        .collect()
}

struct GradleDependency {
    name: String,
    version: String,
    scope: String,
}

fn gradle_dependency(line: &str) -> Option<GradleDependency> {
    let line = line.trim();
    let scope = gradle_scope(line)?;
    let (name, version) = gradle_coordinate_from_line(line)?;
    Some(GradleDependency {
        name,
        version: version?,
        scope: scope.to_string(),
    })
}

fn gradle_finding(file_path: &Path, dependency: GradleDependency) -> Option<DepHygieneFinding> {
    if is_floating_gradle_version(&dependency.version) {
        return Some(DepHygieneFinding::new(
            ManifestKind::GradleBuild,
            file_path,
            dependency.name,
            dependency.version,
            DepHygieneSeverity::High,
            format!(
                "{}: floating version - accepts any future package release without review",
                dependency.scope
            ),
        ));
    }
    if is_open_ended_gradle_range(&dependency.version) {
        return Some(DepHygieneFinding::new(
            ManifestKind::GradleBuild,
            file_path,
            dependency.name,
            dependency.version,
            DepHygieneSeverity::Medium,
            format!(
                "{}: open-ended range; add an upper bound to fix the supply-chain surface",
                dependency.scope
            ),
        ));
    }
    None
}

fn gradle_scope(line: &str) -> Option<&'static str> {
    GRADLE_SCOPES
        .iter()
        .copied()
        .find(|scope| line_has_scope(line, scope))
}

fn line_has_scope(line: &str, scope: &str) -> bool {
    line.strip_prefix(scope)
        .and_then(|suffix| suffix.chars().next())
        .is_some_and(|next| next.is_whitespace() || next == '(')
}

fn gradle_coordinate_from_line(line: &str) -> Option<(String, Option<String>)> {
    quoted_coordinate(line)
        .and_then(|coordinate| gradle_coordinate(&coordinate))
        .or_else(|| gradle_map_coordinate(line))
}

fn quoted_coordinate(line: &str) -> Option<String> {
    for quote in ['"', '\''] {
        if let Some(value) = value_between_quotes(line, quote) {
            return Some(value.to_string());
        }
    }
    None
}

fn value_between_quotes(line: &str, quote: char) -> Option<&str> {
    let start = line.find(quote)? + quote.len_utf8();
    let end = line[start..].find(quote)? + start;
    Some(line[start..end].trim()).filter(|value| !value.is_empty())
}

fn gradle_coordinate(value: &str) -> Option<(String, Option<String>)> {
    let parts = value.split(':').collect::<Vec<_>>();
    match parts.as_slice() {
        [group, artifact, version] => coordinate_parts(group, artifact, Some(*version)),
        [group, artifact] => coordinate_parts(group, artifact, None),
        _ => None,
    }
}

fn gradle_map_coordinate(line: &str) -> Option<(String, Option<String>)> {
    let group = gradle_named_value(line, "group")?;
    let artifact =
        gradle_named_value(line, "name").or_else(|| gradle_named_value(line, "artifact"))?;
    let version = gradle_named_value(line, "version");
    coordinate_parts(&group, &artifact, version.as_deref())
}

fn gradle_named_value(line: &str, key: &str) -> Option<String> {
    let (_, tail) = line.split_once(&format!("{key}:"))?;
    quoted_coordinate(tail)
}

fn coordinate_parts(
    group: &str,
    artifact: &str,
    version: Option<&str>,
) -> Option<(String, Option<String>)> {
    let group = group.trim();
    let artifact = artifact.trim();
    if group.is_empty() || artifact.is_empty() {
        return None;
    }
    Some((
        format!("{group}/{artifact}"),
        version
            .map(str::trim)
            .filter(|version| !version.is_empty())
            .map(str::to_string),
    ))
}

fn is_floating_gradle_version(version: &str) -> bool {
    version == "+"
        || version.ends_with(".+")
        || version.eq_ignore_ascii_case("latest.release")
        || version.eq_ignore_ascii_case("latest.integration")
}

fn is_open_ended_gradle_range(version: &str) -> bool {
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
