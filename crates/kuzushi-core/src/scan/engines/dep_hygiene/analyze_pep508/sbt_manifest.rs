use super::*;

pub(in crate::scan::engines::dep_hygiene) fn analyze_sbt_build(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    raw.lines()
        .filter_map(|line| sbt_dependency(line).and_then(|dep| sbt_finding(file_path, dep)))
        .collect()
}

fn sbt_finding(file_path: &Path, dependency: SbtDependency) -> Option<DepHygieneFinding> {
    let trimmed = dependency.version.trim();
    if is_floating_sbt_version(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::SbtBuild,
            file_path,
            dependency.name,
            dependency.version,
            DepHygieneSeverity::High,
            "libraryDependencies: floating version - accepts any future release without review",
        ));
    }
    if is_floor_only_number_range(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::SbtBuild,
            file_path,
            dependency.name,
            dependency.version,
            DepHygieneSeverity::Medium,
            "libraryDependencies: floor-only range; add an upper bound to fix the supply-chain surface",
        ));
    }
    None
}

fn sbt_dependency(line: &str) -> Option<SbtDependency> {
    let trimmed = line.trim();
    if !dependency_candidate(trimmed) {
        return None;
    }
    let values = quoted_values(trimmed);
    let [group, artifact, version, ..] = values.as_slice() else {
        return None;
    };
    Some(SbtDependency {
        name: format!("{group}/{artifact}"),
        version: version.to_string(),
    })
}

fn dependency_candidate(line: &str) -> bool {
    line.contains("libraryDependencies") || line.starts_with('"')
}

fn quoted_values(line: &str) -> Vec<String> {
    line.split('"')
        .skip(1)
        .step_by(2)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn is_floating_sbt_version(version: &str) -> bool {
    version.is_empty()
        || version == "+"
        || version.ends_with(".+")
        || version.eq_ignore_ascii_case("latest")
        || version.eq_ignore_ascii_case("latest.release")
        || version.eq_ignore_ascii_case("latest.integration")
}

struct SbtDependency {
    name: String,
    version: String,
}
