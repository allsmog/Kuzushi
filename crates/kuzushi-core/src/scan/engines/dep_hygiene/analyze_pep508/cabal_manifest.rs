use super::*;

pub(in crate::scan::engines::dep_hygiene) fn analyze_cabal_file(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    let mut in_build_depends = false;
    raw.lines()
        .filter_map(|line| dependencies_from_line(line, &mut in_build_depends))
        .flatten()
        .filter_map(|dependency| cabal_finding(file_path, dependency))
        .collect()
}

fn cabal_finding(file_path: &Path, dependency: CabalDependency<'_>) -> Option<DepHygieneFinding> {
    let constraint = dependency.constraint.unwrap_or("");
    let trimmed = constraint.trim();
    if is_floating_cabal_constraint(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::CabalFile,
            file_path,
            dependency.name,
            constraint,
            DepHygieneSeverity::High,
            "build-depends: floating constraint - accepts any future release without review",
        ));
    }
    if is_floor_only_number_range(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::CabalFile,
            file_path,
            dependency.name,
            constraint,
            DepHygieneSeverity::Medium,
            "build-depends: floor-only range; add an upper bound to fix the supply-chain surface",
        ));
    }
    None
}

fn dependencies_from_line<'a>(
    line: &'a str,
    in_build_depends: &mut bool,
) -> Option<Vec<CabalDependency<'a>>> {
    let line = strip_comment(line);
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Some(Vec::new());
    }
    if let Some(rest) = trimmed.strip_prefix("build-depends:") {
        *in_build_depends = true;
        return Some(parse_dependencies(rest));
    }
    if dependency_continuation(line, trimmed, *in_build_depends) {
        return Some(parse_dependencies(trimmed));
    }
    *in_build_depends = false;
    Some(Vec::new())
}

fn dependency_continuation(line: &str, trimmed: &str, in_build_depends: bool) -> bool {
    in_build_depends && line.starts_with([' ', '\t']) && !trimmed.contains(':')
}

fn parse_dependencies(text: &str) -> Vec<CabalDependency<'_>> {
    text.split(',').filter_map(cabal_dependency).collect()
}

fn cabal_dependency(text: &str) -> Option<CabalDependency<'_>> {
    let text = text.trim();
    let name = text
        .split([' ', '<', '>', '=', '^', '~'])
        .next()
        .unwrap_or_default()
        .trim();
    if name.is_empty() {
        return None;
    }
    let constraint = text
        .strip_prefix(name)
        .map(str::trim)
        .filter(|rest| !rest.is_empty());
    Some(CabalDependency { name, constraint })
}

fn strip_comment(line: &str) -> &str {
    line.split("--").next().unwrap_or(line)
}

fn is_floating_cabal_constraint(constraint: &str) -> bool {
    constraint.is_empty()
        || constraint == "*"
        || constraint.eq_ignore_ascii_case("latest")
        || constraint.eq_ignore_ascii_case("dev")
}

struct CabalDependency<'a> {
    name: &'a str,
    constraint: Option<&'a str>,
}
