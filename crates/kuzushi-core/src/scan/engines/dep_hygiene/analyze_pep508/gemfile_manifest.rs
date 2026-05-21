use super::*;

pub(in crate::scan::engines::dep_hygiene) fn analyze_gemfile(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    raw.lines()
        .filter_map(gem_declaration)
        .filter_map(|dependency| gemfile_finding(file_path, dependency))
        .collect()
}

struct GemDependency {
    name: String,
    constraint: String,
}

fn gem_declaration(line: &str) -> Option<GemDependency> {
    let line = line.trim_start();
    let rest = line.strip_prefix("gem ")?;
    let mut parts = rest.split(',').map(str::trim);
    let name = quoted_value(parts.next()?)?;
    Some(GemDependency {
        name: name.to_string(),
        constraint: gem_constraints(parts),
    })
}

fn gemfile_finding(
    file_path: &Path,
    dependency: GemDependency,
) -> Option<DepHygieneFinding> {
    let constraint = dependency.constraint.trim();
    if is_floating_gem_constraint(constraint) {
        return Some(DepHygieneFinding::new(
            ManifestKind::Gemfile,
            file_path,
            dependency.name,
            constraint,
            DepHygieneSeverity::High,
            "Gemfile: floating constraint - accepts any future gem release without review",
        ));
    }
    if is_floor_only_gem_constraint(constraint) {
        return Some(DepHygieneFinding::new(
            ManifestKind::Gemfile,
            file_path,
            dependency.name,
            constraint,
            DepHygieneSeverity::Medium,
            "Gemfile: floor-only range; add an upper bound to fix the supply-chain surface",
        ));
    }
    None
}

fn gem_constraints<'a>(parts: impl Iterator<Item = &'a str>) -> String {
    parts
        .filter_map(quoted_value)
        .collect::<Vec<_>>()
        .join(",")
}

fn quoted_value(value: &str) -> Option<&str> {
    value
        .strip_prefix('"')
        .and_then(|value| value.split('"').next())
        .or_else(|| value.strip_prefix('\'').and_then(|value| value.split('\'').next()))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn is_floating_gem_constraint(constraint: &str) -> bool {
    constraint.is_empty()
        || constraint == "*"
        || constraint.eq_ignore_ascii_case("latest")
        || constraint.eq_ignore_ascii_case(">= 0")
        || constraint.eq_ignore_ascii_case(">= 0.0.0")
}

fn is_floor_only_gem_constraint(constraint: &str) -> bool {
    is_floor_only_nonempty_range(&compact_gem_constraint(constraint))
}

fn compact_gem_constraint(constraint: &str) -> String {
    constraint.split_whitespace().collect()
}
