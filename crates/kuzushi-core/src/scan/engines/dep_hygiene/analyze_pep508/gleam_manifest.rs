use super::*;

const GLEAM_DEPENDENCY_SCOPES: &[&str] = &["dependencies", "dev-dependencies"];

pub(in crate::scan::engines::dep_hygiene) fn analyze_gleam_toml(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    let Ok(value) = toml::from_str::<toml::Value>(raw) else {
        return Vec::new();
    };
    GLEAM_DEPENDENCY_SCOPES
        .iter()
        .flat_map(|scope| section_findings(file_path, &value, scope))
        .collect()
}

fn section_findings(
    file_path: &Path,
    value: &toml::Value,
    scope: &str,
) -> Vec<DepHygieneFinding> {
    value
        .get(scope)
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|dependencies| dependencies.iter())
        .filter_map(|(name, value)| gleam_finding(file_path, scope, name, value.as_str()?))
        .collect()
}

fn gleam_finding(
    file_path: &Path,
    scope: &str,
    name: &str,
    constraint: &str,
) -> Option<DepHygieneFinding> {
    let trimmed = constraint.trim();
    if is_floating_gleam_constraint(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::GleamToml,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::High,
            format!("{scope}: floating constraint - accepts any future release without review"),
        ));
    }
    if is_floor_only_number_range(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::GleamToml,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::Medium,
            format!("{scope}: floor-only range; add an upper bound to fix the supply-chain surface"),
        ));
    }
    None
}

fn is_floating_gleam_constraint(constraint: &str) -> bool {
    constraint.is_empty()
        || constraint == "*"
        || constraint.eq_ignore_ascii_case("latest")
        || constraint.eq_ignore_ascii_case("dev")
}
