use super::*;

const COMPOSER_SECTIONS: &[&str] = &["require", "require-dev"];

pub(in crate::scan::engines::dep_hygiene) fn analyze_composer_json(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    COMPOSER_SECTIONS
        .iter()
        .flat_map(|section| section_findings(file_path, &value, section))
        .collect()
}

fn section_findings(file_path: &Path, value: &Value, section: &str) -> Vec<DepHygieneFinding> {
    value
        .get(section)
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|packages| packages.iter())
        .filter(|(name, _)| is_composer_package(name))
        .filter_map(|(name, value)| composer_finding(file_path, section, name, value.as_str()?))
        .collect()
}

fn composer_finding(
    file_path: &Path,
    section: &str,
    name: &str,
    constraint: &str,
) -> Option<DepHygieneFinding> {
    let trimmed = constraint.trim();
    if is_floating_composer_constraint(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::ComposerJson,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::High,
            format!("{section}: floating constraint - accepts any future release without review"),
        ));
    }
    if is_floor_only_nonempty_range(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::ComposerJson,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::Medium,
            format!(
                "{section}: floor-only range; add an upper bound to fix the supply-chain surface"
            ),
        ));
    }
    None
}

fn is_composer_package(name: &str) -> bool {
    name != "php"
        && !name.starts_with("ext-")
        && !name.starts_with("lib-")
        && !name.starts_with("composer-")
}

fn is_floating_composer_constraint(constraint: &str) -> bool {
    constraint.is_empty()
        || constraint == "*"
        || constraint.eq_ignore_ascii_case("latest")
        || constraint.eq_ignore_ascii_case("dev-master")
        || constraint.eq_ignore_ascii_case("dev-main")
}
