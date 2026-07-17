use super::*;
use serde_json::Value as YamlValue;

const PUBSPEC_SECTIONS: &[&str] = &["dependencies", "dev_dependencies"];

pub(in crate::scan::engines::dep_hygiene) fn analyze_pubspec_yaml(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    let Ok(value) = crate::yaml::parse_value(raw) else {
        return Vec::new();
    };
    PUBSPEC_SECTIONS
        .iter()
        .flat_map(|section| section_findings(file_path, &value, section))
        .collect()
}

fn section_findings(file_path: &Path, value: &YamlValue, section: &str) -> Vec<DepHygieneFinding> {
    value
        .get(section)
        .and_then(YamlValue::as_object)
        .into_iter()
        .flat_map(|dependencies| dependencies.iter())
        .filter_map(|(name, dependency)| {
            pubspec_finding(file_path, section, name, dependency_version(dependency)?)
        })
        .collect()
}

fn pubspec_finding(
    file_path: &Path,
    section: &str,
    name: &str,
    constraint: &str,
) -> Option<DepHygieneFinding> {
    let trimmed = constraint.trim();
    if is_floating_pubspec_constraint(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::PubspecYaml,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::High,
            format!("{section}: floating constraint - accepts any future release without review"),
        ));
    }
    if is_floor_only_number_range(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::PubspecYaml,
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

fn dependency_version(value: &YamlValue) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.as_object()?.get("version")?.as_str())
}

fn is_floating_pubspec_constraint(constraint: &str) -> bool {
    constraint.is_empty()
        || constraint == "any"
        || constraint == "*"
        || constraint.eq_ignore_ascii_case("latest")
}
