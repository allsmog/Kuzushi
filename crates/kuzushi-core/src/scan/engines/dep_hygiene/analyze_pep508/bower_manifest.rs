use super::*;

const BOWER_SECTIONS: &[&str] = &["dependencies", "devDependencies"];

pub(in crate::scan::engines::dep_hygiene) fn analyze_bower_json(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    BOWER_SECTIONS
        .iter()
        .flat_map(|section| section_findings(file_path, &value, section))
        .collect()
}

fn section_findings(file_path: &Path, value: &Value, section: &str) -> Vec<DepHygieneFinding> {
    value
        .get(section)
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|dependencies| dependencies.iter())
        .filter_map(|(name, value)| {
            bower_finding(file_path, section, name, dependency_version(value)?)
        })
        .collect()
}

fn bower_finding(
    file_path: &Path,
    section: &str,
    name: &str,
    constraint: &str,
) -> Option<DepHygieneFinding> {
    let trimmed = constraint.trim();
    if trimmed.is_empty() || trimmed == "*" || trimmed.eq_ignore_ascii_case("latest") {
        return Some(DepHygieneFinding::new(
            ManifestKind::BowerJson,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::High,
            format!("{section}: floating version - accepts any future release without review"),
        ));
    }
    if is_floor_only_number_range(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::BowerJson,
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

fn dependency_version(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.as_object()?.get("version")?.as_str())
}
