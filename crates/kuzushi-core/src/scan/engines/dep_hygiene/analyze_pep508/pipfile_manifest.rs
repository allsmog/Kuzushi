use super::*;

const PIPFILE_SECTIONS: &[&str] = &["packages", "dev-packages"];

pub(in crate::scan::engines::dep_hygiene) fn analyze_pipfile(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    let Ok(value) = toml::from_str::<toml::Value>(raw) else {
        return Vec::new();
    };
    PIPFILE_SECTIONS
        .iter()
        .flat_map(|section| section_findings(file_path, &value, section))
        .collect()
}

fn section_findings(
    file_path: &Path,
    value: &toml::Value,
    section: &str,
) -> Vec<DepHygieneFinding> {
    value
        .get(section)
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|packages| packages.iter())
        .filter_map(|(name, value)| pipfile_finding(file_path, section, name, value))
        .collect()
}

fn pipfile_finding(
    file_path: &Path,
    section: &str,
    name: &str,
    value: &toml::Value,
) -> Option<DepHygieneFinding> {
    let constraint = pipfile_constraint(value)?;
    if constraint == "*" || constraint.is_empty() || constraint.eq_ignore_ascii_case("latest") {
        return Some(DepHygieneFinding::new(
            ManifestKind::Pipfile,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::High,
            format!("{section}: wildcard pin - accepts any future release without review"),
        ));
    }
    if is_floor_only_nonempty_range(&constraint) {
        return Some(DepHygieneFinding::new(
            ManifestKind::Pipfile,
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

fn pipfile_constraint(value: &toml::Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|constraint| !constraint.is_empty())
        .map(str::to_string)
        .or_else(|| table_version(value))
}

fn table_version(value: &toml::Value) -> Option<String> {
    value
        .get("version")
        .and_then(toml::Value::as_str)
        .map(str::trim)
        .map(str::to_string)
}
