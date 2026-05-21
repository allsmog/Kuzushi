use super::*;

pub(in crate::scan::engines::dep_hygiene) fn analyze_julia_project_toml(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    let Ok(value) = toml::from_str::<toml::Value>(raw) else {
        return Vec::new();
    };
    dependency_names(&value)
        .into_iter()
        .filter_map(|name| julia_finding(file_path, &name, compatibility(&value, &name)))
        .collect()
}

fn julia_finding(
    file_path: &Path,
    name: &str,
    constraint: Option<&str>,
) -> Option<DepHygieneFinding> {
    let constraint = constraint.unwrap_or("");
    let trimmed = constraint.trim();
    if is_floating_julia_compat(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::JuliaProjectToml,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::High,
            "compat: missing or floating compatibility bound",
        ));
    }
    if is_floor_only_number_range(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::JuliaProjectToml,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::Medium,
            "compat: floor-only range; add an upper bound to fix the supply-chain surface",
        ));
    }
    None
}

fn dependency_names(value: &toml::Value) -> Vec<String> {
    value
        .get("deps")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|deps| deps.keys())
        .filter(|name| *name != "julia")
        .map(|name| name.to_string())
        .collect()
}

fn compatibility<'a>(value: &'a toml::Value, name: &str) -> Option<&'a str> {
    value
        .get("compat")
        .and_then(toml::Value::as_table)?
        .get(name)?
        .as_str()
}

fn is_floating_julia_compat(constraint: &str) -> bool {
    constraint.is_empty()
        || constraint == "*"
        || constraint.eq_ignore_ascii_case("latest")
        || constraint.eq_ignore_ascii_case("dev")
}
