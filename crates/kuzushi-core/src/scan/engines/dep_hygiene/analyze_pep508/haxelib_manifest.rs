use super::*;

pub(in crate::scan::engines::dep_hygiene) fn analyze_haxelib_json(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    value
        .get("dependencies")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|dependencies| dependencies.iter())
        .filter_map(|(name, value)| haxelib_finding(file_path, name, value.as_str()?))
        .collect()
}

fn haxelib_finding(
    file_path: &Path,
    name: &str,
    constraint: &str,
) -> Option<DepHygieneFinding> {
    let trimmed = constraint.trim();
    if is_floating_haxelib_constraint(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::HaxelibJson,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::High,
            "dependencies: floating constraint - accepts any future release without review",
        ));
    }
    if is_floor_only_number_range(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::HaxelibJson,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::Medium,
            "dependencies: floor-only range; add an upper bound to fix the supply-chain surface",
        ));
    }
    None
}

fn is_floating_haxelib_constraint(constraint: &str) -> bool {
    constraint.is_empty()
        || constraint == "*"
        || constraint.eq_ignore_ascii_case("latest")
        || constraint.eq_ignore_ascii_case("dev")
}
