use super::*;
use serde_json::Value as YamlValue;

const SHARD_SCOPES: &[&str] = &["dependencies", "development_dependencies"];

pub(in crate::scan::engines::dep_hygiene) fn analyze_shard_manifest(
    file_path: &Path,
    raw: &str,
    manifest: ManifestKind,
) -> Vec<DepHygieneFinding> {
    let Ok(value) = crate::yaml::parse_value(raw) else {
        return Vec::new();
    };
    SHARD_SCOPES
        .iter()
        .flat_map(|scope| section_findings(file_path, &value, scope, manifest))
        .collect()
}

fn section_findings(
    file_path: &Path,
    value: &YamlValue,
    scope: &str,
    manifest: ManifestKind,
) -> Vec<DepHygieneFinding> {
    value
        .get(scope)
        .and_then(YamlValue::as_object)
        .into_iter()
        .flat_map(|dependencies| dependencies.iter())
        .filter_map(|(name, dependency)| {
            shard_finding(
                file_path,
                manifest,
                scope,
                name,
                dependency_version(dependency),
            )
        })
        .collect()
}

fn shard_finding(
    file_path: &Path,
    manifest: ManifestKind,
    scope: &str,
    name: &str,
    constraint: Option<&str>,
) -> Option<DepHygieneFinding> {
    let constraint = constraint.unwrap_or("");
    let trimmed = constraint.trim();
    if is_floating_shard_constraint(trimmed) {
        return Some(DepHygieneFinding::new(
            manifest,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::High,
            format!("{scope}: floating constraint - accepts any future release without review"),
        ));
    }
    if is_floor_only_number_range(trimmed) {
        return Some(DepHygieneFinding::new(
            manifest,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::Medium,
            format!(
                "{scope}: floor-only range; add an upper bound to fix the supply-chain surface"
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

fn is_floating_shard_constraint(constraint: &str) -> bool {
    constraint.is_empty()
        || constraint == "*"
        || constraint.eq_ignore_ascii_case("latest")
        || constraint.eq_ignore_ascii_case("dev")
}
