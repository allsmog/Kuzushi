use super::*;
use serde_json::Value as YamlValue;

pub(in crate::scan::engines::dep_hygiene) fn analyze_conda_environment(
    file_path: &Path,
    raw: &str,
    manifest: ManifestKind,
) -> Vec<DepHygieneFinding> {
    let Ok(value) = crate::yaml::parse_value(raw) else {
        return Vec::new();
    };
    dependencies(&value)
        .flat_map(|dependency| conda_dependency_findings(file_path, manifest, dependency))
        .collect()
}

fn conda_dependency_findings(
    file_path: &Path,
    manifest: ManifestKind,
    dependency: &YamlValue,
) -> Vec<DepHygieneFinding> {
    if let Some(raw) = dependency.as_str() {
        return conda_finding(file_path, manifest, raw)
            .into_iter()
            .collect();
    }
    pip_dependencies(dependency)
        .into_iter()
        .flatten()
        .filter_map(YamlValue::as_str)
        .filter_map(|raw| pip_finding(file_path, manifest, raw))
        .collect()
}

fn conda_finding(file_path: &Path, manifest: ManifestKind, raw: &str) -> Option<DepHygieneFinding> {
    let dependency = conda_dependency(raw)?;
    dependency_finding(file_path, manifest, "dependencies", dependency)
}

fn pip_finding(file_path: &Path, manifest: ManifestKind, raw: &str) -> Option<DepHygieneFinding> {
    let dependency = pip_dependency(raw)?;
    dependency_finding(file_path, manifest, "dependencies.pip", dependency)
}

fn dependency_finding(
    file_path: &Path,
    manifest: ManifestKind,
    section: &str,
    dependency: DependencySpec<'_>,
) -> Option<DepHygieneFinding> {
    if is_floating_dependency(dependency.constraint) {
        return Some(DepHygieneFinding::new(
            manifest,
            file_path,
            dependency.name,
            dependency.constraint,
            DepHygieneSeverity::High,
            format!("{section}: floating constraint - accepts any future release without review"),
        ));
    }
    if is_floor_only_number_range(dependency.constraint) {
        return Some(DepHygieneFinding::new(
            manifest,
            file_path,
            dependency.name,
            dependency.constraint,
            DepHygieneSeverity::Medium,
            format!(
                "{section}: floor-only range; add an upper bound to fix the supply-chain surface"
            ),
        ));
    }
    None
}

fn conda_dependency(raw: &str) -> Option<DependencySpec<'_>> {
    let raw = raw.trim();
    let name = raw
        .split(['=', '<', '>', ' '])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())?;
    Some(DependencySpec {
        name,
        constraint: raw.strip_prefix(name).unwrap_or("").trim(),
    })
}

fn pip_dependency(raw: &str) -> Option<DependencySpec<'_>> {
    let raw = raw.trim();
    let name_end = raw
        .find(['=', '<', '>', '!', '~', '[', ';'])
        .unwrap_or(raw.len());
    let name = raw[..name_end].trim();
    (!name.is_empty()).then_some(DependencySpec {
        name,
        constraint: raw[name_end..].trim(),
    })
}

fn dependencies(value: &YamlValue) -> impl Iterator<Item = &YamlValue> {
    sequence_child(value, "dependencies").into_iter().flatten()
}

fn pip_dependencies(value: &YamlValue) -> Option<&Vec<YamlValue>> {
    sequence_child(value, "pip")
}

fn sequence_child<'a>(value: &'a YamlValue, key: &str) -> Option<&'a Vec<YamlValue>> {
    value.as_object()?.get(key)?.as_array()
}

fn is_floating_dependency(constraint: &str) -> bool {
    constraint.is_empty()
        || constraint == "*"
        || constraint.eq_ignore_ascii_case("latest")
        || constraint.eq_ignore_ascii_case("dev")
}

struct DependencySpec<'a> {
    name: &'a str,
    constraint: &'a str,
}
