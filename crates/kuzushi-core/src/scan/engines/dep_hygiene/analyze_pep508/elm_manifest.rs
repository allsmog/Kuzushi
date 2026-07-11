use super::*;

pub(in crate::scan::engines::dep_hygiene) fn analyze_elm_json(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    elm_dependency_scopes(&value)
        .into_iter()
        .flat_map(|(scope, dependencies)| section_findings(file_path, scope, dependencies))
        .collect()
}

fn section_findings(
    file_path: &Path,
    scope: &str,
    dependencies: &serde_json::Map<String, Value>,
) -> Vec<DepHygieneFinding> {
    dependencies
        .iter()
        .filter_map(|(name, value)| elm_finding(file_path, scope, name, value.as_str()?))
        .collect()
}

fn elm_finding(
    file_path: &Path,
    scope: &str,
    name: &str,
    constraint: &str,
) -> Option<DepHygieneFinding> {
    let trimmed = constraint.trim();
    if is_floating_elm_constraint(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::ElmJson,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::High,
            format!("{scope}: floating constraint - accepts any future release without review"),
        ));
    }
    if is_floor_only_number_range(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::ElmJson,
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

fn elm_dependency_scopes(value: &Value) -> Vec<(&'static str, &serde_json::Map<String, Value>)> {
    let mut scopes = Vec::new();
    collect_nested_scope(&mut scopes, value, "dependencies", "dependencies");
    collect_nested_scope(&mut scopes, value, "test-dependencies", "test-dependencies");
    scopes
}

fn collect_nested_scope<'a>(
    scopes: &mut Vec<(&'static str, &'a serde_json::Map<String, Value>)>,
    value: &'a Value,
    key: &'static str,
    scope: &'static str,
) {
    let Some(dependencies) = value.get(key).and_then(Value::as_object) else {
        return;
    };
    match (
        dependencies.get("direct").and_then(Value::as_object),
        dependencies.get("indirect").and_then(Value::as_object),
    ) {
        (Some(direct), indirect) => {
            scopes.push((concat_scope(scope, "direct"), direct));
            if let Some(indirect) = indirect {
                scopes.push((concat_scope(scope, "indirect"), indirect));
            }
        }
        _ => scopes.push((scope, dependencies)),
    }
}

fn concat_scope(scope: &'static str, kind: &'static str) -> &'static str {
    match (scope, kind) {
        ("dependencies", "direct") => "dependencies.direct",
        ("dependencies", "indirect") => "dependencies.indirect",
        ("test-dependencies", "direct") => "test-dependencies.direct",
        ("test-dependencies", "indirect") => "test-dependencies.indirect",
        _ => scope,
    }
}

fn is_floating_elm_constraint(constraint: &str) -> bool {
    constraint.is_empty()
        || constraint == "*"
        || constraint.eq_ignore_ascii_case("latest")
        || constraint.eq_ignore_ascii_case("dev")
}
