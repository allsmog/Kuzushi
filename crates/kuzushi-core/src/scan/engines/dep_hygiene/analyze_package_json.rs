use super::*;

pub(crate) fn analyze_package_json(file_path: &Path, raw: &str) -> Vec<DepHygieneFinding> {
    let Ok(parsed) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for section in ["dependencies", "devDependencies"] {
        let Some(deps) = parsed.get(section).and_then(Value::as_object) else {
            continue;
        };

        for (name, value) in deps {
            let Some(raw_constraint) = value.as_str() else {
                continue;
            };
            let trimmed = raw_constraint.trim();
            if trimmed.is_empty()
                || trimmed == "*"
                || trimmed == "latest"
                || trimmed.ends_with("@latest")
            {
                out.push(DepHygieneFinding::new(
                    ManifestKind::PackageJson,
                    file_path,
                    name,
                    raw_constraint,
                    DepHygieneSeverity::High,
                    format!(
                        "{section}: floating tag - pulls whatever is published next, even a malicious release"
                    ),
                ));
                continue;
            }
            if is_floor_only_number_range(trimmed) {
                out.push(DepHygieneFinding::new(
                    ManifestKind::PackageJson,
                    file_path,
                    name,
                    raw_constraint,
                    DepHygieneSeverity::Medium,
                    format!(
                        "{section}: floor-only range; declare an upper bound to prevent unintended major upgrades"
                    ),
                ));
                continue;
            }
            if trimmed.starts_with("^0.") {
                out.push(DepHygieneFinding::new(
                    ManifestKind::PackageJson,
                    file_path,
                    name,
                    raw_constraint,
                    DepHygieneSeverity::Low,
                    format!(
                        "{section}: caret on 0.x - pre-1.0 packages can break under any release"
                    ),
                ));
            }
        }
    }

    out
}
