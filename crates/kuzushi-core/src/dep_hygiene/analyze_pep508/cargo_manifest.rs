use super::*;

pub(in crate::dep_hygiene) fn analyze_cargo_toml(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    let mut out = Vec::new();
    let mut in_deps = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_deps = trimmed == "[dependencies]" || trimmed == "[dev-dependencies]";
            continue;
        }
        if !in_deps || trimmed.is_empty() {
            continue;
        }

        let Some((name, value)) = split_assignment(trimmed) else {
            continue;
        };
        if value.starts_with('{') {
            continue;
        }
        let constraint = clean_quoted_constraint(value);
        if constraint == "*" || constraint.is_empty() {
            out.push(DepHygieneFinding::new(
                ManifestKind::CargoToml,
                file_path,
                name,
                constraint,
                DepHygieneSeverity::High,
                "Cargo: wildcard pin - accepts any future release without review",
            ));
        } else if is_floor_only_number_range(&constraint) {
            out.push(DepHygieneFinding::new(
                ManifestKind::CargoToml,
                file_path,
                name,
                constraint,
                DepHygieneSeverity::Medium,
                "Cargo: floor-only range; declare an upper bound to fix the supply-chain surface",
            ));
        }
    }

    out
}
