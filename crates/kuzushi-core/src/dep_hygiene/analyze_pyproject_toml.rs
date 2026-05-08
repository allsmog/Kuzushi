use super::*;

pub(crate) fn analyze_pyproject_toml(file_path: &Path, raw: &str) -> Vec<DepHygieneFinding> {
    let mut out = Vec::new();
    let mut in_deps = false;
    let mut in_poetry_deps = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_deps = trimmed == "[project]" || trimmed == "[project.optional-dependencies]";
            in_poetry_deps = trimmed == "[tool.poetry.dependencies]"
                || trimmed == "[tool.poetry.dev-dependencies]";
            continue;
        }

        if in_deps {
            if let Some(spec) = quoted_list_entry(trimmed) {
                if let Some(finding) = analyze_pep508(file_path, spec) {
                    out.push(finding);
                }
            }
        }

        if in_poetry_deps {
            let Some((name, value)) = split_assignment(trimmed) else {
                continue;
            };
            if value.starts_with('{') {
                continue;
            }
            let constraint = clean_quoted_constraint(value);
            if constraint == "*"
                || constraint.is_empty()
                || constraint.eq_ignore_ascii_case("latest")
            {
                out.push(DepHygieneFinding::new(
                    ManifestKind::PyprojectToml,
                    file_path,
                    name,
                    constraint,
                    DepHygieneSeverity::High,
                    "poetry: wildcard pin - accepts any future release without review",
                ));
            } else if is_floor_only_number_range(&constraint) {
                out.push(DepHygieneFinding::new(
                    ManifestKind::PyprojectToml,
                    file_path,
                    name,
                    constraint,
                    DepHygieneSeverity::Medium,
                    "poetry: floor-only range; add an upper bound to fix the supply-chain surface",
                ));
            }
        }
    }

    out
}
