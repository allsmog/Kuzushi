use super::*;

pub(in crate::scan::engines::dep_hygiene) fn analyze_nimble_file(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    raw.lines()
        .filter_map(requires_args)
        .flat_map(quoted_values)
        .filter_map(|value| nimble_dependency(&value).and_then(|dep| nimble_finding(file_path, dep)))
        .collect()
}

fn nimble_finding(
    file_path: &Path,
    dependency: NimbleDependency<'_>,
) -> Option<DepHygieneFinding> {
    let constraint = dependency.constraint.unwrap_or("");
    let trimmed = constraint.trim();
    if is_floating_nimble_constraint(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::NimbleFile,
            file_path,
            dependency.name,
            constraint,
            DepHygieneSeverity::High,
            "requires: floating constraint - accepts any future release without review",
        ));
    }
    if is_floor_only_number_range(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::NimbleFile,
            file_path,
            dependency.name,
            constraint,
            DepHygieneSeverity::Medium,
            "requires: floor-only range; add an upper bound to fix the supply-chain surface",
        ));
    }
    None
}

fn requires_args(line: &str) -> Option<&str> {
    let line = line.split('#').next().unwrap_or(line).trim();
    line.strip_prefix("requires")
}

fn quoted_values(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut rest = text;
    while let Some((value, remaining)) = quoted_value(rest) {
        values.push(value.to_string());
        rest = remaining;
    }
    values
}

fn quoted_value(text: &str) -> Option<(&str, &str)> {
    let quote_start = text.find('"')?;
    let rest = &text[quote_start + 1..];
    let quote_end = rest.find('"')?;
    Some((&rest[..quote_end], &rest[quote_end + 1..]))
}

fn nimble_dependency(value: &str) -> Option<NimbleDependency<'_>> {
    let value = value.trim();
    let name = value
        .split([' ', '<', '>', '=', '~', '^'])
        .next()
        .unwrap_or_default()
        .trim();
    if name.is_empty() {
        return None;
    }
    let constraint = value.strip_prefix(name).map(str::trim).filter(|rest| !rest.is_empty());
    Some(NimbleDependency { name, constraint })
}

fn is_floating_nimble_constraint(constraint: &str) -> bool {
    constraint.is_empty()
        || constraint == "*"
        || constraint.eq_ignore_ascii_case("latest")
        || constraint.eq_ignore_ascii_case("dev")
}

struct NimbleDependency<'a> {
    name: &'a str,
    constraint: Option<&'a str>,
}
