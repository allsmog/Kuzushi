use super::*;

const R_DEPENDENCY_FIELDS: &[&str] = &["Depends", "Imports", "Suggests", "LinkingTo"];

pub(in crate::scan::engines::dep_hygiene) fn analyze_r_description(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    parsed_fields(raw)
        .into_iter()
        .filter(|(field, _)| R_DEPENDENCY_FIELDS.contains(&field.as_str()))
        .flat_map(|(field, value)| field_findings(file_path, &field, &value))
        .collect()
}

fn field_findings(file_path: &Path, field: &str, value: &str) -> Vec<DepHygieneFinding> {
    split_r_dependencies(value)
        .into_iter()
        .filter_map(r_dependency)
        .filter_map(|dependency| r_finding(file_path, field, dependency))
        .collect()
}

fn r_finding(
    file_path: &Path,
    field: &str,
    dependency: RDependency<'_>,
) -> Option<DepHygieneFinding> {
    if dependency.name == "R" {
        return None;
    }
    let constraint = dependency.constraint.unwrap_or("");
    let trimmed = constraint.trim();
    if is_floating_r_constraint(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::RDescription,
            file_path,
            dependency.name,
            constraint,
            DepHygieneSeverity::High,
            format!("{field}: floating constraint - accepts any future release without review"),
        ));
    }
    if is_floor_only_number_range(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::RDescription,
            file_path,
            dependency.name,
            constraint,
            DepHygieneSeverity::Medium,
            format!(
                "{field}: floor-only range; add an upper bound to fix the supply-chain surface"
            ),
        ));
    }
    None
}

fn parsed_fields(text: &str) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    for line in text.lines() {
        apply_description_line(&mut fields, line);
    }
    fields
}

fn apply_description_line(fields: &mut Vec<(String, String)>, line: &str) {
    if line.starts_with([' ', '\t']) {
        append_continuation(fields, line);
    } else if let Some((key, value)) = line.split_once(':') {
        fields.push((key.trim().to_string(), value.trim().to_string()));
    }
}

fn append_continuation(fields: &mut [(String, String)], line: &str) {
    if let Some((_, value)) = fields.last_mut() {
        value.push(' ');
        value.push_str(line.trim());
    }
}

fn r_dependency(raw: &str) -> Option<RDependency<'_>> {
    let raw = raw.trim();
    let (name, constraint) = raw
        .split_once('(')
        .map(|(name, rest)| (name.trim(), rest.trim_end_matches(')').trim()))
        .unwrap_or((raw, ""));
    (!name.is_empty()).then_some(RDependency {
        name,
        constraint: (!constraint.is_empty()).then_some(constraint),
    })
}

fn split_r_dependencies(value: &str) -> Vec<&str> {
    let mut dependencies = Vec::new();
    let mut start = 0usize;
    let mut depth = 0u32;
    for (index, ch) in value.char_indices() {
        depth = next_depth(depth, ch);
        if ch == ',' && depth == 0 {
            dependencies.push(value[start..index].trim());
            start = index + ch.len_utf8();
        }
    }
    dependencies.push(value[start..].trim());
    dependencies
}

fn next_depth(depth: u32, ch: char) -> u32 {
    match ch {
        '(' => depth + 1,
        ')' => depth.saturating_sub(1),
        _ => depth,
    }
}

fn is_floating_r_constraint(constraint: &str) -> bool {
    constraint.is_empty()
        || constraint == "*"
        || constraint.eq_ignore_ascii_case("latest")
        || constraint.eq_ignore_ascii_case("dev")
}

struct RDependency<'a> {
    name: &'a str,
    constraint: Option<&'a str>,
}
