use super::*;

pub(in crate::scan::engines::dep_hygiene) fn analyze_cpanfile(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    raw.lines()
        .filter_map(|line| cpan_requirement(line).and_then(|req| cpan_finding(file_path, req)))
        .collect()
}

fn cpan_finding(file_path: &Path, requirement: CpanRequirement<'_>) -> Option<DepHygieneFinding> {
    let constraint = requirement.version.unwrap_or("");
    let trimmed = constraint.trim();
    if is_floating_cpan_constraint(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::Cpanfile,
            file_path,
            requirement.name,
            constraint,
            DepHygieneSeverity::High,
            format!(
                "{}: floating constraint - accepts any future release without review",
                requirement.scope
            ),
        ));
    }
    if is_floor_only_number_range(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::Cpanfile,
            file_path,
            requirement.name,
            constraint,
            DepHygieneSeverity::Medium,
            format!(
                "{}: floor-only range; add an upper bound to fix the supply-chain surface",
                requirement.scope
            ),
        ));
    }
    None
}

fn cpan_requirement(line: &str) -> Option<CpanRequirement<'_>> {
    let line = line.split('#').next().unwrap_or(line).trim();
    let (scope, rest) = line.split_once(char::is_whitespace)?;
    if !scope.ends_with("requires") {
        return None;
    }
    let (name, rest) = quoted_value(rest)?;
    Some(CpanRequirement {
        scope,
        name,
        version: requirement_version(rest),
    })
}

fn requirement_version(text: &str) -> Option<&str> {
    quoted_value(text.split_once(',')?.1).map(|(version, _)| version)
}

fn quoted_value(text: &str) -> Option<(&str, &str)> {
    let text = text.trim_start();
    let quote = text
        .chars()
        .next()
        .filter(|quote| matches!(quote, '\'' | '"'))?;
    let rest = &text[quote.len_utf8()..];
    let end = rest.find(quote)?;
    Some((&rest[..end], &rest[end + quote.len_utf8()..]))
}

fn is_floating_cpan_constraint(constraint: &str) -> bool {
    constraint.is_empty()
        || constraint == "*"
        || constraint.eq_ignore_ascii_case("latest")
        || constraint.eq_ignore_ascii_case("dev")
}

struct CpanRequirement<'a> {
    scope: &'a str,
    name: &'a str,
    version: Option<&'a str>,
}
