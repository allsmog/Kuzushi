use super::*;

pub(in crate::scan::engines::dep_hygiene) fn analyze_opam_file(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    raw.lines()
        .scan(false, opam_depends_line)
        .flatten()
        .filter_map(|dependency| opam_finding(file_path, dependency))
        .collect()
}

fn opam_finding(file_path: &Path, dependency: OpamDependency<'_>) -> Option<DepHygieneFinding> {
    let constraint = dependency.constraint.unwrap_or("");
    let trimmed = constraint.trim();
    if is_floating_opam_constraint(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::OpamFile,
            file_path,
            dependency.name,
            constraint,
            DepHygieneSeverity::High,
            "depends: floating constraint - accepts any future release without review",
        ));
    }
    if is_floor_only_opam_constraint(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::OpamFile,
            file_path,
            dependency.name,
            constraint,
            DepHygieneSeverity::Medium,
            "depends: floor-only range; add an upper bound to fix the supply-chain surface",
        ));
    }
    None
}

fn opam_depends_line<'a>(in_depends: &mut bool, line: &'a str) -> Option<Vec<OpamDependency<'a>>> {
    let line = line.split('#').next().unwrap_or(line).trim();
    if !*in_depends {
        *in_depends = line.starts_with("depends:");
    }
    if !*in_depends {
        return Some(Vec::new());
    }
    let dependencies = first_quoted_name(line)
        .map(|(name, rest)| OpamDependency {
            name,
            constraint: opam_constraint(rest),
        })
        .into_iter()
        .collect();
    if line.contains(']') {
        *in_depends = false;
    }
    Some(dependencies)
}

fn first_quoted_name(text: &str) -> Option<(&str, &str)> {
    let (_, rest) = text.split_once('"')?;
    let (name, rest) = rest.split_once('"')?;
    Some((name, rest))
}

fn opam_constraint(text: &str) -> Option<&str> {
    let (_, rest) = text.split_once('{')?;
    let (constraint, _) = rest.split_once('}')?;
    Some(constraint.trim())
}

fn is_floating_opam_constraint(constraint: &str) -> bool {
    constraint.is_empty()
        || constraint == "*"
        || !contains_version_operator(constraint)
        || constraint.eq_ignore_ascii_case("latest")
        || constraint.eq_ignore_ascii_case("dev")
}

fn contains_version_operator(constraint: &str) -> bool {
    constraint.contains(['=', '<', '>'])
}

fn is_floor_only_opam_constraint(constraint: &str) -> bool {
    constraint.contains(">=") && !constraint.contains('<')
}

struct OpamDependency<'a> {
    name: &'a str,
    constraint: Option<&'a str>,
}
