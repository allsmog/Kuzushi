use super::*;

pub(in crate::scan::engines::dep_hygiene) fn analyze_mix_exs(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    raw.lines()
        .filter_map(|line| mix_dependency(line).and_then(|dep| mix_finding(file_path, dep)))
        .collect()
}

fn mix_finding(file_path: &Path, dependency: MixDependency) -> Option<DepHygieneFinding> {
    let trimmed = dependency.constraint.trim();
    if is_floating_mix_constraint(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::MixExs,
            file_path,
            dependency.name,
            dependency.constraint,
            DepHygieneSeverity::High,
            "deps: floating constraint - accepts any future release without review",
        ));
    }
    if is_floor_only_number_range(trimmed) {
        return Some(DepHygieneFinding::new(
            ManifestKind::MixExs,
            file_path,
            dependency.name,
            dependency.constraint,
            DepHygieneSeverity::Medium,
            "deps: floor-only range; add an upper bound to fix the supply-chain surface",
        ));
    }
    None
}

fn mix_dependency(line: &str) -> Option<MixDependency> {
    let trimmed = line.trim();
    let name = atom_after(trimmed, "{:")?;
    let constraint = quoted_values(trimmed).next()?;
    Some(MixDependency { name, constraint })
}

fn atom_after(line: &str, marker: &str) -> Option<String> {
    line.split_once(marker)
        .and_then(|(_, tail)| atom_name(tail))
}

fn atom_name(value: &str) -> Option<String> {
    let name = value
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .collect::<String>();
    (!name.is_empty()).then_some(name)
}

fn quoted_values(line: &str) -> impl Iterator<Item = String> + '_ {
    line.split('"')
        .skip(1)
        .step_by(2)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn is_floating_mix_constraint(constraint: &str) -> bool {
    constraint.is_empty()
        || constraint == "*"
        || constraint.eq_ignore_ascii_case("latest")
        || constraint.eq_ignore_ascii_case("dev")
}

struct MixDependency {
    name: String,
    constraint: String,
}
