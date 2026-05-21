use super::*;

pub(in crate::scan::engines::dep_hygiene) fn analyze_conanfile_txt(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    let mut in_requires = false;
    raw.lines()
        .filter_map(|line| requirement_from_line(line, &mut in_requires))
        .filter_map(|requirement| conan_finding(file_path, requirement))
        .collect()
}

struct ConanRequirement {
    name: String,
    version: String,
}

fn requirement_from_line(line: &str, in_requires: &mut bool) -> Option<ConanRequirement> {
    let line = strip_comment(line).trim();
    if line.is_empty() {
        return None;
    }
    if let Some(section) = section_name(line) {
        *in_requires = section == "requires";
        return None;
    }
    (*in_requires).then(|| parse_requirement(line)).flatten()
}

fn parse_requirement(line: &str) -> Option<ConanRequirement> {
    let reference = line.split_whitespace().next()?;
    let (name, rest) = reference.split_once('/')?;
    let version = rest.split(['@', '#']).next()?.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some(ConanRequirement {
        name: name.to_string(),
        version: version.to_string(),
    })
}

fn conan_finding(
    file_path: &Path,
    requirement: ConanRequirement,
) -> Option<DepHygieneFinding> {
    if is_floating_conan_version(&requirement.version) {
        return Some(DepHygieneFinding::new(
            ManifestKind::ConanfileTxt,
            file_path,
            requirement.name,
            requirement.version,
            DepHygieneSeverity::High,
            "conanfile.txt: floating version - accepts any future package release without review",
        ));
    }
    if is_open_ended_conan_range(&requirement.version) {
        return Some(DepHygieneFinding::new(
            ManifestKind::ConanfileTxt,
            file_path,
            requirement.name,
            requirement.version,
            DepHygieneSeverity::Medium,
            "conanfile.txt: open-ended range; add an upper bound to fix the supply-chain surface",
        ));
    }
    None
}

fn strip_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or(line)
}

fn section_name(line: &str) -> Option<&str> {
    line.strip_prefix('[')?.strip_suffix(']')
}

fn is_floating_conan_version(version: &str) -> bool {
    version == "*"
        || version.ends_with(".*")
        || version.eq_ignore_ascii_case("latest")
        || version.eq_ignore_ascii_case("dev-latest")
}

fn is_open_ended_conan_range(version: &str) -> bool {
    let Some(range) = version.strip_prefix('[').and_then(|value| value.strip_suffix(']')) else {
        return false;
    };
    range.contains(">=") && !range.contains('<')
}
