use super::*;

pub(in crate::scan::engines::dep_hygiene) fn analyze_requirements_txt(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    raw.lines()
        .filter_map(requirement_line)
        .filter_map(|spec| analyze_pep508_for_manifest(ManifestKind::RequirementsTxt, file_path, spec))
        .collect()
}

fn requirement_line(line: &str) -> Option<&str> {
    let spec = line.split('#').next().unwrap_or_default().trim();
    if spec.is_empty() || spec.starts_with('-') || spec.starts_with("--") {
        None
    } else {
        Some(spec)
    }
}
