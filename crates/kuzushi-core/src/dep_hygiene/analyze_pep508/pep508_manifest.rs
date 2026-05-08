use super::*;

pub(in crate::dep_hygiene) fn analyze_pep508(
    file_path: &Path,
    spec: &str,
) -> Option<DepHygieneFinding> {
    let cleaned = spec.split(';').next().unwrap_or_default().trim();
    let name_len = cleaned
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
        .map(char::len_utf8)
        .sum::<usize>();
    if name_len == 0 {
        return None;
    }
    let name = &cleaned[..name_len];
    let constraint = cleaned[name_len..].trim();

    if constraint.is_empty() {
        return Some(DepHygieneFinding::new(
            ManifestKind::PyprojectToml,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::High,
            "PEP 508: unconstrained - accepts any installed version, including malicious",
        ));
    }

    if is_floor_only_nonempty_range(constraint) {
        return Some(DepHygieneFinding::new(
            ManifestKind::PyprojectToml,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::Medium,
            "PEP 508: floor-only - declare an upper bound for supply-chain hygiene",
        ));
    }

    None
}
