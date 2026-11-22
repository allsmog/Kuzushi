use super::*;

pub(in crate::scan::engines::dep_hygiene) fn analyze_pep508(
    file_path: &Path,
    spec: &str,
) -> Option<DepHygieneFinding> {
    analyze_pep508_for_manifest(ManifestKind::PyprojectToml, file_path, spec)
}

pub(in crate::scan::engines::dep_hygiene) fn analyze_pep508_for_manifest(
    manifest: ManifestKind,
    file_path: &Path,
    spec: &str,
) -> Option<DepHygieneFinding> {
    let requirement = Pep508Requirement::read(spec)?;
    let (severity, reason) = hygiene_verdict(requirement.version_specifier)?;
    Some(DepHygieneFinding::new(
        manifest,
        file_path,
        requirement.name,
        requirement.version_specifier,
        severity,
        reason,
    ))
}

/// One PEP 508 requirement read as the two parts the hygiene rules judge:
/// the distribution name and the version specifier that bounds it.
struct Pep508Requirement<'a> {
    name: &'a str,
    version_specifier: &'a str,
}

impl<'a> Pep508Requirement<'a> {
    /// `name[extra,extra] >= 1.0 ; marker` — the extras group selects optional
    /// features of the same distribution and bounds no version, so it is not
    /// part of the specifier. Reading it as one left every `uvicorn[standard]`
    /// looking constrained.
    fn read(spec: &'a str) -> Option<Self> {
        let cleaned = spec.split(';').next().unwrap_or_default().trim();
        let name_len = distribution_name_len(cleaned);
        if name_len == 0 {
            return None;
        }
        let (name, rest) = cleaned.split_at(name_len);
        Some(Self {
            name,
            version_specifier: version_specifier(rest)?,
        })
    }
}

/// The leading run of PEP 508 name characters. Those exclude `[`, so an extras
/// group never reaches the name.
fn distribution_name_len(cleaned: &str) -> usize {
    cleaned
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
        .map(char::len_utf8)
        .sum()
}

/// What follows the name, past an optional extras group. An unterminated `[`
/// names no readable requirement, so it yields no specifier to judge rather
/// than a specifier holding the rest of the line.
fn version_specifier(rest: &str) -> Option<&str> {
    let rest = rest.trim_start();
    match rest.strip_prefix('[') {
        Some(extras) => extras.split_once(']').map(|(_, tail)| tail.trim()),
        None => Some(rest.trim()),
    }
}

fn hygiene_verdict(specifier: &str) -> Option<(DepHygieneSeverity, &'static str)> {
    if specifier.is_empty() {
        return Some((
            DepHygieneSeverity::High,
            "PEP 508: unconstrained - accepts any installed version, including malicious",
        ));
    }
    if is_floor_only_nonempty_range(&compact_constraint(specifier)) {
        return Some((
            DepHygieneSeverity::Medium,
            "PEP 508: floor-only - declare an upper bound for supply-chain hygiene",
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(spec: &str) -> Option<(DepHygieneSeverity, String)> {
        analyze_pep508(Path::new("/repo/pyproject.toml"), spec)
            .map(|finding| (finding.severity, finding.raw_constraint))
    }

    #[test]
    fn an_extras_group_does_not_constrain_the_version() {
        assert_eq!(
            verdict("uvicorn[standard]"),
            Some((DepHygieneSeverity::High, String::new()))
        );
        assert_eq!(
            verdict("celery [redis,auth] >=5.3"),
            Some((DepHygieneSeverity::Medium, ">=5.3".to_string()))
        );
        assert_eq!(verdict("pydantic[email]==2.7.0"), None);
        assert_eq!(verdict("django[argon2]>=4.0,<5.0"), None);
    }

    #[test]
    fn the_reported_package_name_excludes_its_extras() {
        let finding = analyze_pep508(Path::new("/repo/pyproject.toml"), "uvicorn[standard]")
            .expect("an unconstrained requirement is a finding");
        assert_eq!(finding.package_name, "uvicorn");
    }

    #[test]
    fn a_spaced_floor_only_specifier_is_still_floor_only() {
        assert_eq!(
            verdict("requests >= 2.0"),
            Some((DepHygieneSeverity::Medium, ">= 2.0".to_string()))
        );
    }

    #[test]
    fn unreadable_requirements_produce_no_finding() {
        assert_eq!(verdict("uvicorn[standard"), None);
        assert_eq!(verdict("=1.0"), None);
        assert_eq!(verdict(""), None);
    }

    #[test]
    fn an_environment_marker_is_not_read_as_a_specifier() {
        assert_eq!(
            verdict("tomli ; python_version < \"3.11\""),
            Some((DepHygieneSeverity::High, String::new()))
        );
    }

    #[test]
    fn a_direct_reference_is_not_judged_as_a_version_range() {
        assert_eq!(verdict("pkg @ https://example.invalid/pkg.whl"), None);
    }
}
