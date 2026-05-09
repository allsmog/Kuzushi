use super::*;

pub(crate) fn textual_cvss_severity(value: &str) -> Severity {
    let upper = value.to_ascii_uppercase();
    if upper.contains("CRITICAL") {
        Severity::Critical
    // CVSS v3 vector form encodes impact metrics as /C:H/I:H/A:H. Any
    // high-impact letter on confidentiality, integrity, or availability is
    // a High signal — close enough for triage without a full CVSS parser.
    } else if contains_any(&upper, &["HIGH", "C:H", "I:H", "A:H"]) {
        Severity::High
    } else if upper.contains("MEDIUM") {
        Severity::Medium
    } else if contains_any(&upper, &["LOW", "C:L", "I:L", "A:L"]) {
        Severity::Low
    } else {
        Severity::Medium
    }
}

pub(crate) fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    PackageJson,
    PyprojectToml,
    CargoToml,
    GoMod,
}

impl ManifestKind {
    pub(crate) fn file_name(self) -> &'static str {
        match self {
            Self::PackageJson => "package.json",
            Self::PyprojectToml => "pyproject.toml",
            Self::CargoToml => "Cargo.toml",
            Self::GoMod => "go.mod",
        }
    }
}

pub(crate) const TARGET_MANIFESTS: [ManifestKind; 4] = [
    ManifestKind::PackageJson,
    ManifestKind::PyprojectToml,
    ManifestKind::CargoToml,
    ManifestKind::GoMod,
];

pub fn check_dependency_hygiene(target: &Path) -> Result<DepHygieneReport> {
    let target = canonical_directory(target)?;
    let mut findings = Vec::new();

    for manifest in TARGET_MANIFESTS {
        let manifest_path = target.join(manifest.file_name());
        if !manifest_path.exists() {
            continue;
        }
        let raw = fs::read_to_string(&manifest_path)
            .with_context(|| format!("dep-hygiene: failed to read {}", manifest_path.display()))?;
        findings.extend(analyze_manifest(manifest, &manifest_path, &raw));
    }

    Ok(DepHygieneReport {
        target: target.display().to_string(),
        count: findings.len(),
        findings,
    })
}

pub fn analyze_manifest(
    manifest: ManifestKind,
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    match manifest {
        ManifestKind::PackageJson => analyze_package_json(file_path, raw),
        ManifestKind::PyprojectToml => analyze_pyproject_toml(file_path, raw),
        ManifestKind::CargoToml => analyze_cargo_toml(file_path, raw),
        ManifestKind::GoMod => analyze_go_mod(file_path, raw),
    }
}
