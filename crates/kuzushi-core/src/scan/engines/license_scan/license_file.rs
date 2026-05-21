use super::*;

const LICENSE_FILES: &[&str] = &[
    "license",
    "license.md",
    "license.txt",
    "copying",
    "copying.md",
    "copying.txt",
    "unlicense",
];

const LICENSE_KINDS: &[(&str, &str)] = &[
    ("apache", "apache"),
    ("agpl", "agpl"),
    ("lgpl", "lgpl"),
    ("gpl", "gpl"),
    ("mit", "mit"),
    ("bsd", "bsd"),
    ("mpl", "mpl"),
    ("isc", "isc"),
    ("unlicense", "unlicense"),
];

pub(super) fn repository_license_findings(
    target: &Path,
    manifests: &[PathBuf],
) -> Result<Vec<LicenseScanFinding>> {
    let declared = declared_manifest_licenses(manifests)?;
    if declared.is_empty() {
        return Ok(Vec::new());
    }
    let Some(license_file) = repository_license_file(target)? else {
        return Ok(vec![missing_license_file_finding(target, &declared[0].path)]);
    };
    Ok(license_file_mismatch(target, &license_file, &declared)
        .map(|finding| vec![finding])
        .unwrap_or_default())
}

fn declared_manifest_licenses(manifests: &[PathBuf]) -> Result<Vec<DeclaredLicense>> {
    manifests
        .iter()
        .filter_map(|path| declared_manifest_license(path).transpose())
        .collect()
}

fn declared_manifest_license(path: &Path) -> Result<Option<DeclaredLicense>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("license-scan: read {}", path.display()))?;
    match manifest_license(path, &text)? {
        ManifestLicense::Declared(license) => Ok(Some(DeclaredLicense {
            path: path.to_path_buf(),
            license,
        })),
        ManifestLicense::Skip | ManifestLicense::Missing => Ok(None),
    }
}

struct DeclaredLicense {
    path: PathBuf,
    license: String,
}

fn repository_license_file(target: &Path) -> Result<Option<PathBuf>> {
    for entry in
        fs::read_dir(target).with_context(|| format!("license-scan: read {}", target.display()))?
    {
        let path = entry?.path();
        if is_repository_license_file(&path) {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn is_repository_license_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_ascii_lowercase())
        .is_some_and(|name| LICENSE_FILES.contains(&name.as_str()))
}

fn license_file_mismatch(
    target: &Path,
    license_file: &Path,
    declared: &[DeclaredLicense],
) -> Option<LicenseScanFinding> {
    let file_kind = license_text_kind(&fs::read_to_string(license_file).ok()?)?;
    declared.iter().find_map(|item| {
        let manifest_kind = license_text_kind(&item.license)?;
        (manifest_kind != file_kind)
            .then(|| license_file_mismatch_finding(target, license_file, &item.license, file_kind))
    })
}

fn license_text_kind(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    LICENSE_KINDS
        .iter()
        .find_map(|(needle, kind)| lower.contains(needle).then_some(*kind))
}

fn missing_license_file_finding(target: &Path, path: &Path) -> LicenseScanFinding {
    LicenseScanFinding::new(
        target,
        path,
        "license-scan/missing-license-file",
        Severity::Low,
        "Public package manifests declare licenses but no repository license file was found",
        "top-level LICENSE/COPYING file missing",
        None,
    )
}

fn license_file_mismatch_finding(
    target: &Path,
    license_file: &Path,
    license: &str,
    file_kind: &str,
) -> LicenseScanFinding {
    LicenseScanFinding::new(
        target,
        license_file,
        "license-scan/license-file-mismatch",
        Severity::Low,
        "Manifest license declaration does not match the repository license file",
        format!("manifest license = {license}; license file appears to be {file_kind}"),
        Some(license.to_string()),
    )
}
