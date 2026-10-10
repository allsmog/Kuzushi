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
    files: &[PathBuf],
    cancellation: &ScanCancellation,
) -> Result<Vec<LicenseScanFinding>> {
    let declared = declared_manifest_licenses(target, manifests, cancellation)?;
    if declared.is_empty() {
        return Ok(Vec::new());
    }
    let Some(license_file) = repository_license_file(target, files) else {
        return Ok(vec![missing_license_file_finding(
            target,
            &declared[0].path,
        )]);
    };
    ensure_scan_active(cancellation)?;
    Ok(license_file_mismatch(target, license_file, &declared)?
        .map(|finding| vec![finding])
        .unwrap_or_default())
}

fn declared_manifest_licenses(
    target: &Path,
    manifests: &[PathBuf],
    cancellation: &ScanCancellation,
) -> Result<Vec<DeclaredLicense>> {
    manifests
        .iter()
        .filter_map(|path| declared_manifest_license(target, path, cancellation).transpose())
        .collect()
}

fn declared_manifest_license(
    target: &Path,
    path: &Path,
    cancellation: &ScanCancellation,
) -> Result<Option<DeclaredLicense>> {
    ensure_scan_active(cancellation)?;
    let text = crate::bounded_file::read_utf8_text_within(target, path, MAX_LICENSE_MANIFEST_BYTES)
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

fn repository_license_file<'a>(target: &Path, files: &'a [PathBuf]) -> Option<&'a Path> {
    files
        .iter()
        .find(|path| path.parent() == Some(target) && is_repository_license_file(path))
        .map(PathBuf::as_path)
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
) -> Result<Option<LicenseScanFinding>> {
    let text =
        crate::bounded_file::read_utf8_text_within(target, license_file, MAX_LICENSE_FILE_BYTES)
            .with_context(|| format!("license-scan: read {}", license_file.display()))?;
    let Some(file_kind) = license_text_kind(&text) else {
        return Ok(None);
    };
    Ok(declared.iter().find_map(|item| {
        let manifest_kind = license_text_kind(&item.license)?;
        (manifest_kind != file_kind)
            .then(|| license_file_mismatch_finding(target, license_file, &item.license, file_kind))
    }))
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
