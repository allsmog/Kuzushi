//! Read each bounded manifest once for the policy and source-header consumers.
use super::*;

pub(super) struct InspectedManifest {
    pub(super) path: PathBuf,
    pub(super) license: ManifestLicense,
}

impl InspectedManifest {
    pub(super) fn declared_license(&self) -> Option<&str> {
        match &self.license {
            ManifestLicense::Declared(license) => Some(license),
            ManifestLicense::Skip | ManifestLicense::Missing => None,
        }
    }
}

pub(super) fn inspect_manifests(
    target: &Path,
    files: &[PathBuf],
    cancellation: &ScanCancellation,
) -> Result<Vec<InspectedManifest>> {
    let mut paths = files
        .iter()
        .filter(|path| is_license_manifest(path))
        .collect::<Vec<_>>();
    paths.sort_by_key(|path| relative_display(target, path));
    paths
        .into_iter()
        .map(|path| inspect_manifest(target, path, cancellation))
        .collect()
}

fn inspect_manifest(
    target: &Path,
    path: &Path,
    cancellation: &ScanCancellation,
) -> Result<InspectedManifest> {
    ensure_scan_active(cancellation)?;
    let text = crate::bounded_file::read_utf8_text_within(target, path, MAX_LICENSE_MANIFEST_BYTES)
        .with_context(|| format!("license-scan: read {}", path.display()))?;
    Ok(InspectedManifest {
        path: path.to_path_buf(),
        license: manifest_license(path, &text)?,
    })
}
