use super::*;

const SOURCE_EXTENSIONS: &[&str] = &[
    "c", "cc", "cpp", "go", "h", "hpp", "java", "js", "jsx", "kt", "php", "py", "rb", "rs", "ts",
    "tsx",
];

pub(super) fn source_header_findings(
    target: &Path,
    manifests: &[PathBuf],
    cancellation: &ScanCancellation,
    require_source_spdx_headers: bool,
) -> Result<Vec<LicenseScanFinding>> {
    let declared = declared_license_kind(manifests)?;
    if declared.is_none() && !require_source_spdx_headers {
        return Ok(Vec::new());
    }
    let mut findings = Vec::new();
    collect_spdx_header_findings(
        target,
        target,
        declared.as_deref(),
        require_source_spdx_headers,
        &mut findings,
        cancellation,
    )?;
    findings.sort_by_key(|finding| finding.file_path.clone());
    Ok(findings)
}

fn declared_license_kind(manifests: &[PathBuf]) -> Result<Option<String>> {
    for path in manifests {
        let text = crate::bounded_file::read_utf8_text(path, MAX_LICENSE_MANIFEST_BYTES)
            .with_context(|| format!("license-scan: read {}", path.display()))?;
        if let ManifestLicense::Declared(license) = manifest_license(path, &text)? {
            return Ok(Some(normalize_license_id(&license)));
        }
    }
    Ok(None)
}

fn collect_spdx_header_findings(
    target: &Path,
    dir: &Path,
    declared: Option<&str>,
    require_source_spdx_headers: bool,
    findings: &mut Vec<LicenseScanFinding>,
    cancellation: &ScanCancellation,
) -> Result<()> {
    if cancellation.is_cancelled() {
        anyhow::bail!("license-scan scan cancelled");
    }
    for entry in
        fs::read_dir(dir).with_context(|| format!("license-scan: read {}", dir.display()))?
    {
        let path = entry?.path();
        inspect_path(
            target,
            &path,
            declared,
            require_source_spdx_headers,
            findings,
            cancellation,
        )?;
    }
    Ok(())
}

fn inspect_path(
    target: &Path,
    path: &Path,
    declared: Option<&str>,
    require_source_spdx_headers: bool,
    findings: &mut Vec<LicenseScanFinding>,
    cancellation: &ScanCancellation,
) -> Result<()> {
    let file_type = fs::symlink_metadata(path)?.file_type();
    if file_type.is_dir() && !ignored_dir(path) {
        return collect_spdx_header_findings(
            target,
            path,
            declared,
            require_source_spdx_headers,
            findings,
            cancellation,
        );
    }
    if !file_type.is_file() || !is_source_file(path) {
        return Ok(());
    }
    inspect_source_path(
        target,
        path,
        declared,
        require_source_spdx_headers,
        findings,
    )
}

fn inspect_source_path(
    target: &Path,
    path: &Path,
    declared: Option<&str>,
    require_source_spdx_headers: bool,
    findings: &mut Vec<LicenseScanFinding>,
) -> Result<()> {
    match source_spdx_license(path)? {
        Some(header)
            if declared.is_some_and(|license| normalize_license_id(&header) != license) =>
        {
            findings.push(spdx_header_mismatch_finding(
                target,
                path,
                declared.unwrap_or_default(),
                &header,
            ));
        }
        Some(_) => {}
        None if require_source_spdx_headers => {
            findings.push(missing_spdx_header_finding(target, path));
        }
        None => {}
    }
    Ok(())
}

fn source_spdx_license(path: &Path) -> Result<Option<String>> {
    let text = crate::bounded_file::read_utf8_text_prefix(path, MAX_SOURCE_HEADER_BYTES)
        .with_context(|| format!("license-scan: read {}", path.display()))?;
    Ok(text.text.lines().take(20).find_map(spdx_license_from_line))
}

fn is_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_ascii_lowercase())
        .is_some_and(|extension| SOURCE_EXTENSIONS.contains(&extension.as_str()))
}

fn spdx_license_from_line(line: &str) -> Option<String> {
    line.split_once("SPDX-License-Identifier:")
        .map(|(_, value)| value.trim().trim_matches('*').trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalize_license_id(value: &str) -> String {
    value
        .trim()
        .trim_matches(['(', ')'])
        .to_ascii_lowercase()
        .replace('_', "-")
}

fn missing_spdx_header_finding(target: &Path, path: &Path) -> LicenseScanFinding {
    LicenseScanFinding::new(
        target,
        path,
        "license-scan/missing-spdx-header",
        Severity::Low,
        "Source file is missing an SPDX license header",
        "no SPDX-License-Identifier header in first 20 lines",
        None,
    )
}

fn spdx_header_mismatch_finding(
    target: &Path,
    path: &Path,
    declared: &str,
    header: &str,
) -> LicenseScanFinding {
    LicenseScanFinding::new(
        target,
        path,
        "license-scan/spdx-header-mismatch",
        Severity::Low,
        "Source SPDX license header does not match package manifest license",
        format!("manifest license = {declared}; source SPDX = {header}"),
        Some(header.to_string()),
    )
}
