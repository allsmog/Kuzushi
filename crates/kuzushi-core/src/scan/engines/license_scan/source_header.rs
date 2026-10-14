use super::*;

const SOURCE_EXTENSIONS: &[&str] = &[
    "c", "cc", "cpp", "go", "h", "hpp", "java", "js", "jsx", "kt", "php", "py", "rb", "rs", "ts",
    "tsx",
];

pub(super) fn source_header_findings(
    target: &Path,
    manifests: &[PathBuf],
    files: &[PathBuf],
    cancellation: &ScanCancellation,
    require_source_spdx_headers: bool,
) -> Result<Vec<LicenseScanFinding>> {
    let declared = declared_license_kind(target, manifests, cancellation)?;
    if declared.is_none() && !require_source_spdx_headers {
        return Ok(Vec::new());
    }
    let mut findings = Vec::new();
    for path in files.iter().filter(|path| is_source_file(path)) {
        ensure_scan_active(cancellation)?;
        inspect_source_path(
            target,
            path,
            declared.as_deref(),
            require_source_spdx_headers,
            &mut findings,
        )?;
    }
    findings.sort_by_key(|finding| finding.file_path.clone());
    Ok(findings)
}

fn declared_license_kind(
    target: &Path,
    manifests: &[PathBuf],
    cancellation: &ScanCancellation,
) -> Result<Option<String>> {
    for path in manifests {
        ensure_scan_active(cancellation)?;
        let text =
            crate::bounded_file::read_utf8_text_within(target, path, MAX_LICENSE_MANIFEST_BYTES)
                .with_context(|| format!("license-scan: read {}", path.display()))?;
        if let ManifestLicense::Declared(license) = manifest_license(path, &text)? {
            return Ok(Some(normalize_license_id(&license)));
        }
    }
    Ok(None)
}

fn inspect_source_path(
    target: &Path,
    path: &Path,
    declared: Option<&str>,
    require_source_spdx_headers: bool,
    findings: &mut Vec<LicenseScanFinding>,
) -> Result<()> {
    match source_spdx_license(target, path)? {
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

fn source_spdx_license(target: &Path, path: &Path) -> Result<Option<String>> {
    let text =
        crate::bounded_file::read_utf8_text_prefix_within(target, path, MAX_SOURCE_HEADER_BYTES)
            .with_context(|| format!("license-scan: read {}", path.display()))?;
    inspected_header(&text.text, text.truncated)
}

fn inspected_header(text: &str, truncated: bool) -> Result<Option<String>> {
    let text = complete_header_text(text, truncated);
    let lines = text.lines().take(20).collect::<Vec<_>>();
    let header = lines.iter().find_map(|line| spdx_license_from_line(line));
    if header.is_some() {
        return Ok(header);
    }
    anyhow::ensure!(!truncated || lines.len() >= 20,
        "license-scan: source header exceeds the {MAX_SOURCE_HEADER_BYTES}-byte inspection limit before 20 complete lines; header absence is unverified");
    Ok(None)
}

fn complete_header_text(text: &str, truncated: bool) -> &str {
    if !truncated || text.ends_with('\n') {
        return text;
    }
    text.rsplit_once('\n')
        .map(|(complete, _)| complete)
        .unwrap_or_default()
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

#[cfg(test)]
mod inspection_tests {
    use super::*;

    #[test]
    fn truncated_lines_cannot_establish_header_absence_or_an_incomplete_identifier() {
        assert!(inspected_header("// SPDX-License-Identifier: MI", true).is_err());
        assert!(
            inspected_header("// first complete line\n// uninspected remainder", true).is_err()
        );
    }

    #[test]
    fn a_complete_header_remains_usable_before_an_uninspected_remainder() {
        assert_eq!(
            inspected_header("// SPDX-License-Identifier: MIT\n// incomplete", true).unwrap(),
            Some("MIT".into())
        );
        assert_eq!(
            inspected_header("// complete with no header", false).unwrap(),
            None
        );
        assert_eq!(
            inspected_header(&("// complete\n".repeat(20) + "// incomplete"), true).unwrap(),
            None
        );
    }
}
