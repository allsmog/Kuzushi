use super::*;
use std::collections::BTreeMap;

type LicenseBoundaries<'a> = BTreeMap<PathBuf, Vec<&'a str>>;

const SOURCE_EXTENSIONS: &[&str] = &[
    "c", "cc", "cpp", "go", "h", "hpp", "java", "js", "jsx", "kt", "php", "py", "rb", "rs", "ts",
    "tsx",
];

pub(super) fn source_header_findings(
    target: &Path,
    manifests: &[InspectedManifest],
    files: &[PathBuf],
    cancellation: &ScanCancellation,
    require_source_spdx_headers: bool,
) -> Result<Vec<LicenseScanFinding>> {
    let boundaries = manifest_boundaries(manifests, cancellation)?;
    let mut findings = Vec::new();
    for path in files.iter().filter(|path| is_source_file(path)) {
        ensure_scan_active(cancellation)?;
        let declared = licenses_for_source(path, &boundaries);
        if !header_check_applies(declared, require_source_spdx_headers) {
            continue;
        }
        inspect_source_path(
            target,
            path,
            declared,
            require_source_spdx_headers,
            &mut findings,
        )?;
    }
    findings.sort_by_key(|finding| finding.file_path.clone());
    Ok(findings)
}

fn manifest_boundaries<'a>(
    manifests: &'a [InspectedManifest],
    cancellation: &ScanCancellation,
) -> Result<LicenseBoundaries<'a>> {
    let mut boundaries = BTreeMap::new();
    for manifest in manifests {
        ensure_scan_active(cancellation)?;
        record_boundary(&mut boundaries, manifest);
    }
    Ok(boundaries)
}

fn record_boundary<'a>(boundaries: &mut LicenseBoundaries<'a>, manifest: &'a InspectedManifest) {
    let Some(directory) = manifest.path.parent() else {
        return;
    };
    // Even an unknown or private package defines a local boundary. It does not
    // authorize borrowing another package's declaration.
    let declared = boundaries.entry(directory.to_path_buf()).or_default();
    if let Some(license) = manifest.declared_license() {
        declared.push(license);
    }
}

fn licenses_for_source<'a>(source: &Path, boundaries: &'a LicenseBoundaries<'a>) -> &'a [&'a str] {
    source
        .ancestors()
        .skip(1)
        .find_map(|directory| boundaries.get(directory))
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn header_check_applies(declared: &[&str], require_headers: bool) -> bool {
    require_headers || !declared.is_empty()
}

fn inspect_source_path(
    target: &Path,
    path: &Path,
    declared: &[&str],
    require_source_spdx_headers: bool,
    findings: &mut Vec<LicenseScanFinding>,
) -> Result<()> {
    match source_spdx_license(target, path)? {
        Some(header) => findings.extend(header_mismatch_finding(target, path, declared, &header)),
        None if require_source_spdx_headers => {
            findings.push(missing_spdx_header_finding(target, path));
        }
        None => {}
    }
    Ok(())
}

fn header_mismatch_finding(
    target: &Path,
    path: &Path,
    declared: &[&str],
    header: &str,
) -> Option<LicenseScanFinding> {
    let license = mismatched_declaration(declared, header)?;
    Some(spdx_header_mismatch_finding(
        target,
        path,
        &normalize_license_id(license),
        header,
    ))
}

fn mismatched_declaration<'a>(declared: &[&'a str], header: &str) -> Option<&'a str> {
    if declared
        .iter()
        .any(|license| normalized_license_chars(license).eq(normalized_license_chars(header)))
    {
        return None;
    }
    declared.first().copied()
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
    normalized_license_chars(value).collect()
}

fn normalized_license_chars(value: &str) -> impl Iterator<Item = char> + '_ {
    value
        .trim()
        .trim_matches(['(', ')'])
        .chars()
        .map(|character| match character {
            '_' => '-',
            other => other.to_ascii_lowercase(),
        })
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
