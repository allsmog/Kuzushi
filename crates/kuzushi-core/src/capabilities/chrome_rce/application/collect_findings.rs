use crate::capabilities::chrome_rce::domain::is_source_path;
use crate::findings::{Finding, Severity};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub(crate) fn collect_findings(
    root: &Path,
    dir: &Path,
    findings: &mut Vec<Finding>,
    limit: usize,
) -> Result<bool> {
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("chrome-rce could not read {}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        if collect_findings_entry(root, entry, findings, limit)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn collect_findings_entry(
    root: &Path,
    entry: fs::DirEntry,
    findings: &mut Vec<Finding>,
    limit: usize,
) -> Result<bool> {
    if should_skip_path(&entry.file_name().to_string_lossy()) {
        return Ok(false);
    }
    let path = entry.path();
    let file_type = entry.file_type()?;
    if file_type.is_dir() {
        return collect_findings(root, &path, findings, limit);
    }
    collect_file_findings(root, &path, &file_type, findings, limit)
}

fn collect_file_findings(
    root: &Path,
    path: &Path,
    file_type: &fs::FileType,
    findings: &mut Vec<Finding>,
    limit: usize,
) -> Result<bool> {
    if !file_type.is_file() || !is_source_path(root, path) {
        return Ok(false);
    }
    collect_duplicate_handle_findings(root, path, findings, limit)
}

fn should_skip_path(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".kuzushi"
            | ".next"
            | ".turbo"
            | "coverage"
            | "dist"
            | "native"
            | "node_modules"
            | "target"
    )
}

fn collect_duplicate_handle_findings(
    root: &Path,
    path: &Path,
    findings: &mut Vec<Finding>,
    limit: usize,
) -> Result<bool> {
    let raw = crate::bounded_file::read_regular_bytes_within(root, path, 8 * 1024 * 1024)
        .with_context(|| format!("chrome-rce could not read source {}", path.display()))?;
    if raw.iter().take(4096).any(|byte| *byte == 0) {
        return Ok(false);
    }
    let text = String::from_utf8_lossy(&raw);
    if !contains_unrejected_duplicate_handle(&text) {
        return Ok(false);
    }
    Ok(push_duplicate_handle_lines(
        root, path, &text, findings, limit,
    ))
}

fn contains_unrejected_duplicate_handle(text: &str) -> bool {
    text.contains("DuplicateHandle")
        && !DUPLICATE_HANDLE_REJECTION_MARKERS
            .iter()
            .any(|marker| text.contains(marker))
}

const DUPLICATE_HANDLE_REJECTION_MARKERS: &[&str] = &[
    "IsPseudoHandle",
    "INVALID_HANDLE_VALUE",
    "IsValidHandleValue",
    "reinterpret_cast<intptr_t>",
];

fn push_duplicate_handle_lines(
    root: &Path,
    path: &Path,
    text: &str,
    findings: &mut Vec<Finding>,
    limit: usize,
) -> bool {
    for (index, line) in text.lines().enumerate() {
        if line.contains("DuplicateHandle") {
            findings.push(duplicate_handle_finding(root, path, index));
            if findings.len() >= limit {
                return true;
            }
        }
    }
    false
}

fn duplicate_handle_finding(root: &Path, path: &Path, index: usize) -> Finding {
    Finding::new_tool(
        "chrome-rce",
        "chrome-rce-mojo-broker-pseudohandle-reject",
        path.strip_prefix(root).unwrap_or(path).display().to_string(),
        (index + 1) as u32,
        None,
        Severity::High,
        "DuplicateHandle text appears in a Chromium IPC/broker path without a recognized rejection marker in that file. Confirm executable call sites and handle validation before assessing impact; this heuristic does not establish a vulnerability.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_limit_stops_before_later_files_are_inspected() {
        let root = tempfile::tempdir().unwrap();
        let broker = root.path().join("broker");
        fs::create_dir(&broker).unwrap();
        fs::write(
            broker.join("a-owned.cc"),
            "// Owned inert token: DuplicateHandle.\n",
        )
        .unwrap();
        fs::File::create(broker.join("z-uninspected.cc"))
            .unwrap()
            .set_len(8 * 1024 * 1024 + 1)
            .unwrap();
        let mut findings = Vec::new();
        assert!(collect_findings(root.path(), root.path(), &mut findings, 1).unwrap());
        assert_eq!(findings.len(), 1);
        assert!(collect_findings(root.path(), root.path(), &mut Vec::new(), 4).is_err());
    }
}
