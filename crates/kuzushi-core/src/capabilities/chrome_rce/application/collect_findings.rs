use crate::capabilities::chrome_rce::domain::is_source_path;
use crate::findings::{Finding, Severity};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub(crate) fn collect_findings(root: &Path, dir: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("chrome-rce could not read {}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        collect_findings_entry(root, entry, findings)?;
    }
    Ok(())
}

fn collect_findings_entry(
    root: &Path,
    entry: fs::DirEntry,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    if should_skip_path(&entry.file_name().to_string_lossy()) {
        return Ok(());
    }
    let path = entry.path();
    let file_type = entry.file_type()?;
    if file_type.is_dir() {
        return collect_findings(root, &path, findings);
    }
    collect_file_findings(root, &path, &file_type, findings)
}

fn collect_file_findings(
    root: &Path,
    path: &Path,
    file_type: &fs::FileType,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    if !file_type.is_file() || !is_source_path(root, path) {
        return Ok(());
    }
    collect_duplicate_handle_findings(root, path, findings)
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
) -> Result<()> {
    let raw = crate::bounded_file::read_regular_bytes_within(root, path, 8 * 1024 * 1024)
        .with_context(|| format!("chrome-rce could not read source {}", path.display()))?;
    if raw.iter().take(4096).any(|byte| *byte == 0) {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&raw);
    if !contains_unrejected_duplicate_handle(&text) {
        return Ok(());
    }
    push_duplicate_handle_lines(root, path, &text, findings);
    Ok(())
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

fn push_duplicate_handle_lines(root: &Path, path: &Path, text: &str, findings: &mut Vec<Finding>) {
    for (index, line) in text.lines().enumerate() {
        if line.contains("DuplicateHandle") {
            findings.push(duplicate_handle_finding(root, path, index));
        }
    }
}

fn duplicate_handle_finding(root: &Path, path: &Path, index: usize) -> Finding {
    Finding::new_tool(
        "chrome-rce",
        "chrome-rce-mojo-broker-pseudohandle-reject",
        path.strip_prefix(root).unwrap_or(path).display().to_string(),
        (index + 1) as u32,
        None,
        Severity::High,
        "::DuplicateHandle is called in a Chrome IPC/broker path without an obvious pseudo-handle reject. Anchored to CVE-2025-2783; reject Win32 pseudo-handles before duplicating peer-supplied handles.",
    )
}
