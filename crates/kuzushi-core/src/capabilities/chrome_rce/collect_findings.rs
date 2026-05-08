use super::*;

pub(crate) fn collect_findings(root: &Path, dir: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
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
    let Ok(file_type) = entry.file_type() else {
        return Ok(());
    };
    if file_type.is_dir() {
        return collect_findings(root, &path, findings);
    }
    collect_file_findings(root, &path, &file_type, findings);
    Ok(())
}

fn collect_file_findings(
    root: &Path,
    path: &Path,
    file_type: &fs::FileType,
    findings: &mut Vec<Finding>,
) {
    if !file_type.is_file() || !is_source_path(root, path) {
        return;
    }
    collect_duplicate_handle_findings(root, path, findings);
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

fn collect_duplicate_handle_findings(root: &Path, path: &Path, findings: &mut Vec<Finding>) {
    let raw = fs::read(path).unwrap_or_default();
    if raw.iter().take(4096).any(|byte| *byte == 0) {
        return;
    }
    let text = String::from_utf8_lossy(&raw);
    if !contains_unrejected_duplicate_handle(&text) {
        return;
    }
    push_duplicate_handle_lines(root, path, &text, findings);
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

pub(crate) fn is_source_path(root: &Path, path: &Path) -> bool {
    has_source_extension(path) && is_chrome_surface_path(&repo_relative_path(root, path))
}

fn has_source_extension(path: &Path) -> bool {
    let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    SOURCE_EXTENSIONS.contains(&ext)
}

fn repo_relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/")
}

fn is_chrome_surface_path(relative: &str) -> bool {
    CHROME_SURFACE_MARKERS
        .iter()
        .any(|marker| relative.contains(marker))
}

const SOURCE_EXTENSIONS: &[&str] = &["c", "cc", "cpp", "cxx", "h", "hh", "hpp"];
const CHROME_SURFACE_MARKERS: &[&str] = &["/ipc/", "/mojo/", "/services/", "/sandbox/", "broker"];
