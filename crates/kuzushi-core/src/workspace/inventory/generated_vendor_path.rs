use super::*;

pub(crate) fn generated_vendor_path(
    relative: &str,
    file_name: &str,
    is_dir: bool,
) -> Option<InventoryPathClassification> {
    let lower_name = file_name.to_ascii_lowercase();
    let lower_path = relative.to_ascii_lowercase();
    let (kind, reason) = if is_dir && vendor_dir(&lower_name) {
        ("vendor", "dependency or vendored source directory")
    } else if is_dir && generated_dir(&lower_name) {
        ("generated", "generated or build output directory")
    } else if !is_dir && generated_file(&lower_path) {
        ("generated", "generated source file")
    } else {
        return None;
    };
    Some(InventoryPathClassification {
        path: relative.to_string(),
        kind: kind.to_string(),
        reason: reason.to_string(),
    })
}

pub(crate) fn ignored_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".hg" | ".svn" | ".kuzushi" | ".codex-active" | ".ruff_cache" | ".pytest_cache"
    )
}

pub(crate) fn vendor_dir(name: &str) -> bool {
    matches!(
        name,
        "node_modules"
            | "vendor"
            | "third_party"
            | "third-party"
            | "external"
            | ".venv"
            | "venv"
            | "__pycache__"
    )
}

pub(crate) fn generated_dir(name: &str) -> bool {
    matches!(
        name,
        "target"
            | "dist"
            | "build"
            | "out"
            | ".next"
            | "coverage"
            | "generated"
            | "gen"
            | "__generated__"
    )
}

pub(crate) fn generated_file(path: &str) -> bool {
    path.ends_with(".pb.go")
        || path.ends_with(".gen.go")
        || path.ends_with(".generated.ts")
        || path.ends_with(".generated.js")
        || path.ends_with(".g.rs")
        || path.contains("/generated/")
        || path.contains("/__generated__/")
}

pub(crate) fn read_text_prefix(path: &Path, max_bytes: usize) -> Result<Option<String>> {
    let bytes = fs::read(path).with_context(|| format!("Could not read {}", path.display()))?;
    if bytes.iter().take(4096).any(|byte| *byte == 0) {
        return Ok(None);
    }
    let prefix = &bytes[..bytes.len().min(max_bytes)];
    Ok(Some(String::from_utf8_lossy(prefix).to_string()))
}

pub(crate) fn repo_relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

pub(crate) fn root_name(root: &Path) -> String {
    root.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repository")
        .to_string()
}

pub(crate) fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

pub(crate) fn trim_detail(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(crate) fn extract_quoted_after_marker(line: &str, marker: &str) -> Option<String> {
    let index = line.find(marker)?;
    extract_first_quoted(&line[index + marker.len()..])
}

pub(crate) fn extract_quoted_after_marker_case_insensitive(
    line: &str,
    marker: &str,
) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let index = lower.find(marker)?;
    extract_first_quoted(&line[index + marker.len()..])
}
