use super::prelude::*;
use super::*;

pub(crate) fn collect_variant_source_files_inner(
    repo_root: &Path,
    dir: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let name = entry.file_name().to_string_lossy().to_string();
        if file_type.is_dir() {
            if ignored_variant_dir(&name) {
                continue;
            }
            collect_variant_source_files_inner(repo_root, &path, files)?;
            continue;
        }
        if file_type.is_file()
            && is_variant_source_file(&path)
            && repo_relative_path(repo_root, &path).is_some()
        {
            files.push(path);
        }
    }
    Ok(())
}

pub(crate) fn repo_relative_path(repo_root: &Path, path: &Path) -> Option<String> {
    path.strip_prefix(repo_root).ok().map(|relative| {
        relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/")
    })
}

pub(crate) fn is_variant_source_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some(
            "js" | "jsx"
                | "ts"
                | "tsx"
                | "mjs"
                | "cjs"
                | "py"
                | "go"
                | "rs"
                | "java"
                | "kt"
                | "rb"
                | "php"
                | "c"
                | "cc"
                | "cpp"
                | "h"
                | "hpp"
        )
    )
}

pub(crate) fn ignored_variant_dir(name: &str) -> bool {
    name.starts_with('.')
        || DEFAULT_VENDOR_PATHS
            .iter()
            .any(|ignored| ignored.eq_ignore_ascii_case(name))
        || matches!(
            name,
            "target" | "dist" | "build" | "coverage" | "__pycache__"
        )
}

pub(crate) fn line_window(text: &str, center_line_index: usize, radius: usize) -> String {
    let lines = text.lines().collect::<Vec<_>>();
    let start = center_line_index.saturating_sub(radius);
    let end = (center_line_index + radius + 1).min(lines.len());
    lines[start..end].join("\n")
}

pub(crate) fn variants_array(raw: Value) -> Vec<Value> {
    match raw {
        Value::Object(mut object) => object
            .remove("variants")
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default(),
        Value::Array(items) => items,
        _ => Vec::new(),
    }
}
