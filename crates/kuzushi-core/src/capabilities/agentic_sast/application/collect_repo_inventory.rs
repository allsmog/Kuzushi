use super::*;

pub(crate) fn collect_agentic_repo_inventory(
    root: &Path,
    max_files: usize,
    max_bytes_per_file: usize,
) -> Result<Vec<(String, String)>> {
    collect_agentic_repo_inventory_with_filters(root, max_files, max_bytes_per_file, &[], &[])
}

pub(crate) fn collect_agentic_repo_inventory_with_filters(
    root: &Path,
    max_files: usize,
    max_bytes_per_file: usize,
    include_patterns: &[String],
    exclude_patterns: &[String],
) -> Result<Vec<(String, String)>> {
    let mut files = Vec::new();
    collect_agentic_repo_inventory_inner(
        root,
        root,
        max_files,
        max_bytes_per_file,
        include_patterns,
        exclude_patterns,
        &mut files,
    )?;
    Ok(files)
}

pub(crate) fn collect_agentic_repo_inventory_inner(
    root: &Path,
    dir: &Path,
    max_files: usize,
    max_bytes_per_file: usize,
    include_patterns: &[String],
    exclude_patterns: &[String],
    files: &mut Vec<(String, String)>,
) -> Result<()> {
    if files.len() >= max_files {
        return Ok(());
    }
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        if files.len() >= max_files {
            break;
        }
        let path = entry.path();
        let file_name = entry.file_name();
        if should_skip_path(&file_name.to_string_lossy()) {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_agentic_repo_inventory_inner(
                root,
                &path,
                max_files,
                max_bytes_per_file,
                include_patterns,
                exclude_patterns,
                files,
            )?;
        } else if file_type.is_file() && is_agentic_context_file(&path) {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            if !agentic_path_allowed(&relative, include_patterns, exclude_patterns) {
                continue;
            }
            let raw = fs::read(&path).unwrap_or_default();
            if raw.iter().take(4096).any(|byte| *byte == 0) {
                continue;
            }
            let snippet =
                String::from_utf8_lossy(&raw[..raw.len().min(max_bytes_per_file)]).to_string();
            files.push((relative, snippet));
        }
    }
    Ok(())
}

pub(crate) fn agentic_path_allowed(
    relative_path: &str,
    include_patterns: &[String],
    exclude_patterns: &[String],
) -> bool {
    let path = normalize_agentic_path(relative_path);
    let included = include_patterns.is_empty()
        || include_patterns
            .iter()
            .any(|pattern| pattern_matches_path(pattern, &path));
    included
        && !exclude_patterns
            .iter()
            .any(|pattern| pattern_matches_path(pattern, &path))
}

fn normalize_agentic_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn pattern_matches_path(pattern: &str, path: &str) -> bool {
    let pattern = normalize_agentic_path(pattern.trim());
    if pattern.is_empty() {
        return false;
    }
    if wildcard_match(&pattern, path) {
        return true;
    }
    if !pattern.contains('/') {
        if let Some(file_name) = Path::new(path).file_name().and_then(|name| name.to_str()) {
            return wildcard_match(&pattern, file_name);
        }
    }
    false
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let mut pattern_index = 0usize;
    let mut text_index = 0usize;
    let mut star_index = None;
    let mut match_index = 0usize;

    while text_index < text.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == text[text_index])
        {
            pattern_index += 1;
            text_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            match_index = text_index;
            pattern_index += 1;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            match_index += 1;
            text_index = match_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

pub(crate) fn is_agentic_context_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if matches!(
        name,
        "package.json" | "Cargo.toml" | "pyproject.toml" | "go.mod" | "pom.xml"
    ) {
        return true;
    }
    matches!(
        path.extension().and_then(|ext| ext.to_str()).unwrap_or(""),
        "c" | "cc"
            | "cpp"
            | "h"
            | "hh"
            | "hpp"
            | "hxx"
            | "m"
            | "mm"
            | "cs"
            | "go"
            | "java"
            | "js"
            | "jsx"
            | "kt"
            | "php"
            | "py"
            | "rb"
            | "rs"
            | "sol"
            | "ts"
            | "tsx"
    )
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
