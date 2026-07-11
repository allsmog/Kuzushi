use super::*;
use crate::bounded_file::read_source_text_prefix;

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
    for entry in sorted_readable_entries(dir) {
        if files.len() >= max_files {
            break;
        }
        collect_agentic_entry(
            root,
            entry,
            max_files,
            max_bytes_per_file,
            include_patterns,
            exclude_patterns,
            files,
        )?;
    }
    Ok(())
}

fn sorted_readable_entries(dir: &Path) -> Vec<fs::DirEntry> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    entries
}

fn collect_agentic_entry(
    root: &Path,
    entry: fs::DirEntry,
    max_files: usize,
    max_bytes_per_file: usize,
    include_patterns: &[String],
    exclude_patterns: &[String],
    files: &mut Vec<(String, String)>,
) -> Result<()> {
    let Some((path, file_type)) = visible_agentic_entry(&entry) else {
        return Ok(());
    };
    if file_type.is_dir() {
        return collect_agentic_repo_inventory_inner(
            root,
            &path,
            max_files,
            max_bytes_per_file,
            include_patterns,
            exclude_patterns,
            files,
        );
    }
    if let Some(item) = agentic_inventory_file(
        root,
        &path,
        file_type.is_file(),
        max_bytes_per_file,
        include_patterns,
        exclude_patterns,
    ) {
        files.push(item);
    }
    Ok(())
}

fn visible_agentic_entry(entry: &fs::DirEntry) -> Option<(PathBuf, fs::FileType)> {
    if should_skip_path(&entry.file_name().to_string_lossy()) {
        return None;
    }
    Some((entry.path(), entry.file_type().ok()?))
}

fn agentic_inventory_file(
    root: &Path,
    path: &Path,
    is_file: bool,
    max_bytes_per_file: usize,
    include_patterns: &[String],
    exclude_patterns: &[String],
) -> Option<(String, String)> {
    if !is_file || !is_agentic_context_file(path) {
        return None;
    }
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string();
    if !agentic_path_allowed(&relative, include_patterns, exclude_patterns) {
        return None;
    }
    let snippet = read_source_text_prefix(path, max_bytes_per_file)
        .ok()
        .flatten()?;
    Some((relative, snippet))
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
