use crate::capabilities::full_mode_multi::domain::{
    FileBucket, FullModeConfig, BYTES_PER_TOKEN, MAX_FILE_BYTES, SKIP_DIRS,
};
use anyhow::Result;
use std::fs;
use std::path::Path;

pub(crate) fn walk_files(cfg: &FullModeConfig) -> Result<Vec<FileBucket>> {
    if let Some(scope) = &cfg.scope_files {
        return Ok(scoped_file_buckets(&cfg.workspace_root, scope));
    }
    let extensions = if cfg.include_extensions.is_empty() {
        c_default_extensions()
    } else {
        cfg.include_extensions
            .iter()
            .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
            .collect::<Vec<_>>()
    };
    let mut out = Vec::new();
    walk_recursive(
        &cfg.workspace_root,
        &cfg.workspace_root,
        &extensions,
        &mut out,
    )?;
    Ok(out)
}

/// An explicit scope list is an operator allowlist: plan exactly the named
/// files, with no language-extension filter. Filtering scope entries through
/// `c_default_extensions()` silently planned 0 files for Scala/Python/Go
/// shards while still reporting a completed run.
fn scoped_file_buckets(root: &Path, scope: &[std::path::PathBuf]) -> Vec<FileBucket> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for rel in scope {
        if !seen.insert(rel.as_path()) {
            continue;
        }
        let Ok(metadata) = root.join(rel).metadata() else {
            continue;
        };
        let bytes = metadata.len() as usize;
        if !metadata.is_file() || bytes == 0 {
            continue;
        }
        push_file_buckets(root, &rel.to_string_lossy(), bytes, &mut out);
    }
    out
}

/// Files above `MAX_FILE_BYTES` are split into line-aligned window buckets
/// instead of being dropped. Dropping was silent and hit exactly the files
/// most worth scanning (334 KB PowerShellExecutor.cpp with 9 known
/// injection sites planned into ZERO chunks with no diagnostic).
fn push_file_buckets(root: &Path, rel_path: &str, bytes: usize, out: &mut Vec<FileBucket>) {
    if bytes <= MAX_FILE_BYTES {
        out.push(FileBucket::whole(
            rel_path.to_owned(),
            bytes,
            est_tokens_for_bytes(bytes),
        ));
        return;
    }
    // Unreadable / non-UTF-8 oversized files keep the old skip, but the
    // common source-file case is now covered.
    if let Some(windows) = window_buckets_for_large_file(root, rel_path) {
        out.extend(windows);
    }
}

fn window_buckets_for_large_file(root: &Path, rel_path: &str) -> Option<Vec<FileBucket>> {
    let content = fs::read_to_string(root.join(rel_path)).ok()?;
    let mut windows = Vec::new();
    let mut window_start_byte = 0usize;
    let mut window_start_line = 1usize;
    let mut current_len = 0usize;
    let mut current_lines = 0usize;
    for line in content.split_inclusive('\n') {
        if current_len > 0 && current_len + line.len() > MAX_FILE_BYTES {
            windows.push(window_bucket(
                rel_path,
                window_start_byte,
                window_start_line,
                current_len,
            ));
            window_start_byte += current_len;
            window_start_line += current_lines;
            current_len = 0;
            current_lines = 0;
        }
        current_len += line.len();
        current_lines += 1;
    }
    if current_len > 0 {
        windows.push(window_bucket(
            rel_path,
            window_start_byte,
            window_start_line,
            current_len,
        ));
    }
    Some(windows)
}

fn window_bucket(path: &str, start_byte: usize, start_line: usize, bytes: usize) -> FileBucket {
    FileBucket {
        path: path.to_owned(),
        bytes,
        est_tokens: est_tokens_for_bytes(bytes),
        start_byte,
        start_line,
    }
}

pub(crate) fn c_default_extensions() -> Vec<String> {
    ["c", "cc", "cpp", "cxx", "h", "hh", "hpp", "hxx"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

pub(crate) fn walk_recursive(
    root: &Path,
    current: &Path,
    extensions: &[String],
    out: &mut Vec<FileBucket>,
) -> Result<()> {
    let entries = match fs::read_dir(current) {
        Ok(it) => it,
        Err(_) => return Ok(()),
    };
    for entry in entries {
        walk_entry(root, entry, extensions, out)?;
    }
    Ok(())
}

fn walk_entry(
    root: &Path,
    entry: std::io::Result<fs::DirEntry>,
    extensions: &[String],
    out: &mut Vec<FileBucket>,
) -> Result<()> {
    let Ok(entry) = entry else {
        return Ok(());
    };
    let path = entry.path();
    if should_skip_path_name(&path) {
        return Ok(());
    }
    let Ok(file_type) = entry.file_type() else {
        return Ok(());
    };
    if file_type.is_dir() {
        return walk_recursive(root, &path, extensions, out);
    }
    if file_type.is_file() {
        collect_file_bucket(root, &path, extensions, out);
    }
    Ok(())
}

fn should_skip_path_name(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return true;
    };
    name.starts_with('.') || SKIP_DIRS.contains(&name)
}

fn collect_file_bucket(root: &Path, path: &Path, extensions: &[String], out: &mut Vec<FileBucket>) {
    if !has_included_extension(path, extensions) {
        return;
    }
    let Ok(metadata) = path.metadata() else {
        return;
    };
    let bytes = metadata.len() as usize;
    if bytes == 0 {
        return;
    }
    push_file_buckets(root, &relative_file_path(root, path), bytes, out);
}

fn has_included_extension(path: &Path, extensions: &[String]) -> bool {
    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    extensions.iter().any(|candidate| candidate == &ext)
}

fn relative_file_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string_lossy().into_owned())
}

pub(crate) fn est_tokens_for_bytes(bytes: usize) -> usize {
    ((bytes as f64) / BYTES_PER_TOKEN).ceil() as usize
}
