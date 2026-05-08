use super::*;

pub(crate) fn walk_files(cfg: &FullModeConfig) -> Result<Vec<FileBucket>> {
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
    if let Some(scope) = &cfg.scope_files {
        let allowed: std::collections::HashSet<&Path> = scope.iter().map(|p| p.as_path()).collect();
        out.retain(|fb| allowed.contains(Path::new(&fb.path)));
    }
    Ok(out)
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
    if bytes == 0 || bytes > MAX_FILE_BYTES {
        return;
    }
    out.push(FileBucket {
        path: relative_file_path(root, path),
        bytes,
        est_tokens: est_tokens_for_bytes(bytes),
    });
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
