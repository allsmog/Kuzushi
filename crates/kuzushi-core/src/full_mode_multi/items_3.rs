use super::prelude::*;
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
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        let name_owned = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };
        let name = name_owned.as_str();

        if SKIP_DIRS.contains(&name) {
            continue;
        }
        if name.starts_with('.') {
            continue;
        }
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_dir() {
            walk_recursive(root, &path, extensions, out)?;
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        if !extensions.iter().any(|e| e == &ext) {
            continue;
        }
        let metadata = match path.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let bytes = metadata.len() as usize;
        if bytes == 0 || bytes > MAX_FILE_BYTES {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string_lossy().into_owned());
        let est_tokens = est_tokens_for_bytes(bytes);
        out.push(FileBucket {
            path: relative,
            bytes,
            est_tokens,
        });
    }
    Ok(())
}

pub(crate) fn est_tokens_for_bytes(bytes: usize) -> usize {
    ((bytes as f64) / BYTES_PER_TOKEN).ceil() as usize
}
