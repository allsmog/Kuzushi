use super::*;

pub(crate) fn collect_inventory(
    root: &Path,
    max_files: usize,
    max_bytes_per_file: usize,
) -> Result<Vec<(String, String)>> {
    let mut files = Vec::new();
    collect_inventory_inner(root, root, max_files, max_bytes_per_file, &mut files)?;
    Ok(files)
}

pub(crate) fn collect_inventory_inner(
    root: &Path,
    dir: &Path,
    max_files: usize,
    max_bytes_per_file: usize,
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
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            collect_inventory_inner(root, &path, max_files, max_bytes_per_file, files)?;
            continue;
        }
        if !is_systems_source(&path) {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let content =
            String::from_utf8_lossy(&bytes[..bytes.len().min(max_bytes_per_file)]).to_string();
        let rel = path_relative_to(root, &path);
        files.push((rel, content));
    }
    Ok(())
}

pub(crate) fn is_systems_source(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| SYSTEMS_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}
