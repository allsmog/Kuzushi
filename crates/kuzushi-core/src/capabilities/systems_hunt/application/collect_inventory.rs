use super::*;

pub(crate) fn collect_inventory(
    root: &Path,
    max_files: usize,
    max_bytes_per_file: usize,
) -> Result<Vec<(String, String)>> {
    let mut files = Vec::new();
    collect_inventory_inner(
        root,
        root,
        InventoryWalkOptions {
            max_files,
            max_bytes_per_file,
            include_non_production: true,
        },
        &mut files,
    )?;
    Ok(files)
}

pub(crate) fn collect_production_inventory(
    root: &Path,
    options: &SystemsHuntInput,
) -> Result<Vec<(String, String)>> {
    let mut files = Vec::new();
    collect_inventory_inner(
        root,
        root,
        InventoryWalkOptions {
            max_files: options.max_files,
            max_bytes_per_file: options.head_bytes,
            include_non_production: options.include_non_production,
        },
        &mut files,
    )?;
    Ok(files)
}

#[derive(Clone, Copy)]
pub(crate) struct InventoryWalkOptions {
    max_files: usize,
    max_bytes_per_file: usize,
    include_non_production: bool,
}

pub(crate) fn collect_inventory_inner(
    root: &Path,
    dir: &Path,
    options: InventoryWalkOptions,
    files: &mut Vec<(String, String)>,
) -> Result<()> {
    if files.len() >= options.max_files {
        return Ok(());
    }
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        if files.len() >= options.max_files {
            break;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if should_skip_systems_dir(name.as_ref(), options.include_non_production) {
                continue;
            }
            collect_inventory_inner(root, &path, options, files)?;
            continue;
        }
        if !is_systems_source(&path) {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let content =
            String::from_utf8_lossy(&bytes[..bytes.len().min(options.max_bytes_per_file)])
                .to_string();
        let rel = path_relative_to(root, &path);
        files.push((rel, content));
    }
    Ok(())
}

fn should_skip_systems_dir(name: &str, include_non_production: bool) -> bool {
    SKIP_DIRS.contains(&name)
        || (!include_non_production && NON_PRODUCTION_SYSTEMS_DIRS.contains(&name))
}

pub(crate) fn is_systems_source(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| SYSTEMS_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}
