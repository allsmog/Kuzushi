use super::*;
use crate::bounded_file::read_source_text_prefix;

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
    for entry in sorted_readable_entries(dir) {
        if files.len() >= options.max_files {
            break;
        }
        collect_systems_entry(root, entry, options, files)?;
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

fn collect_systems_entry(
    root: &Path,
    entry: fs::DirEntry,
    options: InventoryWalkOptions,
    files: &mut Vec<(String, String)>,
) -> Result<()> {
    let Ok(file_type) = entry.file_type() else {
        return Ok(());
    };
    if file_type.is_dir() {
        return collect_systems_directory(root, &entry, options, files);
    }
    if let Some(item) = systems_inventory_file(root, &entry.path(), file_type.is_file(), options) {
        files.push(item);
    }
    Ok(())
}

fn collect_systems_directory(
    root: &Path,
    entry: &fs::DirEntry,
    options: InventoryWalkOptions,
    files: &mut Vec<(String, String)>,
) -> Result<()> {
    let name = entry.file_name();
    if should_skip_systems_dir(&name.to_string_lossy(), options.include_non_production) {
        return Ok(());
    }
    collect_inventory_inner(root, &entry.path(), options, files)
}

fn systems_inventory_file(
    root: &Path,
    path: &Path,
    is_file: bool,
    options: InventoryWalkOptions,
) -> Option<(String, String)> {
    if !is_file || !is_systems_source(path) {
        return None;
    }
    let content = read_source_text_prefix(path, options.max_bytes_per_file)
        .ok()
        .flatten()?;
    Some((path_relative_to(root, path), content))
}

fn should_skip_systems_dir(name: &str, include_non_production: bool) -> bool {
    SKIP_DIRS.contains(&name)
        || (!include_non_production && NON_PRODUCTION_SYSTEMS_DIRS.contains(&name))
}

pub(crate) fn is_systems_source(path: &Path) -> bool {
    if is_non_production_test_source(path) {
        return false;
    }
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| SYSTEMS_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

fn is_non_production_test_source(path: &Path) -> bool {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .map(|stem| stem.to_ascii_lowercase())
        .unwrap_or_default();
    if stem.ends_with("_test")
        || stem.ends_with("_tests")
        || stem.ends_with("_unittest")
        || stem.ends_with("_browsertest")
        || stem.ends_with("_perftest")
        || stem.ends_with("_fuzzer")
        || stem.contains("_test_")
        || stem.contains("_tests_")
        || stem.contains("_unittest_")
        || stem.contains("_browsertest_")
        || stem.contains("_perftest_")
        || stem.contains("_fuzzer_")
        || stem.starts_with("test_")
        || stem == "test"
        || stem == "tests"
    {
        return true;
    }

    path.components().any(|component| {
        let Some(name) = component.as_os_str().to_str() else {
            return false;
        };
        matches!(
            name.to_ascii_lowercase().as_str(),
            "test" | "tests" | "testing" | "unittest" | "unittests" | "browser_tests"
        )
    })
}
