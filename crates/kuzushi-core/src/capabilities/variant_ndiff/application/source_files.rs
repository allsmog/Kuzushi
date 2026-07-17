use super::*;

#[derive(Debug, Clone, Copy)]
pub(crate) struct VariantSearchLimits {
    pub(crate) max_source_files: usize,
    pub(crate) max_walk_entries: usize,
    pub(crate) max_file_bytes: usize,
    pub(crate) max_total_bytes: usize,
}

impl Default for VariantSearchLimits {
    fn default() -> Self {
        Self {
            max_source_files: 10_000,
            max_walk_entries: 50_000,
            max_file_bytes: 8 * 1024 * 1024,
            max_total_bytes: 128 * 1024 * 1024,
        }
    }
}

pub(crate) struct VariantSourceInventory {
    pub(crate) files: Vec<PathBuf>,
    pub(crate) truncation_reasons: Vec<String>,
}

struct VariantSourceWalk {
    limits: VariantSearchLimits,
    entries_seen: usize,
    files: Vec<PathBuf>,
    truncation_reasons: Vec<String>,
}

pub(crate) fn collect_variant_source_inventory(
    repo_root: &Path,
    limits: VariantSearchLimits,
) -> Result<VariantSourceInventory> {
    let mut walk = VariantSourceWalk {
        limits,
        entries_seen: 0,
        files: Vec::new(),
        truncation_reasons: Vec::new(),
    };
    collect_variant_source_files_inner(repo_root, repo_root, &mut walk)?;
    walk.files.sort();
    Ok(VariantSourceInventory {
        files: walk.files,
        truncation_reasons: walk.truncation_reasons,
    })
}

fn collect_variant_source_files_inner(
    repo_root: &Path,
    dir: &Path,
    walk: &mut VariantSourceWalk,
) -> Result<()> {
    if source_walk_stopped(walk) {
        return Ok(());
    }
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        if observe_walk_entry(walk) {
            break;
        }
        collect_variant_source_entry(repo_root, entry, walk)?;
    }
    Ok(())
}

fn source_walk_stopped(walk: &mut VariantSourceWalk) -> bool {
    if walk.entries_seen >= walk.limits.max_walk_entries {
        record_truncation(walk, "walk_entry_limit");
        return true;
    }
    if walk.files.len() >= walk.limits.max_source_files {
        record_truncation(walk, "source_file_limit");
        return true;
    }
    false
}

fn observe_walk_entry(walk: &mut VariantSourceWalk) -> bool {
    if source_walk_stopped(walk) {
        return true;
    }
    walk.entries_seen += 1;
    if walk.entries_seen <= walk.limits.max_walk_entries {
        return false;
    }
    record_truncation(walk, "walk_entry_limit");
    true
}

fn collect_variant_source_entry(
    repo_root: &Path,
    entry: fs::DirEntry,
    walk: &mut VariantSourceWalk,
) -> Result<()> {
    let path = entry.path();
    let Ok(file_type) = entry.file_type() else {
        return Ok(());
    };
    if file_type.is_dir() {
        return collect_variant_source_directory(repo_root, &entry, &path, walk);
    }
    collect_variant_source_file(repo_root, path, &file_type, walk);
    Ok(())
}

fn collect_variant_source_directory(
    repo_root: &Path,
    entry: &fs::DirEntry,
    path: &Path,
    walk: &mut VariantSourceWalk,
) -> Result<()> {
    let name = entry.file_name().to_string_lossy().to_string();
    if ignored_variant_dir(&name) {
        return Ok(());
    }
    collect_variant_source_files_inner(repo_root, path, walk)
}

fn collect_variant_source_file(
    repo_root: &Path,
    path: PathBuf,
    file_type: &fs::FileType,
    walk: &mut VariantSourceWalk,
) {
    if !file_type.is_file() || !is_variant_source_file(&path) {
        return;
    }
    if repo_relative_path(repo_root, &path).is_some() {
        walk.files.push(path);
    }
}

fn record_truncation(walk: &mut VariantSourceWalk, reason: &str) {
    if !walk.truncation_reasons.iter().any(|item| item == reason) {
        walk.truncation_reasons.push(reason.to_string());
    }
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
