use super::*;

pub(crate) fn inventory_files(root: &Path, limit: usize) -> Result<Vec<String>> {
    let mut out = Vec::new();
    collect_inventory(root, root, limit, &mut out)?;
    if out.is_empty() {
        out.push("(no files found)".to_string());
    }
    Ok(out)
}

/// Breadth-first so the row limit samples every subtree: a depth-first walk
/// spends the whole budget inside the alphabetically-first directories on
/// monorepo-scale targets, leaving late-sorting roots (`src/`) unlisted.
pub(crate) fn collect_inventory(
    root: &Path,
    dir: &Path,
    limit: usize,
    out: &mut Vec<String>,
) -> Result<()> {
    let mut pending = std::collections::VecDeque::from([dir.to_path_buf()]);
    while let Some(dir) = pending.pop_front() {
        if inventory_limit_reached(out, limit) {
            return Ok(());
        }
        for entry in sorted_inventory_entries(&dir) {
            collect_inventory_entry_if_room(root, entry, limit, out, &mut pending)?;
        }
    }
    Ok(())
}

fn sorted_inventory_entries(dir: &Path) -> Vec<fs::DirEntry> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    entries
}

fn inventory_limit_reached(out: &[String], limit: usize) -> bool {
    out.len() >= limit
}

fn collect_inventory_entry_if_room(
    root: &Path,
    entry: fs::DirEntry,
    limit: usize,
    out: &mut Vec<String>,
    pending: &mut std::collections::VecDeque<PathBuf>,
) -> Result<()> {
    if inventory_limit_reached(out, limit) {
        return Ok(());
    }
    collect_inventory_entry(root, entry, out, pending)
}

fn collect_inventory_entry(
    root: &Path,
    entry: fs::DirEntry,
    out: &mut Vec<String>,
    pending: &mut std::collections::VecDeque<PathBuf>,
) -> Result<()> {
    let Some(kind) = inventory_entry_kind(&entry) else {
        return Ok(());
    };
    let path = entry.path();
    collect_inventory_path(root, &path, kind, out, pending)
}

#[derive(Clone, Copy)]
enum InventoryEntryKind {
    Directory,
    File,
}

fn inventory_entry_kind(entry: &fs::DirEntry) -> Option<InventoryEntryKind> {
    if skipped_inventory_entry(entry) {
        return None;
    }
    let file_type = entry.file_type().ok()?;
    classify_inventory_entry_type(file_type)
}

fn classify_inventory_entry_type(file_type: fs::FileType) -> Option<InventoryEntryKind> {
    if file_type.is_dir() {
        return Some(InventoryEntryKind::Directory);
    }
    file_type.is_file().then_some(InventoryEntryKind::File)
}

fn collect_inventory_path(
    root: &Path,
    path: &Path,
    kind: InventoryEntryKind,
    out: &mut Vec<String>,
    pending: &mut std::collections::VecDeque<PathBuf>,
) -> Result<()> {
    match kind {
        InventoryEntryKind::Directory => {
            pending.push_back(path.to_path_buf());
            Ok(())
        }
        InventoryEntryKind::File => {
            push_inventory_path(root, path, out);
            Ok(())
        }
    }
}

fn skipped_inventory_entry(entry: &fs::DirEntry) -> bool {
    let name = entry.file_name().to_string_lossy().to_string();
    if should_skip_path(&name) {
        return true;
    }
    entry.file_type().is_ok_and(|kind| kind.is_dir()) && should_skip_hidden_dir(&name)
}

fn push_inventory_path(root: &Path, path: &Path, out: &mut Vec<String>) {
    out.push(
        path.strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string(),
    );
}
