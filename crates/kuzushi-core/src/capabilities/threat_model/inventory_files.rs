use super::*;

pub(crate) fn inventory_files(root: &Path, limit: usize) -> Result<Vec<String>> {
    let mut out = Vec::new();
    collect_inventory(root, root, limit, &mut out)?;
    if out.is_empty() {
        out.push("(no files found)".to_string());
    }
    Ok(out)
}

pub(crate) fn collect_inventory(
    root: &Path,
    dir: &Path,
    limit: usize,
    out: &mut Vec<String>,
) -> Result<()> {
    for entry in sorted_inventory_entries(dir) {
        collect_inventory_entry_if_room(root, entry, limit, out)?;
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
) -> Result<()> {
    if inventory_limit_reached(out, limit) {
        return Ok(());
    }
    collect_inventory_entry(root, entry, limit, out)
}

fn collect_inventory_entry(
    root: &Path,
    entry: fs::DirEntry,
    limit: usize,
    out: &mut Vec<String>,
) -> Result<()> {
    let Some(kind) = inventory_entry_kind(&entry) else {
        return Ok(());
    };
    let path = entry.path();
    collect_inventory_path(root, &path, kind, limit, out)
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
    limit: usize,
    out: &mut Vec<String>,
) -> Result<()> {
    match kind {
        InventoryEntryKind::Directory => collect_inventory(root, path, limit, out),
        InventoryEntryKind::File => {
            push_inventory_path(root, path, out);
            Ok(())
        }
    }
}

fn skipped_inventory_entry(entry: &fs::DirEntry) -> bool {
    let name = entry.file_name();
    should_skip_path(&name.to_string_lossy())
}

fn push_inventory_path(root: &Path, path: &Path, out: &mut Vec<String>) {
    out.push(
        path.strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string(),
    );
}
