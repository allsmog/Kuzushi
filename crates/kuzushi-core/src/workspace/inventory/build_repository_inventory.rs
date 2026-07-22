use super::*;

const MAX_REPOSITORY_ENTRIES: usize = 100_000;
const MAX_REPOSITORY_INSPECTED_BYTES: usize = 512 * 1024 * 1024;
const MAX_FILE_INSPECTION_BYTES: usize = 256 * 1024;

struct InventoryBudget<'p> {
    entries: usize,
    inspected_bytes: usize,
    max_entries: usize,
    max_inspected_bytes: usize,
    truncation: Option<String>,
    /// Walked-entry observer: monorepo walks run for minutes, and a silent
    /// walk reads as a hung run — callers surface these counts as heartbeat
    /// progress.
    progress: Option<&'p mut dyn FnMut(usize)>,
}

pub fn build_repository_inventory(root: impl AsRef<Path>) -> Result<RepositoryInventory> {
    build_repository_inventory_with_progress(root, |_| {})
}

pub fn build_repository_inventory_with_progress(
    root: impl AsRef<Path>,
    mut on_entries: impl FnMut(usize),
) -> Result<RepositoryInventory> {
    build_repository_inventory_with_limits(
        root.as_ref(),
        MAX_REPOSITORY_ENTRIES,
        MAX_REPOSITORY_INSPECTED_BYTES,
        &mut on_entries,
    )
}

fn build_repository_inventory_with_limits(
    root: &Path,
    max_entries: usize,
    max_inspected_bytes: usize,
    on_entries: &mut dyn FnMut(usize),
) -> Result<RepositoryInventory> {
    let root = root
        .canonicalize()
        .with_context(|| format!("repository root {} does not exist", root.display()))?;
    if !root.is_dir() {
        anyhow::bail!("repository root {} is not a directory", root.display());
    }

    let mut builder = InventoryBuilder::default();
    let mut budget = InventoryBudget::new(max_entries, max_inspected_bytes, on_entries);
    walk_repository(&root, &root, &mut builder, &mut budget)?;
    let truncation = budget
        .truncation
        .map(|reason| InventoryTruncation { reason });
    Ok(builder.finish(root_name(&root), truncation))
}

impl<'p> InventoryBudget<'p> {
    fn new(
        max_entries: usize,
        max_inspected_bytes: usize,
        progress: &'p mut dyn FnMut(usize),
    ) -> Self {
        Self {
            entries: 0,
            inspected_bytes: 0,
            max_entries,
            max_inspected_bytes,
            truncation: None,
            progress: Some(progress),
        }
    }

    fn entries_exhausted(&self) -> bool {
        self.entries >= self.max_entries
    }

    fn collect_dir(&mut self, read_dir: fs::ReadDir, dir: &Path) -> Result<Vec<fs::DirEntry>> {
        let remaining = self.max_entries.saturating_sub(self.entries);
        let mut entries = read_dir
            .take(remaining.saturating_add(1))
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("Could not enumerate {}", dir.display()))?;
        if entries.len() > remaining {
            entries.truncate(remaining);
            self.mark_truncated(format!(
                "entry cap of {} reached at {}; inventory covers the walked prefix only",
                self.max_entries,
                dir.display()
            ));
        }
        self.entries += entries.len();
        if let Some(progress) = self.progress.as_deref_mut() {
            progress(self.entries);
        }
        Ok(entries)
    }

    /// Returns whether the file's content may still be inspected. Once the
    /// byte budget is exhausted the walk continues metadata-only.
    fn record_inspected_bytes(&mut self, bytes: usize, path: &Path) -> bool {
        let next = self.inspected_bytes.saturating_add(bytes);
        if next > self.max_inspected_bytes {
            self.mark_truncated(format!(
                "content-inspection cap of {} bytes reached at {}; remaining files recorded metadata-only",
                self.max_inspected_bytes,
                path.display()
            ));
            return false;
        }
        self.inspected_bytes = next;
        true
    }

    fn mark_truncated(&mut self, reason: String) {
        if self.truncation.is_none() {
            self.truncation = Some(reason);
        }
    }
}

fn walk_repository(
    root: &Path,
    dir: &Path,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
) -> Result<()> {
    if budget.entries_exhausted() {
        budget.mark_truncated(format!(
            "entry cap reached before walking {}; inventory covers the walked prefix only",
            dir.display()
        ));
        return Ok(());
    }
    let read_dir = fs::read_dir(dir)
        .with_context(|| format!("Could not read repository directory {}", dir.display()))?;
    let mut entries = budget.collect_dir(read_dir, dir)?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        walk_repository_entry(root, entry, builder, budget)?;
    }

    Ok(())
}

fn walk_repository_entry(
    root: &Path,
    entry: fs::DirEntry,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
) -> Result<()> {
    let path = entry.path();
    let file_type = entry
        .file_type()
        .with_context(|| format!("Could not inspect repository entry {}", path.display()))?;
    let name = entry.file_name().to_string_lossy().to_string();
    let relative = repo_relative(root, &path);

    if file_type.is_dir() {
        return walk_repository_dir(root, &path, &relative, &name, builder, budget);
    }
    if file_type.is_file() {
        walk_repository_file(&path, &relative, &name, builder, budget)?;
    }
    Ok(())
}

fn walk_repository_dir(
    root: &Path,
    path: &Path,
    relative: &str,
    name: &str,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
) -> Result<()> {
    if ignored_dir(name) {
        return Ok(());
    }
    if let Some(classification) = generated_vendor_path(relative, name, true) {
        builder.add_generated_vendor_path(classification);
        return Ok(());
    }
    walk_repository(root, path, builder, budget)
}

fn walk_repository_file(
    path: &Path,
    relative: &str,
    name: &str,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
) -> Result<()> {
    let generated_vendor = record_file_metadata(relative, name, builder);
    let Some(text) = read_text_prefix(path, MAX_FILE_INSPECTION_BYTES)? else {
        return Ok(());
    };
    if !budget.record_inspected_bytes(text.len(), path) {
        return Ok(());
    }
    inspect_manifest_frameworks(relative, name, &text, builder);
    if generated_vendor.is_some() {
        return Ok(());
    }
    record_source_file(path, relative, &text, builder);
    Ok(())
}

fn record_file_metadata(
    relative: &str,
    name: &str,
    builder: &mut InventoryBuilder,
) -> Option<InventoryPathClassification> {
    let generated_vendor = generated_vendor_path(relative, name, false);
    if let Some(classification) = generated_vendor.clone() {
        builder.add_generated_vendor_path(classification);
    }
    if let Some(kind) = manifest_kind(relative, name) {
        builder.add_manifest(relative, kind);
    }
    if let Some(kind) = dependency_manifest_kind(relative, name) {
        builder.add_dependency_manifest(relative, kind);
    }
    if let Some(kind) = config_file_kind(relative, name) {
        builder.add_config_file(relative, kind);
    }
    generated_vendor
}

fn record_source_file(path: &Path, relative: &str, text: &str, builder: &mut InventoryBuilder) {
    let Some(language) = language_for_path(path) else {
        return;
    };
    builder.add_source_file(relative, language, text.len() as u64);
    inspect_source_file(relative, language, text, builder);
}

#[cfg(test)]
mod coverage_limit_tests {
    use super::*;

    #[test]
    fn entry_capped_walk_returns_partial_inventory_marked_truncated() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();
        fs::write(temp.path().join("b.rs"), "fn b() {}\n").unwrap();

        let inventory = build_repository_inventory_with_limits(temp.path(), 1, 1024, &mut |_| {}).unwrap();

        let truncation = inventory.truncation.expect("partial walk must be marked");
        assert!(truncation.reason.contains("entry cap"));
        assert_eq!(inventory.source_files.len(), 1);
    }

    #[test]
    fn byte_capped_walk_keeps_metadata_and_marks_truncated() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("large.rs"), "x".repeat(64)).unwrap();

        let inventory = build_repository_inventory_with_limits(temp.path(), 10, 8, &mut |_| {}).unwrap();

        let truncation = inventory.truncation.expect("partial inspection must be marked");
        assert!(truncation.reason.contains("content-inspection cap"));
        assert!(inventory.source_files.is_empty());
    }

    #[test]
    fn uncapped_walk_carries_no_truncation_marker() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();

        let inventory = build_repository_inventory_with_limits(temp.path(), 100, 1024, &mut |_| {}).unwrap();

        assert!(inventory.truncation.is_none());
        assert_eq!(inventory.source_files.len(), 1);
    }
}
