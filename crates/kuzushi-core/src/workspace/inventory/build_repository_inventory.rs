use super::*;

const MAX_REPOSITORY_ENTRIES: usize = 100_000;
const MAX_REPOSITORY_INSPECTED_BYTES: usize = 512 * 1024 * 1024;
const MAX_FILE_INSPECTION_BYTES: usize = 256 * 1024;

#[derive(Debug)]
struct InventoryBudget {
    entries: usize,
    inspected_bytes: usize,
    max_entries: usize,
    max_inspected_bytes: usize,
}

pub fn build_repository_inventory(root: impl AsRef<Path>) -> Result<RepositoryInventory> {
    build_repository_inventory_with_limits(
        root.as_ref(),
        MAX_REPOSITORY_ENTRIES,
        MAX_REPOSITORY_INSPECTED_BYTES,
    )
}

fn build_repository_inventory_with_limits(
    root: &Path,
    max_entries: usize,
    max_inspected_bytes: usize,
) -> Result<RepositoryInventory> {
    let root = root
        .canonicalize()
        .with_context(|| format!("repository root {} does not exist", root.display()))?;
    if !root.is_dir() {
        anyhow::bail!("repository root {} is not a directory", root.display());
    }

    let mut builder = InventoryBuilder::default();
    let mut budget = InventoryBudget::new(max_entries, max_inspected_bytes);
    walk_repository(&root, &root, &mut builder, &mut budget)?;
    Ok(builder.finish(root_name(&root)))
}

impl InventoryBudget {
    fn new(max_entries: usize, max_inspected_bytes: usize) -> Self {
        Self {
            entries: 0,
            inspected_bytes: 0,
            max_entries,
            max_inspected_bytes,
        }
    }

    fn collect_dir(&mut self, read_dir: fs::ReadDir, dir: &Path) -> Result<Vec<fs::DirEntry>> {
        let remaining = self.max_entries.saturating_sub(self.entries);
        let entries = read_dir
            .take(remaining.saturating_add(1))
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("Could not enumerate {}", dir.display()))?;
        anyhow::ensure!(
            entries.len() <= remaining,
            "Repository inventory exceeded the {}-entry coverage limit at {}",
            self.max_entries,
            dir.display()
        );
        self.entries += entries.len();
        Ok(entries)
    }

    fn record_inspected_bytes(&mut self, bytes: usize, path: &Path) -> Result<()> {
        let next = self.inspected_bytes.saturating_add(bytes);
        anyhow::ensure!(
            next <= self.max_inspected_bytes,
            "Repository inventory exceeded the {}-byte inspection limit at {}",
            self.max_inspected_bytes,
            path.display()
        );
        self.inspected_bytes = next;
        Ok(())
    }
}

fn walk_repository(
    root: &Path,
    dir: &Path,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget,
) -> Result<()> {
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
    budget: &mut InventoryBudget,
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
    budget: &mut InventoryBudget,
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
    budget: &mut InventoryBudget,
) -> Result<()> {
    let generated_vendor = record_file_metadata(relative, name, builder);
    let Some(text) = read_text_prefix(path, MAX_FILE_INSPECTION_BYTES)? else {
        return Ok(());
    };
    budget.record_inspected_bytes(text.len(), path)?;
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
    fn refuses_to_label_an_entry_capped_walk_complete() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();
        fs::write(temp.path().join("b.rs"), "fn b() {}\n").unwrap();

        let error = build_repository_inventory_with_limits(temp.path(), 1, 1024).unwrap_err();

        assert!(error.to_string().contains("entry coverage limit"));
    }

    #[test]
    fn refuses_to_label_a_byte_capped_walk_complete() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("large.rs"), "x".repeat(64)).unwrap();

        let error = build_repository_inventory_with_limits(temp.path(), 10, 8).unwrap_err();

        assert!(error.to_string().contains("inspection limit"));
    }
}
