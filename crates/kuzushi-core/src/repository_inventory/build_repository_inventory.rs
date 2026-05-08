use super::*;

pub fn build_repository_inventory(root: impl AsRef<Path>) -> Result<RepositoryInventory> {
    let root = root
        .as_ref()
        .canonicalize()
        .with_context(|| format!("repository root {} does not exist", root.as_ref().display()))?;
    if !root.is_dir() {
        anyhow::bail!("repository root {} is not a directory", root.display());
    }

    let mut builder = InventoryBuilder::default();
    walk_repository(&root, &root, &mut builder)?;
    Ok(builder.finish(root_name(&root)))
}

pub(crate) fn walk_repository(
    root: &Path,
    dir: &Path,
    builder: &mut InventoryBuilder,
) -> Result<()> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        walk_repository_entry(root, entry, builder)?;
    }

    Ok(())
}

fn walk_repository_entry(
    root: &Path,
    entry: fs::DirEntry,
    builder: &mut InventoryBuilder,
) -> Result<()> {
    let path = entry.path();
    let Ok(file_type) = entry.file_type() else {
        return Ok(());
    };
    let name = entry.file_name().to_string_lossy().to_string();
    let relative = repo_relative(root, &path);

    if file_type.is_dir() {
        return walk_repository_dir(root, &path, &relative, &name, builder);
    }
    if file_type.is_file() {
        walk_repository_file(&path, &relative, &name, builder)?;
    }
    Ok(())
}

fn walk_repository_dir(
    root: &Path,
    path: &Path,
    relative: &str,
    name: &str,
    builder: &mut InventoryBuilder,
) -> Result<()> {
    if ignored_dir(name) {
        return Ok(());
    }
    if let Some(classification) = generated_vendor_path(relative, name, true) {
        builder.add_generated_vendor_path(classification);
        return Ok(());
    }
    walk_repository(root, path, builder)
}

fn walk_repository_file(
    path: &Path,
    relative: &str,
    name: &str,
    builder: &mut InventoryBuilder,
) -> Result<()> {
    let generated_vendor = record_file_metadata(relative, name, builder);
    let Some(text) = read_text_prefix(path, 256 * 1024)? else {
        return Ok(());
    };
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
