use super::prelude::*;
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
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        let name = entry.file_name().to_string_lossy().to_string();
        let relative = repo_relative(root, &path);

        if file_type.is_dir() {
            if ignored_dir(&name) {
                continue;
            }
            if let Some(classification) = generated_vendor_path(&relative, &name, true) {
                builder.add_generated_vendor_path(classification);
                continue;
            }
            walk_repository(root, &path, builder)?;
            continue;
        }

        if !file_type.is_file() {
            continue;
        }

        let generated_vendor = generated_vendor_path(&relative, &name, false);
        if let Some(classification) = generated_vendor.clone() {
            builder.add_generated_vendor_path(classification);
        }

        if let Some(kind) = manifest_kind(&relative, &name) {
            builder.add_manifest(&relative, kind);
        }
        if let Some(kind) = dependency_manifest_kind(&relative, &name) {
            builder.add_dependency_manifest(&relative, kind);
        }
        if let Some(kind) = config_file_kind(&relative, &name) {
            builder.add_config_file(&relative, kind);
        }

        let Some(text) = read_text_prefix(&path, 256 * 1024)? else {
            continue;
        };
        inspect_manifest_frameworks(&relative, &name, &text, builder);

        if generated_vendor.is_some() {
            continue;
        }

        let Some(language) = language_for_path(&path) else {
            continue;
        };
        builder.add_source_file(&relative, language, text.len() as u64);
        inspect_source_file(&relative, language, &text, builder);
    }

    Ok(())
}
