use super::CopyDurability;
use crate::BoundedReadFile;
use anyhow::Result;
use std::fs;
use std::path::Path;

#[derive(Clone, Copy)]
pub(super) struct CopyTarget<'a> {
    destination: &'a Path,
    durability: CopyDurability,
}

impl<'a> CopyTarget<'a> {
    pub(super) fn new(destination: &'a Path, durability: CopyDurability) -> Self {
        Self {
            destination,
            durability,
        }
    }
}

pub(super) fn prepare_empty_destination(
    root: &Path,
    destination: &Path,
    label: &str,
) -> Result<()> {
    let destination_metadata = fs::symlink_metadata(destination)?;
    anyhow::ensure!(
        destination_metadata.is_dir() && !destination_metadata.file_type().is_symlink(),
        "{label} copy destination is not a regular directory"
    );
    anyhow::ensure!(
        fs::read_dir(destination)?.next().is_none(),
        "{label} copy destination is not empty"
    );
    let source = fs::canonicalize(root)?;
    let destination = fs::canonicalize(destination)?;
    anyhow::ensure!(
        !source.starts_with(&destination) && !destination.starts_with(&source),
        "{label} copy destination overlaps its source"
    );
    Ok(())
}

pub(super) fn create_directory(target: Option<CopyTarget<'_>>, relative: &Path) -> Result<()> {
    let Some(target) = target else {
        return Ok(());
    };
    fs::create_dir(target.destination.join(relative))?;
    Ok(())
}

pub(super) fn digest_file(
    source: BoundedReadFile,
    target: Option<CopyTarget<'_>>,
    relative: &Path,
    permissions: fs::Permissions,
) -> Result<String> {
    let Some(target) = target else {
        return source.copy_to_with_sha256_hex(&mut std::io::sink());
    };
    let path = target.destination.join(relative);
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    let digest = source.copy_to_with_sha256_hex(&mut output)?;
    if target.durability == CopyDurability::Durable {
        output.sync_all()?;
    }
    drop(output);
    fs::set_permissions(path, permissions)?;
    Ok(digest)
}
