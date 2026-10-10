//! Context samples are projections of the same bounded repository inventory.
use crate::repository_inventory::RepositoryInventory;
use anyhow::{Context, Result};

pub(super) const MAX_CONTEXT_SAMPLE_FILES: usize = 2_000;

#[derive(Debug)]
pub(super) struct ContextFileSample {
    pub(super) files_indexed: usize,
    pub(super) files_sample: Vec<String>,
    pub(super) walk_truncated: bool,
}

pub(super) fn inventory_file_sample(
    inventory: &RepositoryInventory,
    sample_limit: usize,
) -> Result<ContextFileSample> {
    let inspection = inventory
        .inspection
        .as_ref()
        .context("Context file sampling requires an inventory inspection receipt")?;
    let mut files = inspection.files.iter().collect::<Vec<_>>();
    files.sort_by_key(|path| (path.split('/').count(), *path));
    Ok(ContextFileSample {
        files_indexed: files.len(),
        files_sample: files.into_iter().take(sample_limit).cloned().collect(),
        walk_truncated: inventory.truncation.is_some(),
    })
}

#[cfg(test)]
mod tests;
