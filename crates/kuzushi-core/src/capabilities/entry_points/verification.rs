use super::application::{
    ensure_current_entry_point_catalog, load_explicit_entry_point_catalog,
};
use super::domain::EntryPointCatalog;
use anyhow::{Context, Result};
use std::path::Path;

pub(crate) fn resolve_entry_point_catalog_for_verification(
    target: &Path,
) -> Result<Option<EntryPointCatalog>> {
    let current = ensure_current_entry_point_catalog(target)?;
    if current.catalog.is_some() {
        return Ok(current.catalog);
    }
    match std::fs::symlink_metadata(&current.path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("Could not inspect verification entry-point catalog"),
        Ok(_) => Ok(load_explicit_entry_point_catalog(target)?.catalog),
    }
}
