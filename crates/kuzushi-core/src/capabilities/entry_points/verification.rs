use super::application::{
    ensure_current_entry_point_catalog, load_explicit_entry_point_catalog,
};
use super::domain::EntryPointCatalog;
use super::source_identity::stale_source_disclosure;
use anyhow::{Context, Result};
use std::path::Path;

/// What verification can currently prove about the entry-point catalog.
/// `StaleContext` is a real, disclosable state — not an error — so a
/// threat model stays verifiable after the target moves on.
#[derive(Debug)]
pub(crate) enum VerificationCatalogGrounding {
    Catalog(Box<EntryPointCatalog>),
    /// No context snapshot and no catalog artifact to ground against.
    Absent,
    /// A context snapshot exists but no longer describes the current target.
    StaleContext(String),
}

pub(crate) fn resolve_entry_point_catalog_for_verification(
    target: &Path,
) -> Result<VerificationCatalogGrounding> {
    let current = match ensure_current_entry_point_catalog(target) {
        Ok(current) => current,
        Err(error) => return degraded_or_propagated(error),
    };
    if let Some(catalog) = current.catalog {
        return Ok(VerificationCatalogGrounding::Catalog(Box::new(catalog)));
    }
    match std::fs::symlink_metadata(&current.path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(VerificationCatalogGrounding::Absent)
        }
        Err(error) => Err(error).context("Could not inspect verification entry-point catalog"),
        Ok(_) => explicit_catalog_grounding(target),
    }
}

/// Only a stale context snapshot degrades. An explicitly authored catalog
/// that no longer matches the target, corruption, and I/O still fail loudly.
fn degraded_or_propagated(error: anyhow::Error) -> Result<VerificationCatalogGrounding> {
    match stale_source_disclosure(&error) {
        Some(disclosure) => Ok(VerificationCatalogGrounding::StaleContext(disclosure)),
        None => Err(error),
    }
}

fn explicit_catalog_grounding(target: &Path) -> Result<VerificationCatalogGrounding> {
    let resolution = load_explicit_entry_point_catalog(target)?;
    Ok(match resolution.catalog {
        Some(catalog) => VerificationCatalogGrounding::Catalog(Box::new(catalog)),
        None => VerificationCatalogGrounding::Absent,
    })
}
