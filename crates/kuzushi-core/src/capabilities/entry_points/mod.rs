//! Typed boundary for the deterministic entry-point catalog.

mod application;
mod collection;
mod domain;
mod persistence;
mod source_identity;
mod verification;

pub(crate) use application::*;
pub(crate) use domain::{
    EntryPointCatalog, EntryPointCatalogGrounding, EntryPointCatalogReceipt,
    EntryPointCatalogResolution, ENTRY_POINT_SELECTION_POLICY,
};
pub(crate) use verification::{
    resolve_entry_point_catalog_for_verification, VerificationCatalogGrounding,
};
#[cfg(test)]
pub(crate) use domain::{
    EntryPointCatalogProvenance, EntryPointRecord, ENTRY_POINTS_FILE, MAX_ENTRY_POINTS_BYTES,
};

pub use domain::EntryPointCatalogAuthentication;

/// Shared bound for both catalog producers and consumers.
pub const MAX_ENTRY_POINT_CATALOG_BYTES: usize = domain::MAX_ENTRY_POINTS_BYTES;

/// Authenticate a parsed entry-point catalog without duplicating its
/// canonical payload or target-identity rules in presentation crates.
pub fn authenticate_entry_point_catalog(
    target: &std::path::Path,
    document: &serde_json::Value,
) -> anyhow::Result<EntryPointCatalogAuthentication> {
    application::authenticate_catalog_document(target, document)
}

/// Authenticate one already-read catalog against the exact already-read raw
/// context snapshot. This stays file-I/O free so hydration workers can prove
/// derivation without reopening either artifact between validation and use.
pub fn authenticate_entry_point_catalog_against_context(
    target: &std::path::Path,
    catalog_document: &serde_json::Value,
    context_document: &serde_json::Value,
    context_content_sha256: &str,
) -> anyhow::Result<EntryPointCatalogAuthentication> {
    application::authenticate_catalog_against_context_documents(
        target,
        catalog_document,
        context_document,
        context_content_sha256,
    )
}

#[cfg(test)]
mod tests;
