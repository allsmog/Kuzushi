//! Verify positive observations without treating unseen entry points as absent.
use super::*;

pub(super) fn grounding(
    catalog: &crate::capabilities::entry_points::EntryPointCatalog,
    receipt: Option<&CatalogCoverageReceipt>,
) -> Result<VerificationGrounding> {
    authenticate_partial_receipt(catalog, receipt)?;
    let disclosure = catalog
        .snapshot_coverage
        .disclosure()
        .context("Partial catalog has no coverage disclosure")?;
    Ok(VerificationGrounding {
        surfaces: catalog
            .entry_points
            .iter()
            .map(|entry| entry.surface.clone())
            .collect(),
        source: PARTIAL_CATALOG_GROUNDING,
        degraded: Some(format!(
            "{disclosure}. Only recorded entry points were checked; unseen entry points remain unknown."
        )),
    })
}

fn authenticate_partial_receipt(
    catalog: &crate::capabilities::entry_points::EntryPointCatalog,
    receipt: Option<&CatalogCoverageReceipt>,
) -> Result<()> {
    let Some(receipt) = receipt.filter(|receipt| !receipt.is_unavailable()) else {
        return Ok(());
    };
    anyhow::ensure!(
        receipt.status == "partial",
        "Complete-catalog receipts cannot be verified from partial entry-point coverage"
    );
    authenticate_receipt_catalog(receipt, catalog)
}

pub(super) fn require_complete_receipt(receipt: Option<&CatalogCoverageReceipt>) -> Result<()> {
    anyhow::ensure!(
        receipt.is_none_or(|receipt| receipt.status != "partial"),
        "Partial-catalog receipts require their authenticated partial entry-point catalog"
    );
    Ok(())
}
