//! Exact membership can be known within a partial, source-bound inventory.
use super::*;
use crate::workspace::{InventoryInspection, RepositoryInventory};

const MAX_DISCLOSED_PATHS: usize = 16;

pub(super) fn resolve(paths: &[String], ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let (source, inventory, hash) = crate::workspace::load_or_build_scan_scope_inventory(ctx)?;
    let mut receipt = selected_membership(paths, &inventory)?;
    receipt["inventoryHash"] = json!(hash);
    receipt["source"] = json!(source);
    Ok(receipt)
}

fn selected_membership(paths: &[String], inventory: &RepositoryInventory) -> Result<Value> {
    let inspection = inventory
        .inspection
        .as_ref()
        .context("Evidence selection needs authenticated inventory membership")?;
    let complete = inspection
        .enumeration_complete
        .context("Evidence inventory enumeration extent is unknown; rebuild inventory")?;
    let members = inspection.files.iter().collect::<BTreeSet<_>>();
    let missing = paths
        .iter()
        .filter(|path| !members.contains(path))
        .collect::<Vec<_>>();
    anyhow::ensure!(missing.is_empty(),
        "Selected files are absent from the bounded inventory: {missing:?}. Choose enumerated files or rebuild inventory; no context request was made");
    Ok(inspection_receipt(inspection, inventory, complete))
}

fn inspection_receipt(
    inspection: &InventoryInspection,
    inventory: &RepositoryInventory,
    complete: bool,
) -> Value {
    json!({"schemaVersion":1,"selectedMembershipKnown":true,"enumerationComplete":complete,
        "enumeration":inspection.enumeration,"enumeratedFiles":inspection.files.len(),
        "entries":inspection.entries,"maxEntries":inspection.max_entries,
        "inspectedBytes":inspection.inspected_bytes,"maxInspectedBytes":inspection.max_inspected_bytes,
        "maxFileInspectionBytes":inspection.max_file_inspection_bytes,"truncation":inventory.truncation,
        "omittedPathCount":inspection.omitted_paths.len(),
        "omittedPaths":inspection.omitted_paths.iter().take(MAX_DISCLOSED_PATHS).collect::<Vec<_>>(),
        "additionalOmittedPaths":inspection.omitted_paths.len().saturating_sub(MAX_DISCLOSED_PATHS),
        "truncatedFileCount":inspection.truncated_files.len(),
        "truncatedFiles":inspection.truncated_files.iter().take(MAX_DISCLOSED_PATHS).collect::<Vec<_>>(),
        "additionalTruncatedFiles":inspection.truncated_files.len().saturating_sub(MAX_DISCLOSED_PATHS),
        "completeRepositoryCoverage":false})
}

#[cfg(test)]
mod tests;
