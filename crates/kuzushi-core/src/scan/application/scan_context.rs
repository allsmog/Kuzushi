//! Freeze context once, then consume that exact revision without a live artifact reread.
use crate::scan::{ScanContextDocument, ScanContextRef};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

pub(crate) fn freeze_scan_context(root: &Path, input: &mut Value) -> Result<()> {
    if let Some(reference) = input.get("scanContextRef") {
        read_bound_scan_context(root, reference)?;
        return Ok(());
    }
    let document = ScanContextDocument {
        schema_version: 1,
        target: root.canonicalize()?.to_string_lossy().into_owned(),
        source_identity: crate::incremental_index::current_workspace_resume_identity(root)?,
        context_enrichment: crate::capabilities::agentic_sast::context_enrichment_scan_context(
            root,
        )?,
    };
    input["scanContextRef"] =
        serde_json::to_value(crate::scan::save_scan_context(root, &document)?)?;
    Ok(())
}

pub(crate) fn selected_scan_context(root: &Path, input: &Value) -> Result<Option<String>> {
    let Some(reference) = input.get("scanContextRef") else {
        return crate::capabilities::agentic_sast::context_enrichment_scan_context(root);
    };
    Ok(read_bound_scan_context(root, reference)?.and_then(|document| document.context_enrichment))
}

pub(crate) fn read_bound_scan_context(
    root: &Path,
    value: &Value,
) -> Result<Option<ScanContextDocument>> {
    if value.is_null() {
        return Ok(None);
    }
    let reference: ScanContextRef = serde_json::from_value(value.clone())
        .context("scanContextRef must be an exact frozen reference or explicit null")?;
    let document = crate::scan::load_scan_context(root, &reference)?;
    anyhow::ensure!(document.source_identity == crate::incremental_index::current_workspace_resume_identity(root)?,
        "Frozen supporting context was prepared on different source; prepare and approve a new plan");
    Ok(Some(document))
}

/// Authenticate historical text without requiring the source to remain current.
pub(crate) fn inspect_scan_context(root: &Path, input: &Value) -> Result<Option<String>> {
    let Some(value) = input.get("scanContextRef").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let reference: ScanContextRef = serde_json::from_value(value.clone())?;
    Ok(crate::scan::load_scan_context(root, &reference)?.context_enrichment)
}

#[cfg(test)]
mod tests;
