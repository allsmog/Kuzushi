//! Keep generated partial context inactive, authenticated and visible.
use super::*;

pub(super) fn require_inactive(
    catalog: Option<&crate::capabilities::entry_points::EntryPointCatalog>,
    activate: Option<bool>,
) -> Result<()> {
    if catalog.is_some_and(|catalog| catalog.snapshot_coverage.is_partial()) {
        anyhow::ensure!(
            activate == Some(false),
            "Partial entry-point coverage requires activate=false and explicit Map review before use"
        );
    }
    Ok(())
}

pub(super) fn receipt_status<'a>(
    catalog: &crate::capabilities::entry_points::EntryPointCatalog,
    status: &'a str,
) -> &'a str {
    if catalog.snapshot_coverage.is_partial() {
        return "partial";
    }
    status
}

pub(super) fn stamp_verification(document: &mut Value, input: &BuildInput) -> Result<()> {
    if !has_partial_receipt(document) {
        return Ok(());
    }
    let verification = verify_threat_model_document_with_roots(document, &input.roots)?;
    super::stamp_verification(document, &verification);
    Ok(())
}

pub(super) fn warning(document: &Value, target: &Path) -> Option<String> {
    has_partial_receipt(document)
        .then(|| verification_warning(document, target))
        .flatten()
}

fn has_partial_receipt(document: &Value) -> bool {
    document
        .pointer("/provenance/entryPointCatalog/status")
        .and_then(Value::as_str)
        == Some("partial")
}

pub(crate) fn prompt_warning(grounding: &PromptGrounding) -> String {
    if grounding.entry_point_catalog.receipt.status != "partial" {
        return String::new();
    }
    "Entry-point coverage is partial. Only recorded observations are available. Preserve the supplied inspection limits and open questions; unseen entry points remain unknown. Do not claim complete repository coverage or infer absence from missing observations.".into()
}
