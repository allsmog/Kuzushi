//! Freeze a scanner projection once; execution consumes the saved bytes.
use crate::capabilities::threat_model::{ThreatModelRef, ThreatModelSelection};
use crate::scan::{ScanContextRef, ThreatModelDigestDocument};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::Path;

pub(crate) fn freeze_threat_model_digest(root: &Path, input: &mut Value, tool: &str) -> Result<()> {
    if !crate::modules::tool_uses_frozen_threat_context(tool, input) {
        return Ok(());
    }
    let selection = ThreatModelSelection::from_input(input)?;
    let ThreatModelSelection::Revision(reference) = selection else {
        anyhow::ensure!(
            selection.is_bound(),
            "Select exact context or explicit omission before freezing scanner context"
        );
        anyhow::ensure!(
            input.get("threatModelDigestRef").is_none(),
            "Frozen scanner context cannot accompany omitted context"
        );
        return Ok(());
    };
    if let Some(value) = input.get("threatModelDigestRef") {
        read_bound_threat_model_digest(root, value, &reference)?;
        return Ok(());
    }
    let document = capture_document(root, input, reference)?;
    input["threatModelDigestRef"] =
        serde_json::to_value(crate::scan::save_threat_model_digest(root, &document)?)?;
    Ok(())
}

fn capture_document(
    root: &Path,
    input: &Value,
    reference: ThreatModelRef,
) -> Result<ThreatModelDigestDocument> {
    let source_identity = crate::incremental_index::current_workspace_resume_identity(root)?;
    let preview = capture_preview(root, input, &reference)?;
    anyhow::ensure!(
        source_identity == crate::incremental_index::current_workspace_resume_identity(root)?,
        "Source changed while freezing scanner context; inspect the target and prepare a new plan"
    );
    Ok(ThreatModelDigestDocument {
        schema_version: 1,
        kind: "threat-model-digest".into(),
        target: root.canonicalize()?.to_string_lossy().into_owned(),
        source_identity,
        threat_model_ref: reference,
        preview,
    })
}

pub(crate) fn require_frozen_threat_model_digest(input: &Value, tool: &str) -> Result<()> {
    if !crate::modules::tool_uses_frozen_threat_context(tool, input) {
        return Ok(());
    }
    if matches!(
        ThreatModelSelection::from_input(input)?,
        ThreatModelSelection::Revision(_)
    ) {
        anyhow::ensure!(input.get("threatModelDigestRef").is_some(),
            "This approved work predates frozen scanner context; prepare and approve a replacement plan. Earlier attempts and spending remain recorded");
    }
    Ok(())
}

fn capture_preview(root: &Path, input: &Value, reference: &ThreatModelRef) -> Result<Value> {
    let document = crate::capabilities::threat_model::load_exact_threat_model(root, reference)?;
    let mut preview = crate::capabilities::threat_model::build_scanner_preview(&document);
    let text = crate::capabilities::agentic_sast::selected_threat_model_scan_context(root, input)?;
    preview["sha256"] = json!(text.as_deref().map(crate::prompt_content_sha256));
    preview["text"] = json!(text);
    preview["origin"] = json!("frozen-study");
    preview["limitations"][3] = json!("Execution rechecks source and lesson eligibility. A mismatch refuses work; saved scanner text is not rewritten.");
    Ok(preview)
}

pub(crate) fn inspect_threat_model_digest(
    root: &Path,
    value: &Value,
    reference: &ThreatModelRef,
) -> Result<ThreatModelDigestDocument> {
    let frozen: ScanContextRef = serde_json::from_value(value.clone())
        .context("threatModelDigestRef must be an exact frozen scanner-context reference")?;
    let document = crate::scan::load_threat_model_digest(root, &frozen)?;
    anyhow::ensure!(
        &document.threat_model_ref == reference,
        "Frozen scanner context belongs to a different context revision"
    );
    Ok(document)
}

pub(crate) fn read_bound_threat_model_digest(
    root: &Path,
    value: &Value,
    reference: &ThreatModelRef,
) -> Result<ThreatModelDigestDocument> {
    crate::capabilities::threat_model::load_selected_threat_model(
        root,
        &ThreatModelSelection::Revision(reference.clone()),
    )?;
    let document = inspect_threat_model_digest(root, value, reference)?;
    anyhow::ensure!(
        document.source_identity
            == crate::incremental_index::current_workspace_resume_identity(root)?,
        "Frozen scanner context was prepared on different source; prepare and approve a new plan"
    );
    Ok(document)
}

#[cfg(test)]
mod tests;
