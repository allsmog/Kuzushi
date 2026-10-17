//! Read the host Scan payload from its correlated result, before legacy files.
use super::*;
use crate::run_lifecycle::{CallKind, ProjectionHealth};

pub(super) enum ScanReceiptSource {
    Legacy,
    Typed(Option<PhaseStageReceipt>),
}

pub(super) fn load(target: &Path, run_id: &str) -> Result<ScanReceiptSource> {
    if !typed_history_exists(target, run_id)? {
        return Ok(ScanReceiptSource::Legacy);
    }
    let projection = crate::run_lifecycle::load_run_projection_unhydrated(target, run_id)?;
    anyhow::ensure!(
        matches!(projection.health, ProjectionHealth::Healthy),
        "Scan run history is damaged"
    );
    let calls = projection
        .calls
        .values()
        .filter(|call| call.kind == CallKind::Tool && owns_scan_coverage(call.label.as_str()))
        .collect::<Vec<_>>();
    let call = match calls.as_slice() {
        [] => return Ok(source_without_scan_call(&projection)),
        [call] => *call,
        _ => anyhow::bail!("Scan run has ambiguous parent tool results"),
    };
    let reference = call
        .result_artifact
        .as_ref()
        .context("Scan result has no authenticated artifact")?;
    let result = crate::run_artifacts::load_correlated_run_result_value(
        target,
        run_id,
        reference.producing_item_id,
        reference,
    )?;
    let receipt = scan_receipt(&result)?;
    validate_direct(
        target,
        run_id,
        call.label.as_str(),
        &result,
        receipt.as_ref(),
    )?;
    Ok(ScanReceiptSource::Typed(receipt))
}

fn validate_direct(
    target: &Path,
    run: &str,
    tool: &str,
    result: &Value,
    receipt: Option<&PhaseStageReceipt>,
) -> Result<()> {
    match tool {
        "license-scan:scan" => direct_license::validate(result, receipt),
        "iac-scan:scan" | "cargo-audit:scan" => {
            direct_native::validate(target, run, tool, result, receipt)
        }
        _ => Ok(()),
    }
}

fn owns_scan_coverage(tool: &str) -> bool {
    matches!(
        tool,
        "sast:scan" | "license-scan:scan" | "iac-scan:scan" | "cargo-audit:scan"
    )
}

fn source_without_scan_call(projection: &crate::run_lifecycle::RunProjection) -> ScanReceiptSource {
    // Summary-only lifecycle rows predate correlated tool results.
    if projection.calls.is_empty() {
        return ScanReceiptSource::Legacy;
    }
    ScanReceiptSource::Typed(None)
}

fn typed_history_exists(target: &Path, run_id: &str) -> Result<bool> {
    let path = checked_run_artifact_path(target, run_id, "items.jsonl")?;
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn scan_receipt(result: &Value) -> Result<Option<PhaseStageReceipt>> {
    let Some(value) = result.pointer("/data/phaseStages") else {
        return Ok(None);
    };
    let receipts: Vec<PhaseStageReceipt> = serde_json::from_value(value.clone())
        .context("authenticated Scan result has malformed phase stages")?;
    Ok(receipts
        .into_iter()
        .rev()
        .find(|receipt| receipt.phase == WorkflowPhase::Scan && receipt.scan.is_some()))
}

#[cfg(test)]
mod tests;

mod direct_license;
mod direct_native;
