//! Read the host Scan payload from its correlated result, before legacy files.
use super::*;
use crate::run_lifecycle::{
    ArtifactReference, CallKind, CallProjection, ProjectionHealth, RunProjection,
};

pub(super) enum ScanReceiptSource {
    Legacy,
    Typed(Option<PhaseStageReceipt>),
}

pub(super) fn load(target: &Path, run_id: &str) -> Result<ScanReceiptSource> {
    if !typed_history_exists(target, run_id)? {
        return Ok(ScanReceiptSource::Legacy);
    }
    // Read the summary first: publication after this snapshot must not make an
    // earlier unfinished projection look like contradictory completed evidence.
    let summary = load_run_summary_without_repair(target, run_id);
    let projection = crate::run_lifecycle::load_run_projection_unhydrated(target, run_id)?;
    anyhow::ensure!(
        matches!(projection.health, ProjectionHealth::Healthy),
        "Scan run history is damaged"
    );
    let Some(call) = parent_scan_call(&projection)? else {
        return Ok(source_without_scan_call(&projection));
    };
    let Some(reference) = call.result_artifact.as_ref() else {
        return unpublished_receipt(&projection, call, summary);
    };
    correlated_receipt(target, run_id, call, reference)
}

fn parent_scan_call(projection: &RunProjection) -> Result<Option<&CallProjection>> {
    let calls = projection
        .calls
        .values()
        .filter(|call| call.kind == CallKind::Tool && owns_scan_coverage(call.label.as_str()))
        .collect::<Vec<_>>();
    match calls.as_slice() {
        [] => Ok(None),
        [call] => Ok(Some(*call)),
        _ => anyhow::bail!("Scan run has ambiguous parent tool results"),
    }
}

fn unpublished_receipt(
    projection: &RunProjection,
    call: &CallProjection,
    summary: Result<RunSummary>,
) -> Result<ScanReceiptSource> {
    anyhow::ensure!(
        !call.status.is_terminal() && projection.terminal.is_none(),
        "Scan result has no authenticated artifact"
    );
    let summary = summary.context("Unpublished Scan result has no readable run summary")?;
    anyhow::ensure!(
        unfinished_summary(&summary),
        "Scan result has no authenticated artifact for its recorded run status"
    );
    // This establishes no coverage and makes no claim about process liveness.
    // Typed history still owns this run, so legacy sidecars remain ineligible.
    Ok(ScanReceiptSource::Typed(None))
}

fn unfinished_summary(summary: &RunSummary) -> bool {
    matches!(summary.status.as_str(), "pending" | "running")
        && summary.completed_at_unix.is_none()
        && summary.terminal_result_sha256.is_none()
}

fn correlated_receipt(
    target: &Path,
    run_id: &str,
    call: &CallProjection,
    reference: &ArtifactReference,
) -> Result<ScanReceiptSource> {
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
