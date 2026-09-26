use crate::findings::{Finding, FindingStore};
use crate::run_lifecycle::{
    FindingDeltaSummary, RunItemId, RunItemRecord, RunItemSource, RunItemV1,
    RunObservationHandle, SafeText, MAX_FINDING_ID_SAMPLES,
};
use crate::ToolExecutionContext;
use anyhow::Result;
use std::path::Path;

/// Emit only after the store commit succeeds. Receipts use the last delta
/// per run so an enclosing scan can supersede its engines' observations.
pub(crate) fn emit_persisted_finding_delta(
    ctx: &ToolExecutionContext<'_>,
    findings: &[Finding],
    counts: (u64, u64),
) -> Result<()> {
    let Some(store) = ctx.findings_store else {
        return Ok(());
    };
    emit_finding_delta(ctx.run_observation().as_ref(), store, findings, counts)
}

/// Record a committed store delta on the observing run (a no-op for an
/// unobserved run). A zero delta is still a real observation: it is what lets
/// a clean run offer Report truthfully.
pub(crate) fn emit_finding_delta(
    observation: Option<&RunObservationHandle>,
    store: &FindingStore,
    findings: &[Finding],
    counts: (u64, u64),
) -> Result<()> {
    let Some(observation) = observation else {
        return Ok(());
    };
    let delta = finding_delta_summary(store, findings, counts)?;
    observation.emit(RunItemRecord::new(
        RunItemId::new(),
        RunItemSource::Persistence,
        RunItemV1::FindingDelta { delta },
    ))
}

/// Commit one tool run's findings under the run lifecycle, then record the
/// typed store delta on the observing run. Added/updated counts are measured
/// against the store before insertion, so re-observed fingerprints count as
/// updates rather than additions.
pub(crate) fn commit_observed_findings(
    store: &FindingStore,
    observation: Option<&RunObservationHandle>,
    run_id: &str,
    target: &Path,
    findings: &[Finding],
) -> Result<()> {
    let counts = store.fingerprint_delta(findings)?;
    insert_run_findings(store, run_id, target, findings)?;
    emit_finding_delta(observation, store, findings, counts)
}

fn insert_run_findings(
    store: &FindingStore,
    run_id: &str,
    target: &Path,
    findings: &[Finding],
) -> Result<()> {
    store.with_run_lifecycle(run_id, target, || {
        for finding in findings {
            store.insert_finding(run_id, finding)?;
        }
        Ok(((), findings.len()))
    })
}

fn finding_delta_summary(
    store: &FindingStore,
    findings: &[Finding],
    (added, updated): (u64, u64),
) -> Result<FindingDeltaSummary> {
    Ok(FindingDeltaSummary {
        added,
        updated,
        removed: 0,
        store_watermark: SafeText::operator_visible(
            store.projection_meta()?.applied_seq.to_string(),
        ),
        finding_id_samples: findings
            .iter()
            .take(MAX_FINDING_ID_SAMPLES)
            .map(|finding| SafeText::operator_visible(&finding.fingerprint))
            .collect(),
    })
}
