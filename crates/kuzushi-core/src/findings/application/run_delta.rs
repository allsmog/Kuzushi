use crate::findings::{Finding, FindingStore};
use crate::run_lifecycle::{
    FindingDeltaSummary, RunItemId, RunItemRecord, RunItemSource, RunItemStatus, RunItemV1,
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
/// typed store delta on the observing run. The insertion reports the delta it
/// produced, so a receipt names the findings the ledger holds rather than the
/// observations the run emitted; re-observed fingerprints count as updates
/// rather than additions.
pub(crate) fn commit_observed_findings(
    store: &FindingStore,
    observation: Option<&RunObservationHandle>,
    run_id: &str,
    target: &Path,
    findings: &[Finding],
) -> Result<()> {
    commit_observed_findings_with_status(
        store,
        observation,
        run_id,
        target,
        findings,
        RunItemStatus::Completed,
    )
}

pub(crate) fn commit_observed_findings_with_status(
    store: &FindingStore,
    observation: Option<&RunObservationHandle>,
    run_id: &str,
    target: &Path,
    findings: &[Finding],
    status: RunItemStatus,
) -> Result<()> {
    anyhow::ensure!(
        matches!(status, RunItemStatus::Completed | RunItemStatus::Partial),
        "Finding commits require a completed or partial outcome"
    );
    let delta = insert_run_findings(store, run_id, target, findings, status)?;
    emit_finding_delta(observation, store, findings, (delta.added, delta.updated))
}

/// The run's recorded findings count stays the number of observations it
/// emitted — the honest answer to "what did this run report" — while the
/// returned delta answers "what did the store gain".
fn insert_run_findings(
    store: &FindingStore,
    run_id: &str,
    target: &Path,
    findings: &[Finding],
    status: RunItemStatus,
) -> Result<crate::findings::persistence::CommittedFindingDelta> {
    store.with_run_lifecycle_status(run_id, target, || {
        let delta = store.insert_findings_measuring_delta(run_id, findings)?;
        Ok((delta, findings.len(), status))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_commit_status_is_refused_before_creating_a_run() {
        let root = tempfile::tempdir().unwrap();
        let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let error = commit_observed_findings_with_status(
            &store,
            None,
            "invalid-status",
            root.path(),
            &[],
            RunItemStatus::Canceled,
        )
        .unwrap_err();
        assert!(error.to_string().contains("completed or partial"));
        assert_eq!(store.run_status("invalid-status").unwrap(), None);
        assert!(store.list_all_findings().unwrap().is_empty());
    }
}
