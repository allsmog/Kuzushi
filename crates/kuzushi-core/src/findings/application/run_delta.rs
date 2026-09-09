use crate::findings::Finding;
use crate::run_lifecycle::{
    FindingDeltaSummary, RunItemId, RunItemRecord, RunItemSource, RunItemV1, SafeText,
    MAX_FINDING_ID_SAMPLES,
};
use crate::ToolExecutionContext;
use anyhow::Result;

/// Emit only after the store commit succeeds. Receipts use the last delta
/// per run so an enclosing scan can supersede its engines' observations.
pub(crate) fn emit_persisted_finding_delta(
    ctx: &ToolExecutionContext<'_>,
    findings: &[Finding],
    counts: (u64, u64),
) -> Result<()> {
    let (Some(observation), Some(store)) = (ctx.run_observation(), ctx.findings_store) else {
        return Ok(());
    };
    let delta = FindingDeltaSummary {
        added: counts.0,
        updated: counts.1,
        removed: 0,
        store_watermark: SafeText::operator_visible(
            store.projection_meta()?.applied_seq.to_string(),
        ),
        finding_id_samples: findings
            .iter()
            .take(MAX_FINDING_ID_SAMPLES)
            .map(|finding| SafeText::operator_visible(&finding.fingerprint))
            .collect(),
    };
    observation.emit(RunItemRecord::new(
        RunItemId::new(),
        RunItemSource::Persistence,
        RunItemV1::FindingDelta { delta },
    ))
}
