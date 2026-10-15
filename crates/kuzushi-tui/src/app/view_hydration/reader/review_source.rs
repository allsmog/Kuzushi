use super::*;

pub(super) fn read_review_source(
    target: &Path,
    key: &ViewHydrationKey,
) -> Option<ViewHydrationValue> {
    let ViewHydrationKey::FindingReviewSource {
        stable_fp,
        decision_id,
        decision_watermark,
        observation_watermark,
    } = key
    else {
        return None;
    };
    let value = read_source(
        target,
        stable_fp,
        *decision_watermark,
        *observation_watermark,
        *decision_id,
    )
    .map_err(|error| error.to_string());
    Some(ViewHydrationValue::FindingReviewSource(value))
}

fn read_source(
    target: &Path,
    stable_fp: &str,
    decision: u64,
    observed: Option<u64>,
    decision_id: i64,
) -> anyhow::Result<Option<FindingReviewSource>> {
    let workspace = kuzushi_core::WorkspaceTarget::new(target)?;
    let Some(basis) = kuzushi_core::workspace::read_finding_review_source(
        &workspace, stable_fp, decision, observed,
    )?
    else {
        return Ok(None);
    };
    let decided_revision = recorded_revision(target, &basis.run_id);
    let later_revision = basis
        .later_observation
        .as_ref()
        .map(|later| recorded_revision(target, &later.run_id));
    Ok(Some(FindingReviewSource {
        reviewed_source: kuzushi_core::workspace::read_decision_reviewed_source(
            &workspace,
            decision_id,
        )?,
        basis,
        decided_revision,
        later_revision,
    }))
}

fn recorded_revision(target: &Path, run_id: &str) -> RecordedSourceRevision {
    match kuzushi_core::run_artifacts::load_run_summary_without_repair(target, run_id) {
        Ok(summary) => summary
            .target_git
            .map(RecordedSourceRevision::Known)
            .unwrap_or(RecordedSourceRevision::NotRecorded),
        Err(_) => RecordedSourceRevision::Unreadable,
    }
}

#[cfg(test)]
mod tests;
