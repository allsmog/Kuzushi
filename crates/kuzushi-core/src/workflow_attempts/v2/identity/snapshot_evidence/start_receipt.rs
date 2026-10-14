//! Start-time source remains useful after a host-recovered interruption.
use super::*;

pub(super) fn read(
    target: &Path,
    run: &str,
    projection: &crate::run_lifecycle::RunProjection,
    producer: crate::run_lifecycle::RunItemId,
) -> SnapshotEvidence {
    let leaf = crate::artifact_contract::scan_start_source_artifact_leaf(producer);
    let references = projection
        .artifacts
        .values()
        .filter(|reference| {
            reference.producing_item_id == producer && reference.path.as_str() == leaf
        })
        .collect::<Vec<_>>();
    let reference = match references.as_slice() {
        [] => return SnapshotEvidence::Absent,
        [reference] => *reference,
        _ => return SnapshotEvidence::Invalid,
    };
    let value = match crate::run_artifacts::load_correlated_run_result_value(
        target, run, producer, reference,
    ) {
        Ok(value) => value,
        Err(_) => return SnapshotEvidence::Invalid,
    };
    verified_snapshot_claim(target, snapshot_claim(&value))
}
