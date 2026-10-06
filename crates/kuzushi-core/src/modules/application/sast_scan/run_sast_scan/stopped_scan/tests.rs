use super::*;

fn job(disposition: NativeEngineDisposition, gaps: &[&str]) -> crate::scan::NativeEngineCoverage {
    crate::scan::NativeEngineCoverage {
        engine: "semgrep".into(),
        scope: None,
        findings_count: 0,
        disposition,
        scan_errors: gaps.iter().map(|gap| (*gap).into()).collect(),
    }
}

#[test]
fn stopped_engine_projection_distinguishes_completed_failed_partial_and_unstarted_work() {
    use NativeEngineDisposition::*;
    let complete = job(Complete, &[]);
    let skipped = job(NotStarted, &[]);
    let failed = job(Failed, &["labeled error"]);
    let gap = job(Complete, &["unread file"]);
    assert_eq!(stopped_engine_outcome(&[]), ScanEngineStageOutcome::Skipped);
    assert_eq!(
        stopped_engine_outcome(&[&complete]),
        ScanEngineStageOutcome::Complete
    );
    assert_eq!(
        stopped_engine_outcome(&[&skipped]),
        ScanEngineStageOutcome::Skipped
    );
    assert_eq!(
        stopped_engine_outcome(&[&complete, &skipped]),
        ScanEngineStageOutcome::Partial
    );
    assert_eq!(
        stopped_engine_outcome(&[&complete, &failed]),
        ScanEngineStageOutcome::Failed
    );
    assert_eq!(
        stopped_engine_outcome(&[&gap]),
        ScanEngineStageOutcome::Partial
    );
    for disposition in [Canceled, Interrupted] {
        assert_eq!(
            stopped_engine_outcome(&[&job(disposition, &["stopped"])]),
            ScanEngineStageOutcome::Failed
        );
    }
}

#[test]
fn cancellation_changes_only_the_stopped_task_not_completed_or_unstarted_jobs() {
    use crate::run_lifecycle::RunItemStatus;
    use crate::scan::CancellationDisposition::Canceled;
    assert_eq!(
        stopped_task_status(ScanEngineStageOutcome::Failed, Some(Canceled)),
        RunItemStatus::Canceled
    );
    assert_eq!(
        stopped_task_status(ScanEngineStageOutcome::Complete, Some(Canceled)),
        RunItemStatus::Completed
    );
    assert_eq!(
        stopped_task_status(ScanEngineStageOutcome::Skipped, Some(Canceled)),
        RunItemStatus::Skipped
    );
}
