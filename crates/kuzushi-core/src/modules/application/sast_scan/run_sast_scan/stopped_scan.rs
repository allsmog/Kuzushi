use super::*;
use crate::scan::{native_scan_failure, NativeEngineDisposition, NativeScanFailure};

pub(super) fn record(
    input: &SastScanExecutionInput<'_>,
    artifacts: &SastRunArtifacts,
    baseline: &ScanStageBaseline,
    error: &anyhow::Error,
) -> Result<()> {
    let failure = native_scan_failure(error);
    let findings = retained_findings(input, artifacts, failure)?;
    let run_refs = stopped_run_refs(input.primary_run_id, failure);
    let delta = scan_finding_delta(&baseline.finding_fingerprints, &findings);
    let scan = ScanStageData {
        scope: scan_stage_scope(input.workspace, input.options),
        plan: scan_stage_plan(input.input, &baseline.selected),
        engines: stopped_engines(&baseline.selected, failure, error),
        finding_delta: delta,
        severity_counts: scan_severity_counts(&findings),
        artifact_delta: scan_artifact_delta(
            input.workspace.root(),
            &run_refs,
            &baseline.artifacts,
        )?,
        duration_ms: elapsed_millis(baseline.started),
        cost: None,
        target_snapshot: baseline.target_snapshot.clone(),
    };
    settle_tasks(input, &baseline.lifecycle_tasks, &scan.engines)?;
    record_sast_scan_stage(artifacts, PhaseStageOutcome::Failed, run_refs, scan)?;
    input.emit_finding_delta(delta, &findings)
}

fn retained_findings(
    input: &SastScanExecutionInput<'_>,
    artifacts: &SastRunArtifacts,
    failure: Option<&NativeScanFailure>,
) -> Result<Vec<crate::findings::Finding>> {
    let Some(failure) = failure else {
        return Ok(Vec::new());
    };
    let findings = input
        .store
        .list_findings_for_scan_id(&failure.report.run.id)?;
    artifacts.write_json(
        "native-coverage.json",
        "native scan coverage",
        &json!(failure.report.coverage),
    )?;
    artifacts.write_json(
        "findings.json",
        "retained discovery observations",
        &json!(findings),
    )?;
    Ok(findings)
}

fn stopped_run_refs(primary: &str, failure: Option<&NativeScanFailure>) -> Vec<String> {
    let mut refs = vec![primary.to_string()];
    if let Some(failure) = failure {
        if failure.report.run.id != primary {
            refs.push(failure.report.run.id.clone());
        }
    }
    refs
}

fn stopped_engines(
    selected: &SastTaskSelection,
    failure: Option<&NativeScanFailure>,
    error: &anyhow::Error,
) -> Vec<ScanStageEngine> {
    let Some(failure) = failure else {
        return vec![ScanStageEngine {
            engine: "sast:scan".into(),
            outcome: ScanEngineStageOutcome::Failed,
            run_ref: None,
            detail: Some(format!(
                "pipeline stopped before complete engine outcomes were available: {error}"
            )),
        }];
    };
    let mut engines = selected
        .planned_engine_ids()
        .iter()
        .map(|engine| stopped_engine(engine, failure))
        .collect::<Vec<_>>();
    if failure
        .report
        .coverage
        .engines
        .iter()
        .all(|job| job.disposition == NativeEngineDisposition::Complete)
    {
        engines.push(ScanStageEngine {
            engine: "sast:scan".into(),
            outcome: ScanEngineStageOutcome::Failed,
            run_ref: Some(failure.report.run.id.clone()),
            detail: Some(format!(
                "Discovery observations retained; later scan processing stopped: {}",
                failure.cause
            )),
        });
    }
    engines
}

fn stopped_engine(engine: &str, failure: &NativeScanFailure) -> ScanStageEngine {
    let jobs = failure
        .report
        .coverage
        .engines
        .iter()
        .filter(|job| job.engine == engine)
        .collect::<Vec<_>>();
    let outcome = stopped_engine_outcome(&jobs);
    let detail = match outcome {
        ScanEngineStageOutcome::Skipped => {
            Some("Not started: scan plan stopped. No automatic retry.".into())
        }
        _ => failure.report.coverage.engine_detail(engine),
    };
    ScanStageEngine {
        engine: engine.into(),
        outcome,
        run_ref: (!jobs.is_empty()).then(|| failure.report.run.id.clone()),
        detail,
    }
}

fn stopped_engine_outcome(jobs: &[&crate::scan::NativeEngineCoverage]) -> ScanEngineStageOutcome {
    use NativeEngineDisposition::NotStarted;
    if jobs.iter().all(|job| job.disposition == NotStarted) {
        return ScanEngineStageOutcome::Skipped;
    }
    if jobs.iter().any(|job| {
        matches!(
            job.disposition,
            NativeEngineDisposition::Failed
                | NativeEngineDisposition::Canceled
                | NativeEngineDisposition::Interrupted
        )
    }) {
        return ScanEngineStageOutcome::Failed;
    }
    if jobs
        .iter()
        .any(|job| job.disposition == NotStarted || !job.scan_errors.is_empty())
    {
        return ScanEngineStageOutcome::Partial;
    }
    ScanEngineStageOutcome::Complete
}

fn settle_tasks(
    input: &SastScanExecutionInput<'_>,
    tasks: &[crate::run_lifecycle::ObservedRunTask],
    engines: &[ScanStageEngine],
) -> Result<()> {
    for task in tasks {
        if let Some(engine) = engines.iter().find(|engine| engine.engine == task.title()) {
            task.update(
                stopped_task_status(engine.outcome, sast_cancellation_disposition(input.ctx)),
                engine.detail.as_deref(),
            )?;
        } else {
            let (status, detail) =
                scan_pipeline_stop_task_terminal(sast_cancellation_disposition(input.ctx));
            task.update(status, Some(detail))?;
        }
    }
    Ok(())
}

fn stopped_task_status(
    outcome: ScanEngineStageOutcome,
    cancellation: Option<crate::scan::CancellationDisposition>,
) -> crate::run_lifecycle::RunItemStatus {
    if outcome != ScanEngineStageOutcome::Failed {
        return scan_task_status(outcome);
    }
    match cancellation {
        Some(crate::scan::CancellationDisposition::Canceled) => {
            crate::run_lifecycle::RunItemStatus::Canceled
        }
        Some(crate::scan::CancellationDisposition::Interrupted) => {
            crate::run_lifecycle::RunItemStatus::Interrupted
        }
        None => crate::run_lifecycle::RunItemStatus::Failed,
    }
}

#[cfg(test)]
mod tests;
