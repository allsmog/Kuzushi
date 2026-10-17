use super::*;
use crate::run_artifacts::{
    PhaseStageReceipt, ScanArtifactDelta, ScanEngineStageOutcome, ScanStageData, ScanStageEngine,
    ScanStagePlan, ScanStageScope,
};

pub(super) struct LicenseScanReceipt {
    pub options: LicenseScanOptions,
    pub started: Instant,
    pub target_snapshot: PhaseTargetSnapshot,
}

impl LicenseScanReceipt {
    pub(super) fn build(
        self,
        run: &str,
        status: RunItemStatus,
        delta: ScanFindingDelta,
        findings: &[Finding],
        artifact: ScanArtifactDelta,
    ) -> PhaseStageReceipt {
        let complete = status == RunItemStatus::Completed;
        PhaseStageReceipt {
            phase: crate::WorkflowPhase::Scan,
            outcome: if complete {
                PhaseStageOutcome::Completed
            } else {
                PhaseStageOutcome::Partial
            },
            run_refs: vec![run.into()],
            scan: Some(self.scan_data(run, complete, delta, findings, artifact)),
        }
    }

    fn scan_data(
        self,
        run: &str,
        complete: bool,
        delta: ScanFindingDelta,
        findings: &[Finding],
        artifact: ScanArtifactDelta,
    ) -> ScanStageData {
        ScanStageData {
            scope: ScanStageScope {
                inspected_files: None,
                target: self.target_snapshot.target.clone(),
                paths: vec![],
            },
            plan: ScanStagePlan {
                selection: "direct".into(),
                engines: vec!["license-scan".into()],
            },
            engines: vec![engine(run, complete, self.options)],
            finding_delta: delta,
            severity_counts: crate::run_artifacts::scan_severity_counts(findings),
            artifact_delta: vec![artifact],
            duration_ms: self
                .started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            cost: None,
            target_snapshot: self.target_snapshot,
        }
    }
}

fn engine(run: &str, complete: bool, options: LicenseScanOptions) -> ScanStageEngine {
    ScanStageEngine {
        engine: "license-scan".into(),
        outcome: if complete {
            ScanEngineStageOutcome::Complete
        } else {
            ScanEngineStageOutcome::Partial
        },
        rule_ids: Some(crate::license_scan::enabled_rule_ids(options)),
        run_ref: Some(run.into()),
        detail: (!complete)
            .then(|| "Source verification was incomplete. Absence is not reassessment.".into()),
    }
}

pub(super) fn publish_committed(
    workspace: &crate::WorkspaceTarget,
    store: &crate::FindingStore,
    run: &str,
    status: RunItemStatus,
    delta: ScanFindingDelta,
    builder: LicenseScanReceipt,
) -> Result<PhaseStageReceipt> {
    let findings = store.list_findings_for_scan_id(run)?;
    let artifact = persist_observations(workspace, run, &findings)?;
    let stage = builder.build(run, status, delta, &findings, artifact);
    crate::run_artifacts::append_run_artifact_jsonl_value(
        workspace.root(),
        run,
        crate::run_artifacts::SAST_PHASE_STAGES_JSONL_FILE,
        &json!(stage),
    )?;
    let scan = stage
        .scan
        .as_ref()
        .context("Direct license coverage is unavailable")?;
    store.reconcile_completed_scan_coverage(run, stage.outcome, scan)?;
    Ok(stage)
}

fn persist_observations(
    workspace: &crate::WorkspaceTarget,
    run: &str,
    findings: &[Finding],
) -> Result<ScanArtifactDelta> {
    crate::run_artifacts::write_run_artifact_json(
        workspace.root(),
        run,
        "findings.json",
        "discovery observations",
        &json!(findings),
    )?;
    Ok(ScanArtifactDelta {
        run_ref: run.into(),
        path: "findings.json".into(),
    })
}
