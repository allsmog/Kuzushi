use super::*;
use crate::module_result::{tool_result_status, ToolResultStatus};
use crate::modules::autonomy::WorkflowPhase;
use crate::run_artifacts::{PhaseStageOutcome, PhaseStageReceipt, ScanStageData};

pub(in crate::modules) type SastPhaseStageOutcome = PhaseStageOutcome;

impl From<ToolResultStatus> for PhaseStageOutcome {
    fn from(status: ToolResultStatus) -> Self {
        match status {
            ToolResultStatus::Completed => Self::Completed,
            ToolResultStatus::Partial => Self::Partial,
            ToolResultStatus::Failed => Self::Failed,
            ToolResultStatus::Skipped => Self::Skipped,
        }
    }
}

pub(in crate::modules) fn record_sast_phase_stage(
    artifacts: &SastRunArtifacts,
    phase: WorkflowPhase,
    outcome: SastPhaseStageOutcome,
    run_refs: Vec<String>,
) -> Result<()> {
    let receipt = PhaseStageReceipt {
        phase,
        outcome,
        run_refs: deduplicated_run_refs(run_refs),
        scan: None,
    };
    artifacts.append_jsonl(SAST_PHASE_STAGES_JSONL_FILE, &json!(receipt))
}

pub(in crate::modules) fn record_sast_scan_stage(
    artifacts: &SastRunArtifacts,
    outcome: SastPhaseStageOutcome,
    run_refs: Vec<String>,
    scan: ScanStageData,
) -> Result<()> {
    let receipt = PhaseStageReceipt {
        phase: WorkflowPhase::Scan,
        outcome,
        run_refs: deduplicated_run_refs(run_refs),
        scan: Some(scan),
    };
    artifacts.append_jsonl(SAST_PHASE_STAGES_JSONL_FILE, &json!(receipt))
}

pub(in crate::modules) fn record_sast_phase_output(
    artifacts: &SastRunArtifacts,
    phase: WorkflowPhase,
    primary_run_id: &str,
    output: &Value,
) -> Result<()> {
    record_sast_phase_stage(
        artifacts,
        phase,
        tool_result_status(output).into(),
        output_run_refs(primary_run_id, output),
    )
}

pub(in crate::modules) fn load_sast_phase_stages(
    artifacts: &SastRunArtifacts,
) -> Result<Vec<Value>> {
    let label = phase_stage_artifact_label()?;
    let body = artifacts.read_text(SAST_PHASE_STAGES_JSONL_FILE, label)?;
    let receipts = parse_phase_stage_receipts(&body)?;
    Ok(WorkflowPhase::ORDER
        .iter()
        .filter_map(|phase| aggregate_phase_receipts(*phase, &receipts))
        .collect())
}

fn phase_stage_artifact_label() -> Result<&'static str> {
    crate::run_artifacts::scan_pipeline_artifact_spec(SAST_PHASE_STAGES_JSONL_FILE)
        .map(|spec| spec.label)
        .context("SAST phase stage artifact must be declared")
}

fn parse_phase_stage_receipts(body: &str) -> Result<Vec<PhaseStageReceipt>> {
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("invalid SAST phase stage receipt"))
        .collect()
}

fn aggregate_phase_receipts(phase: WorkflowPhase, receipts: &[PhaseStageReceipt]) -> Option<Value> {
    let matching = receipts
        .iter()
        .filter(|receipt| receipt.phase == phase)
        .collect::<Vec<_>>();
    let first = matching.first()?;
    let outcome = matching
        .iter()
        .skip(1)
        .fold(first.outcome, |current, receipt| {
            merge_stage_outcome(current, receipt.outcome)
        });
    let run_refs = matching
        .iter()
        .flat_map(|receipt| receipt.run_refs.iter().cloned())
        .collect();
    let scan = matching
        .iter()
        .rev()
        .find_map(|receipt| receipt.scan.clone());
    Some(json!(PhaseStageReceipt {
        phase,
        outcome,
        run_refs: deduplicated_run_refs(run_refs),
        scan,
    }))
}

fn merge_stage_outcome(
    current: SastPhaseStageOutcome,
    next: SastPhaseStageOutcome,
) -> SastPhaseStageOutcome {
    use PhaseStageOutcome::{Completed, Failed, Partial, Skipped};
    match (current, next) {
        (Failed, _) | (_, Failed) => Failed,
        (Partial, _) | (_, Partial) => Partial,
        (Completed, Skipped) | (Skipped, Completed) => Partial,
        (outcome, _) => outcome,
    }
}

fn output_run_refs(primary_run_id: &str, output: &Value) -> Vec<String> {
    let mut run_refs = vec![primary_run_id.to_string()];
    for pointer in ["/runId", "/data/runId"] {
        if let Some(run_id) = output.pointer(pointer).and_then(Value::as_str) {
            run_refs.push(run_id.to_string());
        }
    }
    deduplicated_run_refs(run_refs)
}

fn deduplicated_run_refs(run_refs: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    run_refs
        .into_iter()
        .filter(|run_id| !run_id.trim().is_empty())
        .filter(|run_id| seen.insert(run_id.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_artifacts::{
        load_scan_stage_data, ScanArtifactDelta, ScanEngineStageOutcome, ScanFindingDelta,
        ScanSeverityCount, ScanStageCost, ScanStageEngine, ScanStagePlan, ScanStageScope,
    };
    use crate::workflow_attempts::PhaseTargetSnapshot;

    #[test]
    fn receipts_include_only_executed_phases_and_aggregate_real_outcomes() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let artifacts = SastRunArtifacts::create(&workspace, "scan-stage-truth").unwrap();
        record_sast_phase_stage(
            &artifacts,
            WorkflowPhase::Scan,
            SastPhaseStageOutcome::Completed,
            vec!["scan-stage-truth".to_string(), "semgrep-child".to_string()],
        )
        .unwrap();
        record_sast_phase_stage(
            &artifacts,
            WorkflowPhase::Prove,
            SastPhaseStageOutcome::Completed,
            vec!["verify-1".to_string()],
        )
        .unwrap();
        record_sast_phase_stage(
            &artifacts,
            WorkflowPhase::Prove,
            SastPhaseStageOutcome::Skipped,
            vec!["verify-2".to_string()],
        )
        .unwrap();

        let stages = load_sast_phase_stages(&artifacts).unwrap();

        assert_eq!(stages.len(), 2);
        assert_eq!(stages[0]["phase"], "scan");
        assert_eq!(stages[0]["outcome"], "completed");
        assert_eq!(stages[1]["phase"], "prove");
        assert_eq!(stages[1]["outcome"], "partial");
        assert_eq!(stages[1]["runRefs"], json!(["verify-1", "verify-2"]));
        assert!(stages.iter().all(|stage| stage["phase"] != "fix"));
    }

    #[test]
    fn failed_receipt_dominates_an_earlier_completed_operation() {
        assert_eq!(
            merge_stage_outcome(
                SastPhaseStageOutcome::Completed,
                SastPhaseStageOutcome::Failed,
            ),
            SastPhaseStageOutcome::Failed
        );
    }

    #[test]
    fn typed_scan_stage_round_trips_without_aggregate_reconstruction() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let artifacts = SastRunArtifacts::create(&workspace, "typed-scan-stage").unwrap();
        let scan = typed_scan_stage(target.path());
        record_sast_scan_stage(
            &artifacts,
            SastPhaseStageOutcome::Partial,
            vec!["typed-scan-stage".to_string(), "native-run".to_string()],
            scan.clone(),
        )
        .unwrap();

        let receipt = load_scan_stage_data(target.path(), "typed-scan-stage")
            .unwrap()
            .expect("typed Scan stage");

        assert_eq!(receipt.outcome, PhaseStageOutcome::Partial);
        assert_eq!(receipt.scan, Some(scan));
    }

    fn typed_scan_stage(target: &std::path::Path) -> ScanStageData {
        ScanStageData {
            scope: ScanStageScope {
                target: target.display().to_string(),
                paths: vec!["src/auth".to_string()],
            },
            plan: ScanStagePlan {
                selection: "manual".to_string(),
                engines: vec!["semgrep".to_string(), "cargo-audit".to_string()],
            },
            engines: typed_scan_engines(),
            finding_delta: ScanFindingDelta {
                added: 2,
                updated: 1,
            },
            severity_counts: vec![
                ScanSeverityCount {
                    severity: crate::findings::Severity::Critical,
                    count: 1,
                },
                ScanSeverityCount {
                    severity: crate::findings::Severity::Medium,
                    count: 2,
                },
            ],
            artifact_delta: vec![ScanArtifactDelta {
                run_ref: "native-run".to_string(),
                path: "result.json".to_string(),
            }],
            duration_ms: 1_234,
            cost: Some(ScanStageCost {
                observed_usd: 0.25,
                complete: false,
            }),
            target_snapshot: PhaseTargetSnapshot::capture(target),
        }
    }

    /// Receipts written before severity recording carry no severityCounts
    /// key; they must keep deserializing with empty buckets, not fail or
    /// invent zeros.
    #[test]
    fn receipts_predating_severity_recording_deserialize_with_empty_buckets() {
        let target = tempfile::tempdir().unwrap();
        let mut receipt = json!(PhaseStageReceipt {
            phase: WorkflowPhase::Scan,
            outcome: PhaseStageOutcome::Completed,
            run_refs: vec!["legacy-run".to_string()],
            scan: Some(typed_scan_stage(target.path())),
        });
        receipt["scan"]
            .as_object_mut()
            .unwrap()
            .remove("severityCounts")
            .expect("fixture must have recorded severity counts");

        let parsed: PhaseStageReceipt = serde_json::from_value(receipt).unwrap();

        assert!(parsed.scan.unwrap().severity_counts.is_empty());
    }

    fn typed_scan_engines() -> Vec<ScanStageEngine> {
        vec![
            ScanStageEngine {
                engine: "semgrep".to_string(),
                outcome: ScanEngineStageOutcome::Complete,
                run_ref: Some("native-run".to_string()),
                detail: None,
            },
            ScanStageEngine {
                engine: "cargo-audit".to_string(),
                outcome: ScanEngineStageOutcome::Skipped,
                run_ref: None,
                detail: Some("binary unavailable".to_string()),
            },
        ]
    }
}
