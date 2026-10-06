//! Sequential `kuzushi scan --trials N` vertical slice.

use super::campaign_run::dispatch_scan_batch_plan;
use super::run_exit::RunCommandExit;
use super::scan::ScanScopeArgs;
use super::scan_gate::{apply_batch_scan_gate_policy, ScanGatePolicy};
use super::scan_prepare::{prepare_scan_batch_command, PreparedScanCommand};
use crate::command::{CampaignCommand, ScanModeArg};
use anyhow::{Context, Result};
use kuzushi_core::capabilities::campaign::{
    acquire_batch_controller_lease, acquire_scan_batch_threat_model_lease, campaign_plan_path,
    compile_scan_batch_plan, validate_scan_batch_execution_plan, validate_scan_batch_id,
    CampaignPlanHandle, ScanBatchGatePolicy, ScanBatchPlanSpec, MAX_SCAN_BATCH_TRIALS,
};
use kuzushi_core::findings::{
    derive_batch_occurrence_report_for_controller, BatchOccurrenceReport, FindingStore,
};
use kuzushi_core::WorkspaceTarget;
use std::path::PathBuf;

pub(crate) struct ScanBatchRequest {
    pub(crate) target: PathBuf,
    pub(crate) mode: Option<ScanModeArg>,
    pub(crate) tasks: Vec<String>,
    pub(crate) triage: Option<bool>,
    pub(crate) json: bool,
    pub(crate) ci: bool,
    pub(crate) budget: Option<String>,
    pub(crate) scope: ScanScopeArgs,
    pub(crate) since: Option<String>,
    pub(crate) include_worktree: bool,
    pub(crate) gate: ScanGatePolicy,
    pub(crate) trials: usize,
    pub(crate) workers: usize,
}

pub(crate) async fn scan_batch_command(request: ScanBatchRequest) -> Result<()> {
    validate_batch_request(&request)?;
    let prepared = prepare_batch_scan(&request)?;
    let handle = compile_prepared_batch(&prepared, &request)?;
    announce_batch(&handle);
    validate_frozen_gate_policy(&handle, &request.gate)?;
    let checked = load_checked_batch_plan(&request.target, &handle.campaign_id)?;
    let _model = acquire_scan_batch_threat_model_lease(&request.target, &checked)?;
    let _controller = acquire_batch_controller_lease(&request.target, &handle.campaign_id)?;
    let dispatch = dispatch_scan_batch(
        &request.target,
        &handle.campaign_id,
        handle.effective_workers,
    )
    .await;
    finish_batch_controller(
        &prepared.workspace,
        &prepared.store,
        &handle.campaign_id,
        &request.gate,
        request.json,
        request.ci,
        dispatch,
    )
}

pub(crate) async fn run_existing_batch_command(
    command: CampaignCommand,
    default_target: Option<PathBuf>,
) -> Result<()> {
    let CampaignCommand::Batch { batch_id, json, ci } = command else {
        unreachable!("raw campaign run routed to scan-batch controller")
    };
    validate_scan_batch_id(&batch_id)?;
    let target = crate::support::require_cli_target("campaign batch", None, default_target)?;
    let checked = load_checked_batch_plan(&target, &batch_id)?;
    let workspace = WorkspaceTarget::new(&target)?;
    workspace.ensure_state_dir()?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let gate = gate_policy_from_plan(&checked.gate_policy);
    let _model = acquire_scan_batch_threat_model_lease(&target, &checked)?;
    let _controller = acquire_batch_controller_lease(&target, &batch_id)?;
    let dispatch = dispatch_scan_batch(&target, &batch_id, checked.effective_workers).await;
    finish_batch_controller(&workspace, &store, &batch_id, &gate, json, ci, dispatch)
}

fn load_checked_batch_plan(
    target: &std::path::Path,
    batch_id: &str,
) -> Result<kuzushi_core::capabilities::campaign::ValidatedScanBatchPlan> {
    let path = campaign_plan_path(target, batch_id);
    let body = std::fs::read(&path)
        .with_context(|| format!("could not read scan-batch plan {}", path.display()))?;
    let plan = serde_json::from_slice(&body)
        .with_context(|| format!("{} is malformed JSON", path.display()))?;
    validate_scan_batch_execution_plan(batch_id, &plan)
}

fn gate_policy_from_plan(policy: &ScanBatchGatePolicy) -> ScanGatePolicy {
    ScanGatePolicy {
        fail_on: policy.fail_on,
        sarif: policy.sarif.clone(),
    }
}

fn prepare_batch_scan(request: &ScanBatchRequest) -> Result<PreparedScanCommand> {
    prepare_scan_batch_command(
        &request.target,
        request.mode,
        &request.tasks,
        request.budget.as_deref(),
        &request.scope,
        request.since.as_deref(),
        request.include_worktree,
        request.json,
        request.ci,
    )
}

fn compile_prepared_batch(
    prepared: &PreparedScanCommand,
    request: &ScanBatchRequest,
) -> Result<CampaignPlanHandle> {
    compile_scan_batch_plan(ScanBatchPlanSpec {
        root: prepared.workspace.root(),
        batch_id: None,
        trials: request.trials,
        requested_workers: request.workers,
        gate_policy: ScanBatchGatePolicy {
            fail_on: request.gate.fail_on,
            sarif: request.gate.sarif.clone(),
        },
        prepared_input: prepared.input.clone(),
        config: &prepared.config,
        registry: &prepared.registry,
    })
}

fn announce_batch(handle: &CampaignPlanHandle) {
    eprintln!(
        "scan batch {}: planned {} equivalent logical trials (workers={}/{})",
        handle.campaign_id,
        handle.trials_planned,
        handle.effective_workers,
        handle.requested_workers,
    );
    if let Some(reason) = &handle.parallel_safety.clamp_reason {
        eprintln!("scan batch {}: {reason}", handle.campaign_id);
    }
}

fn finish_batch_controller(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    batch_id: &str,
    gate_policy: &ScanGatePolicy,
    json: bool,
    ci: bool,
    dispatch: Result<()>,
) -> Result<()> {
    let mut report =
        derive_batch_occurrence_report_for_controller(workspace.root(), batch_id, store)
            .context("could not derive the scan-batch occurrence report")?;
    let gate = apply_batch_scan_gate_policy(workspace, store, &report, gate_policy)?;
    report.gate = Some(gate.outcome().clone());
    emit_batch_report(&report, json, ci)?;
    kuzushi_core::capabilities::campaign::record_scan_batch_phase_result(
        workspace.root(),
        batch_id,
        store,
    )
    .context("could not record the scan-batch result for explicit review")?;
    match batch_completion_status(
        dispatch.is_err(),
        gate.operationally_incomplete(),
        gate.failed(),
    ) {
        BatchCompletionStatus::OperationalFailure => operational_failure(dispatch, batch_id),
        BatchCompletionStatus::SecurityGateFailure => {
            gate.enforce();
            Ok(())
        }
        BatchCompletionStatus::Complete => Ok(()),
    }
}

fn validate_frozen_gate_policy(handle: &CampaignPlanHandle, policy: &ScanGatePolicy) -> Result<()> {
    anyhow::ensure!(
        handle.gate_policy.fail_on == policy.fail_on && handle.gate_policy.sarif == policy.sarif,
        "scan-batch controller gate policy differs from its immutable plan"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchCompletionStatus {
    OperationalFailure,
    SecurityGateFailure,
    Complete,
}

fn operational_failure(dispatch: Result<()>, batch_id: &str) -> Result<()> {
    dispatch.and_then(|_| {
        Err(RunCommandExit::new(
            1,
            format!("scan batch {batch_id} is operationally incomplete"),
        )
        .into())
    })
}

fn batch_completion_status(
    dispatch_failed: bool,
    operationally_incomplete: bool,
    gate_failed: bool,
) -> BatchCompletionStatus {
    if dispatch_failed || operationally_incomplete {
        BatchCompletionStatus::OperationalFailure
    } else if gate_failed {
        BatchCompletionStatus::SecurityGateFailure
    } else {
        BatchCompletionStatus::Complete
    }
}

fn validate_batch_request(request: &ScanBatchRequest) -> Result<()> {
    anyhow::ensure!(
        request.trials >= 2,
        "--trials must be at least 2 for batch mode"
    );
    anyhow::ensure!(
        request.trials <= MAX_SCAN_BATCH_TRIALS,
        "--trials exceeds the hard cap of {MAX_SCAN_BATCH_TRIALS}"
    );
    anyhow::ensure!(
        request.target.extension().and_then(|ext| ext.to_str()) != Some("apk"),
        "--trials is not supported for APK handoff scans"
    );
    anyhow::ensure!(request.workers >= 1, "--workers must be at least 1");
    anyhow::ensure!(
        request.triage != Some(true),
        "scan batches are discovery-only; remove --triage and triage the aggregate table"
    );
    Ok(())
}

async fn dispatch_scan_batch(
    target: &std::path::Path,
    batch_id: &str,
    effective_workers: usize,
) -> Result<()> {
    dispatch_scan_batch_plan(
        target.to_path_buf(),
        batch_id.to_string(),
        effective_workers,
    )
    .await
}

fn emit_batch_report(report: &BatchOccurrenceReport, json: bool, _ci: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!("{}", report.output());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
