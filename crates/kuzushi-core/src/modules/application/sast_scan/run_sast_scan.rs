use super::*;
use crate::run_artifacts::{
    PhaseStageOutcome, ScanArtifactDelta, ScanEngineStageOutcome, ScanFindingDelta,
    ScanSeverityCount, ScanStageCost, ScanStageData, ScanStageEngine, ScanStagePlan,
    ScanStageScope,
};
use crate::WorkspaceTarget;
use std::collections::BTreeSet;
use std::time::Instant;

pub(in crate::modules) fn run_sast_scan_with_registry(
    registry: &ModuleRegistry,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let workspace = sast_workspace(ctx)?;
    let PreparedSastScan {
        input,
        primary_run_id,
        whitebox_static,
        threat_model_lease,
    } = prepare_sast_scan(registry, input, ctx, workspace)?;
    let threat_model_lease = ScanThreatModelLease::new(threat_model_lease);
    let store = sast_store(ctx)?;
    ensure_sast_run_started(registry, workspace, &primary_run_id, &input, ctx)?;
    let fallback_trace = fallback_sast_trace(ctx, workspace, &primary_run_id)?;
    let run_ctx = sast_run_context(ctx, fallback_trace.as_ref());
    let result = run_started_sast_scan(
        registry,
        input,
        &run_ctx,
        runtime,
        workspace,
        store,
        primary_run_id.clone(),
        whitebox_static,
        &threat_model_lease,
    );
    result
        .map_err(|error| started_sast_scan_error(workspace, &primary_run_id, error, ctx, &run_ctx))
}

fn started_sast_scan_error(
    workspace: &WorkspaceTarget,
    run_id: &str,
    error: anyhow::Error,
    ctx: &ToolExecutionContext<'_>,
    run_ctx: &ToolExecutionContext<'_>,
) -> anyhow::Error {
    let persistence = persist_sast_terminal_error(
        workspace,
        run_id,
        &error,
        sast_cancellation_disposition(ctx),
        run_ctx.run_observation().as_ref(),
    );
    error_with_persistence(error, persistence)
}

struct PreparedSastScan {
    input: Value,
    primary_run_id: String,
    whitebox_static: Option<WhiteboxStaticPolicy>,
    threat_model_lease: Option<crate::capabilities::threat_model::ThreatModelReadLease>,
}

fn prepare_sast_scan(
    registry: &ModuleRegistry,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    workspace: &WorkspaceTarget,
) -> Result<PreparedSastScan> {
    let input = bind_dispatch_snapshot_input("sast:scan", input, ctx)?;
    let primary_run_id = canonical_sast_run_id(&input, ctx);
    let threat_model_lease = acquire_bound_threat_model_lease(workspace, &input)?;
    crate::capabilities::campaign::verify_scan_batch_child_equivalence(
        workspace.root(),
        &primary_run_id,
        &input,
        ctx.config,
        registry,
    )?;
    let (mut input, whitebox_static) = apply_whitebox_static_sast_policy(input)?;
    set_canonical_sast_run_id(&mut input, &primary_run_id);
    Ok(PreparedSastScan {
        input,
        primary_run_id,
        whitebox_static,
        threat_model_lease,
    })
}

fn acquire_bound_threat_model_lease(
    workspace: &WorkspaceTarget,
    input: &Value,
) -> Result<Option<crate::capabilities::threat_model::ThreatModelReadLease>> {
    let expected = parse_sast_threat_model_binding(input)?;
    crate::capabilities::threat_model::acquire_exact_threat_model_read_lease(
        workspace.root(),
        expected.as_ref(),
    )
    .map(Some)
}

fn parse_sast_threat_model_binding(
    input: &Value,
) -> Result<Option<crate::capabilities::threat_model::ThreatModelRef>> {
    let Some(value) = input
        .get("threatModelRef")
        .or_else(|| input.get("threat_model_ref"))
    else {
        anyhow::bail!("sast:scan input is missing its dispatch-bound threatModelRef");
    };
    if value.is_null() {
        return Ok(None);
    }
    let model_ref = serde_json::from_value(value.clone())
        .context("sast:scan threatModelRef is not a valid immutable model reference")?;
    Ok(Some(model_ref))
}

#[cfg(test)]
mod threat_model_binding_tests {
    use super::*;

    #[test]
    fn explicitly_model_free_scan_holds_a_read_lease() {
        let target = tempfile::tempdir().unwrap();
        crate::capabilities::threat_model::open_writable_threat_model_store(target.path()).unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();

        let lease =
            acquire_bound_threat_model_lease(&workspace, &json!({"threatModelRef": Value::Null}))
                .unwrap();

        assert!(lease.is_some());
        assert!(lease.unwrap().model_ref().is_none());
    }

    #[test]
    fn ordinary_scan_binds_explicit_model_free_state_before_start() {
        let target = tempfile::tempdir().unwrap();
        crate::capabilities::threat_model::open_writable_threat_model_store(target.path()).unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();

        let config = crate::V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let input = bind_dispatch_snapshot_input("sast:scan", json!({}), &ctx).unwrap();

        assert!(input.get("threatModelRef").is_some_and(Value::is_null));
        assert!(acquire_bound_threat_model_lease(&workspace, &input)
            .unwrap()
            .is_some());
    }

    #[test]
    fn scan_refuses_an_unknown_bound_revision() {
        let target = tempfile::tempdir().unwrap();
        crate::capabilities::threat_model::commit_test_model(target.path(), "existing-model");
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let stale_ref = crate::capabilities::threat_model::ThreatModelRef {
            model_id: crate::capabilities::threat_model::ThreatModelId::new(),
            revision_id: crate::capabilities::threat_model::ThreatModelRevisionId::new(),
            sha256: format!("sha256:{}", "0".repeat(64)),
        };

        let error =
            acquire_bound_threat_model_lease(&workspace, &json!({"threatModelRef": stale_ref}))
                .err()
                .expect("a stale immutable reference must be refused");

        assert!(error.to_string().contains("was not found"), "{error:#}");
    }
}

fn fallback_sast_trace(
    ctx: &ToolExecutionContext<'_>,
    workspace: &WorkspaceTarget,
    run_id: &str,
) -> Result<Option<crate::run_artifacts::TraceHandle>> {
    ctx.trace
        .is_none()
        .then(|| fallback_sast_observation(workspace, run_id))
        .transpose()
}

fn fallback_sast_observation(
    workspace: &WorkspaceTarget,
    run_id: &str,
) -> Result<crate::run_artifacts::TraceHandle> {
    let observation = crate::run_lifecycle::RunObservationHandle::jsonl(workspace.root(), run_id)?
        .start_root_task("Run the accepted Scan plan")?;
    observation
        .task_handle()
        .context("fallback Scan observation lacks its semantic task")?
        .update_and_flush(crate::run_lifecycle::RunItemStatus::Running, None)?;
    Ok(observation.trace_handle())
}

fn sast_run_context<'a>(
    ctx: &'a ToolExecutionContext<'_>,
    fallback_trace: Option<&'a crate::run_artifacts::TraceHandle>,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config: ctx.config,
        workspace: ctx.workspace,
        findings_store: ctx.findings_store,
        trace: ctx.trace.or(fallback_trace),
        cancellation: ctx.cancellation,
        authorization: ctx.authorization.clone(),
    }
}

fn sast_cancellation_disposition(
    ctx: &ToolExecutionContext<'_>,
) -> Option<crate::scan::CancellationDisposition> {
    ctx.cancellation
        .and_then(crate::scan::ScanCancellation::disposition)
}

fn persist_sast_terminal_error(
    workspace: &WorkspaceTarget,
    run_id: &str,
    error: &anyhow::Error,
    cancellation: Option<crate::scan::CancellationDisposition>,
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
) -> Result<()> {
    if defer_sast_terminal_to_dispatch(workspace.root(), run_id, observation)? {
        return Ok(());
    }
    let record =
        crate::run_artifacts::ToolRunRecord::new(workspace.root(), run_id, "scan", "sast:scan");
    match cancellation {
        Some(crate::scan::CancellationDisposition::Canceled) => {
            crate::run_artifacts::try_record_tool_run_canceled_observed(
                record,
                &error.to_string(),
                observation,
            )
        }
        Some(crate::scan::CancellationDisposition::Interrupted) => {
            crate::run_artifacts::try_record_tool_run_interrupted_observed(
                record,
                &error.to_string(),
                observation,
            )
        }
        None => crate::run_artifacts::try_record_tool_run_failed_observed(
            record,
            &error.to_string(),
            observation,
        ),
    }
}

fn run_started_sast_scan(
    registry: &ModuleRegistry,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    primary_run_id: String,
    whitebox_static: Option<WhiteboxStaticPolicy>,
    threat_model_lease: &ScanThreatModelLease,
) -> Result<Value> {
    let requests = SastScanRequests::from_input(&input)?;
    let options = sast_scan_options(&input, whitebox_static.is_some())?;
    let option_store = sast_subtool_options(ctx, workspace)?;
    let source = crate::workspace::source_snapshot::SourceSnapshot::capture(ctx, "sast:scan", workspace.root())?;
    let executed = execute_sast_scan(SastScanExecutionInput {
        registry,
        input: &input,
        ctx,
        runtime,
        option_store: &option_store,
        workspace,
        store,
        requests: &requests,
        options: &options,
        primary_run_id: &primary_run_id,
        whitebox_static: whitebox_static.is_some(),
        threat_model_lease,
    })?;
    let findings_count = executed.tally.distinct;
    let (artifacts, result) = executed.into_result(workspace, whitebox_static.as_ref())?;
    let result = source.finish(ctx, "sast:scan", workspace.root(), result);
    persist_sast_scan_result(
        ctx,
        workspace,
        &primary_run_id,
        findings_count,
        artifacts,
        result,
    )
}

fn persist_sast_scan_result(
    ctx: &ToolExecutionContext<'_>,
    workspace: &WorkspaceTarget,
    run_id: &str,
    findings_count: usize,
    artifacts: SastRunArtifacts,
    result: Value,
) -> Result<Value> {
    let summary_artifact = write_sast_summary(workspace, run_id, &artifacts, &result)?;
    let observation = ctx.run_observation();
    write_sast_run_metadata(
        workspace,
        run_id,
        findings_count,
        &artifacts,
        summary_artifact,
        &result,
        observation.as_ref(),
    )?;
    Ok(result)
}

fn canonical_sast_run_id(input: &Value, ctx: &ToolExecutionContext<'_>) -> String {
    ctx.run_id()
        .or_else(|| string_input_any(input, &["runId", "run_id"]))
        .unwrap_or_else(|| crate::run_artifacts::new_run_id("scan"))
}

fn set_canonical_sast_run_id(input: &mut Value, run_id: &str) {
    if let Value::Object(object) = input {
        object.insert("runId".to_string(), json!(run_id));
        object.remove("run_id");
    }
}

fn ensure_sast_run_started(
    registry: &ModuleRegistry,
    workspace: &WorkspaceTarget,
    run_id: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    if crate::run_artifacts::load_run_summary(workspace.root(), run_id).is_ok() {
        return Ok(());
    }
    let execution_model = sast_execution_model(input, ctx.config.model.as_deref());
    crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
        crate::run_artifacts::ToolRunRecord::new(workspace.root(), run_id, "scan", "sast:scan"),
        input,
        execution_model,
        crate::config::config_hash(ctx.config).ok(),
        registry.loaded_module_specifiers(),
    )
}

/// Model recorded in the execution receipt, rather than merely configured in
/// the operator profile. Scanner-only SAST runs do not invoke an agent runtime,
/// so attaching the configured cloud model to them would misstate provenance.
fn sast_execution_model(input: &Value, configured_model: Option<&str>) -> Option<String> {
    if !wants_sast_runtime(input) {
        return None;
    }
    string_input_any(input, &["model"]).or_else(|| configured_model.map(str::to_string))
}

fn error_with_persistence(error: anyhow::Error, persistence: Result<()>) -> anyhow::Error {
    match persistence {
        Ok(()) => error,
        Err(persistence) => anyhow::anyhow!(
            "{error:#}; additionally, run artifact persistence failed: {persistence:#}"
        ),
    }
}

#[cfg(test)]
mod terminal_error_tests {
    use super::*;
    use crate::config::V2Config;
    use crate::findings::FindingStore;
    use crate::run_artifacts::{load_run_summary, try_record_tool_run_failed, ToolRunRecord};
    use crate::scan::ScanCancellation;

    #[test]
    fn nested_sast_cancellation_persists_canceled_before_outer_terminalization() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let cancellation = ScanCancellation::default();
        cancellation.cancel();
        let run_id = "scan-canceled-shared";
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: Some(&cancellation),
            authorization: Default::default(),
        };

        let error = run_sast_scan_with_registry(
            &registry,
            serde_json::json!({
                "runId": run_id,
                "taskMode": "manual",
                "tasks": ["secret-scan"]
            }),
            &ctx,
            None,
        )
        .unwrap_err();

        assert!(error.to_string().contains("cancelled"));
        let summary = load_run_summary(target.path(), run_id).unwrap();
        assert_eq!(summary.status, "canceled");
        let record = ToolRunRecord::new(target.path(), run_id, "scan", "sast:scan");
        let rewrite = try_record_tool_run_failed(record, "late scanner failure").unwrap_err();
        assert!(rewrite
            .to_string()
            .contains("already terminal with status canceled"));
    }

    #[test]
    fn nested_sast_watchdog_interruption_persists_interrupted() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let cancellation = ScanCancellation::default();
        cancellation.interrupt();
        let run_id = "scan-interrupted-shared";
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: Some(&cancellation),
            authorization: Default::default(),
        };

        let error = run_sast_scan_with_registry(
            &registry,
            serde_json::json!({
                "runId": run_id,
                "taskMode": "manual",
                "tasks": ["secret-scan"]
            }),
            &ctx,
            None,
        )
        .unwrap_err();

        assert!(error.to_string().contains("cancelled"));
        let summary = load_run_summary(target.path(), run_id).unwrap();
        assert_eq!(summary.status, "interrupted");
    }
}

#[cfg(test)]
mod lifecycle_task_tests {
    use super::*;
    use crate::run_lifecycle::{ProjectionHealth, RunItemStatus, RunObservationHandle};
    use crate::V2Config;

    #[test]
    fn production_scan_preserves_accepted_engine_order_and_child_run_identity() {
        let (output, projection) = execute_production_scan_fixture();
        assert_accepted_scan_tasks(&output, &projection);
    }

    fn execute_production_scan_fixture() -> (Value, crate::run_lifecycle::RunProjection) {
        let target = production_scan_target();
        let run_id = "scan-lifecycle-task-order";
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let observation = RunObservationHandle::jsonl(target.path(), run_id)
            .unwrap()
            .start_root_task("Run the accepted Scan plan")
            .unwrap();
        let trace = observation.trace_handle();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: Some(&trace),
            cancellation: None,
            authorization: Default::default(),
        };

        let output = run_sast_scan_with_registry(
            &registry,
            serde_json::json!({
                "runId": run_id,
                "taskMode": "manual",
                "tasks": ["dep-hygiene", "secret-scan"]
            }),
            &ctx,
            None,
        )
        .unwrap();
        let projection = crate::run_lifecycle::load_run_projection(target.path(), run_id)
            .unwrap()
            .projection;
        (output, projection)
    }

    fn production_scan_target() -> tempfile::TempDir {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(
            target.path().join("package.json"),
            r#"{"dependencies":{"demo":"latest"}}"#,
        )
        .unwrap();
        std::fs::write(
            target.path().join(".env"),
            "OPENAI_API_KEY=sk-production-scan-lifecycle-sentinel\n",
        )
        .unwrap();
        target
    }

    fn assert_accepted_scan_tasks(
        output: &Value,
        projection: &crate::run_lifecycle::RunProjection,
    ) {
        assert_eq!(projection.health, ProjectionHealth::Healthy);
        let accepted = output["data"]["engines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|engine| engine.as_str().unwrap())
            .collect::<Vec<_>>();
        let tasks = projection
            .task_order
            .iter()
            .filter_map(|task_id| projection.tasks.get(task_id))
            .filter(|task| accepted.contains(&task.title.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            tasks
                .iter()
                .map(|task| task.title.as_str())
                .collect::<Vec<_>>(),
            accepted
        );
        let child_run = output["data"]["runIds"]["native"].as_str().unwrap();
        assert!(tasks.iter().all(|task| {
            task.status == RunItemStatus::Completed
                && task
                    .detail
                    .as_ref()
                    .is_some_and(|detail| detail.as_str().contains(child_run))
        }));
    }
}

struct SastScanExecutionInput<'a> {
    registry: &'a ModuleRegistry,
    input: &'a Value,
    ctx: &'a ToolExecutionContext<'a>,
    runtime: Option<&'a dyn AgentRuntime>,
    option_store: &'a crate::options::ToolOptionStore,
    workspace: &'a crate::workspace::WorkspaceTarget,
    store: &'a crate::findings::FindingStore,
    requests: &'a SastScanRequests,
    options: &'a ScanRunOptions,
    primary_run_id: &'a str,
    whitebox_static: bool,
    threat_model_lease: &'a ScanThreatModelLease,
}

impl SastScanExecutionInput<'_> {
    fn reports(&self, selected: &SastTaskSelection) -> Result<SastPipelineReports> {
        run_selected_sast_pipeline_reports(
            self.registry,
            self.input,
            self.ctx,
            self.runtime,
            self.option_store,
            self.workspace,
            self.store,
            self.options,
            selected,
        )
    }

    fn record_scan_stage(
        &self,
        artifacts: &SastRunArtifacts,
        reports: &SastPipelineReports,
        selected: &SastTaskSelection,
        before_findings: &BTreeSet<String>,
        before_artifacts: &BTreeSet<(String, String)>,
        core_findings: &[crate::findings::Finding],
        started: Instant,
        target_snapshot: crate::workflow_attempts::PhaseTargetSnapshot,
    ) -> Result<()> {
        let run_ids = reports.run_ids(self.primary_run_id.to_string());
        let mut run_refs = vec![self.primary_run_id.to_string()];
        run_refs.extend(run_ids.all().into_iter().map(str::to_string));
        let outcome = scan_stage_outcome(reports);
        let finding_delta = scan_finding_delta(before_findings, core_findings);
        let scan = ScanStageData {
            scope: scan_stage_scope(self.workspace, self.options),
            plan: scan_stage_plan(self.input, selected),
            engines: scan_stage_engines(reports, &run_ids)?,
            finding_delta,
            severity_counts: scan_severity_counts(core_findings),
            artifact_delta: scan_artifact_delta(
                self.workspace.root(),
                &run_refs,
                before_artifacts,
            )?,
            duration_ms: elapsed_millis(started),
            cost: scan_stage_cost(reports)?,
            target_snapshot,
        };
        record_sast_scan_stage(artifacts, outcome, run_refs, scan)?;
        self.emit_finding_delta(finding_delta, core_findings)
    }

    fn emit_finding_delta(
        &self,
        delta: ScanFindingDelta,
        findings: &[crate::findings::Finding],
    ) -> Result<()> {
        let Some(observation) = self.ctx.run_observation() else {
            return Ok(());
        };
        let store_watermark = self.store.projection_meta()?.applied_seq;
        let finding_id_samples = findings
            .iter()
            .take(crate::run_lifecycle::MAX_FINDING_ID_SAMPLES)
            .map(|finding| crate::run_lifecycle::SafeText::operator_visible(&finding.fingerprint))
            .collect();
        observation.emit(crate::run_lifecycle::RunItemRecord::new(
            crate::run_lifecycle::RunItemId::new(),
            crate::run_lifecycle::RunItemSource::Persistence,
            crate::run_lifecycle::RunItemV1::FindingDelta {
                delta: crate::run_lifecycle::FindingDeltaSummary {
                    added: delta.added,
                    updated: delta.updated,
                    removed: 0,
                    store_watermark: crate::run_lifecycle::SafeText::operator_visible(
                        store_watermark.to_string(),
                    ),
                    finding_id_samples,
                },
            },
        ))
    }

    fn record_failed_scan_stage(
        &self,
        artifacts: &SastRunArtifacts,
        selected: &SastTaskSelection,
        started: Instant,
        target_snapshot: crate::workflow_attempts::PhaseTargetSnapshot,
        error: &anyhow::Error,
    ) -> Result<()> {
        let run_ref = self.primary_run_id.to_string();
        let scan = ScanStageData {
            scope: scan_stage_scope(self.workspace, self.options),
            plan: scan_stage_plan(self.input, selected),
            engines: vec![ScanStageEngine {
                engine: "sast:scan".to_string(),
                outcome: ScanEngineStageOutcome::Failed,
                run_ref: Some(run_ref.clone()),
                detail: Some(format!(
                    "pipeline failed before complete per-engine outcomes were available: {error}"
                )),
            }],
            finding_delta: ScanFindingDelta::default(),
            severity_counts: Vec::new(),
            artifact_delta: Vec::new(),
            duration_ms: elapsed_millis(started),
            cost: None,
            target_snapshot,
        };
        record_sast_scan_stage(artifacts, PhaseStageOutcome::Failed, vec![run_ref], scan)
    }

    fn whitebox_artifacts(
        &self,
        run_ids: &SastRunIds,
        artifacts: &SastRunArtifacts,
    ) -> Result<WhiteboxArtifacts> {
        write_sast_whitebox_artifacts(
            self.input,
            self.workspace,
            self.store,
            run_ids,
            artifacts,
            self.whitebox_static,
        )
    }

    fn post_processing(
        &self,
        run_ids: &SastRunIds,
        artifacts: &SastRunArtifacts,
    ) -> Result<SastPostProcessing> {
        run_sast_post_processing(
            self.registry,
            self.requests,
            self.input,
            self.ctx,
            self.runtime,
            self.option_store,
            self.store,
            run_ids,
            artifacts,
            self.threat_model_lease,
        )
    }

    fn output_lines(
        &self,
        primary_run_id: &str,
        tally: SastFindingTally,
        reports: &SastPipelineReports,
        whitebox_artifacts: &WhiteboxArtifacts,
        post_processing: &SastPostProcessing,
    ) -> Vec<String> {
        sast_output_lines(
            primary_run_id,
            tally,
            self.workspace,
            reports,
            self.whitebox_static,
            whitebox_artifacts,
            post_processing,
            self.requests,
        )
    }
}

struct ExecutedSastScan {
    primary_run_id: String,
    run_ids: SastRunIds,
    artifacts: SastRunArtifacts,
    reports: SastPipelineReports,
    tally: SastFindingTally,
    core_findings: Vec<crate::findings::Finding>,
    whitebox_artifacts: WhiteboxArtifacts,
    post_processing: SastPostProcessing,
    lines: Vec<String>,
}

struct ScanStageBaseline {
    selected: SastTaskSelection,
    lifecycle_tasks: Vec<crate::run_lifecycle::ObservedRunTask>,
    finding_fingerprints: BTreeSet<String>,
    artifacts: BTreeSet<(String, String)>,
    target_snapshot: crate::workflow_attempts::PhaseTargetSnapshot,
    started: Instant,
}

fn execute_sast_scan(input: SastScanExecutionInput<'_>) -> Result<ExecutedSastScan> {
    let primary_run_id = input.primary_run_id.to_string();
    let artifacts = SastRunArtifacts::create(input.workspace, &primary_run_id)?;
    write_sast_scan_input(input.workspace, &primary_run_id, &artifacts, input.input)?;
    let baseline = scan_stage_baseline(&input, &primary_run_id)?;
    let reports = scan_reports_with_failure_receipt(&input, &artifacts, &baseline)?;
    let run_ids = reports.run_ids(primary_run_id.clone());
    let core_findings = findings_for_sast_runs(input.store, &run_ids)?;
    artifacts.write_json("findings.json", "discovery observations", &json!(core_findings))?;
    let whitebox_artifacts = input.whitebox_artifacts(&run_ids, &artifacts)?;
    input.record_scan_stage(
        &artifacts,
        &reports,
        &baseline.selected,
        &baseline.finding_fingerprints,
        &baseline.artifacts,
        &core_findings,
        baseline.started,
        baseline.target_snapshot,
    )?;
    let post_processing = input.post_processing(&run_ids, &artifacts)?;
    let tally = SastFindingTally::for_runs(input.store, &run_ids, core_findings.len())?;
    let lines = input.output_lines(
        primary_run_id.as_str(),
        tally,
        &reports,
        &whitebox_artifacts,
        &post_processing,
    );
    Ok(ExecutedSastScan {
        primary_run_id,
        run_ids,
        artifacts,
        reports,
        tally,
        core_findings,
        whitebox_artifacts,
        post_processing,
        lines,
    })
}

fn scan_stage_baseline(
    input: &SastScanExecutionInput<'_>,
    primary_run_id: &str,
) -> Result<ScanStageBaseline> {
    let selected = prepare_sast_task_selection(input.input)?;
    let lifecycle_tasks = observe_scan_plan(input.ctx, &selected)?;
    Ok(ScanStageBaseline {
        selected,
        lifecycle_tasks,
        finding_fingerprints: current_finding_fingerprints(input.store)?,
        artifacts: scan_artifact_inventory(input.workspace.root(), &[primary_run_id.to_string()])?,
        target_snapshot: crate::workflow_attempts::PhaseTargetSnapshot::capture(
            input.workspace.root(),
        ),
        started: Instant::now(),
    })
}

fn scan_reports_with_failure_receipt(
    input: &SastScanExecutionInput<'_>,
    artifacts: &SastRunArtifacts,
    baseline: &ScanStageBaseline,
) -> Result<SastPipelineReports> {
    update_scan_tasks(
        &baseline.lifecycle_tasks,
        crate::run_lifecycle::RunItemStatus::Running,
        None,
    )?;
    input
        .reports(&baseline.selected)
        .and_then(|reports| {
            finish_scan_tasks(&baseline.lifecycle_tasks, &reports)?;
            Ok(reports)
        })
        .map_err(|error| {
            let (status, detail) =
                scan_pipeline_stop_task_terminal(sast_cancellation_disposition(input.ctx));
            let task_persistence =
                update_scan_tasks(&baseline.lifecycle_tasks, status, Some(detail));
            let stage_persistence = input.record_failed_scan_stage(
                artifacts,
                &baseline.selected,
                baseline.started,
                baseline.target_snapshot.clone(),
                &error,
            );
            error_with_persistence(error, task_persistence.and(stage_persistence))
        })
}

fn scan_pipeline_stop_task_terminal(
    cancellation: Option<crate::scan::CancellationDisposition>,
) -> (crate::run_lifecycle::RunItemStatus, &'static str) {
    match cancellation {
        Some(crate::scan::CancellationDisposition::Canceled) => (
            crate::run_lifecycle::RunItemStatus::Canceled,
            "engine stopped after scan cancellation",
        ),
        _ => (
            crate::run_lifecycle::RunItemStatus::Interrupted,
            "engine outcomes are unavailable because the scan pipeline stopped",
        ),
    }
}

fn observe_scan_plan(
    ctx: &ToolExecutionContext<'_>,
    selected: &SastTaskSelection,
) -> Result<Vec<crate::run_lifecycle::ObservedRunTask>> {
    let Some(observation) = ctx.run_observation() else {
        return Ok(Vec::new());
    };
    let mut plan = observation
        .plan_handle()?
        .context("Scan observation has no application-owned plan")?;
    plan.extend_tasks(selected.planned_engine_ids())
}

fn update_scan_tasks(
    tasks: &[crate::run_lifecycle::ObservedRunTask],
    status: crate::run_lifecycle::RunItemStatus,
    detail: Option<&str>,
) -> Result<()> {
    for task in tasks {
        task.update(status, detail)?;
    }
    Ok(())
}

fn finish_scan_tasks(
    tasks: &[crate::run_lifecycle::ObservedRunTask],
    reports: &SastPipelineReports,
) -> Result<()> {
    let run_ids = reports.run_ids("parent".to_string());
    let outcomes = tasks
        .iter()
        .map(|task| scan_task_outcome(reports, task.title()))
        .collect::<Result<Vec<_>>>()?;
    for (task, outcome) in tasks.iter().zip(outcomes) {
        task.update(
            scan_task_status(outcome),
            scan_task_outcome_detail(task.title(), outcome, &run_ids).as_deref(),
        )?;
    }
    Ok(())
}

fn scan_task_outcome_detail(
    engine: &str,
    outcome: ScanEngineStageOutcome,
    run_ids: &SastRunIds,
) -> Option<String> {
    let detail = scan_engine_outcome_detail(outcome);
    match (scan_engine_run_ref(engine, run_ids), detail) {
        (Some(run_ref), Some(detail)) => Some(format!("child run {run_ref}: {detail}")),
        (Some(run_ref), None) => Some(format!("child run {run_ref}: completed")),
        (None, detail) => detail,
    }
}

fn scan_task_outcome(
    reports: &SastPipelineReports,
    engine: &str,
) -> Result<ScanEngineStageOutcome> {
    if reports
        .skipped_engines
        .iter()
        .any(|skipped| skipped.id == engine)
    {
        return Ok(ScanEngineStageOutcome::Skipped);
    }
    reports
        .engine_outcomes
        .get(engine)
        .copied()
        .with_context(|| format!("Scan engine {engine} did not record an outcome"))
}

fn scan_task_status(outcome: ScanEngineStageOutcome) -> crate::run_lifecycle::RunItemStatus {
    match outcome {
        ScanEngineStageOutcome::Complete => crate::run_lifecycle::RunItemStatus::Completed,
        ScanEngineStageOutcome::Partial => crate::run_lifecycle::RunItemStatus::Partial,
        ScanEngineStageOutcome::Skipped => crate::run_lifecycle::RunItemStatus::Skipped,
        ScanEngineStageOutcome::Failed => crate::run_lifecycle::RunItemStatus::Failed,
    }
}

fn current_finding_fingerprints(store: &FindingStore) -> Result<BTreeSet<String>> {
    Ok(store
        .list_findings(usize::MAX)?
        .into_iter()
        .map(|finding| finding.fingerprint)
        .collect())
}

fn scan_stage_scope(
    workspace: &crate::workspace::WorkspaceTarget,
    options: &ScanRunOptions,
) -> ScanStageScope {
    ScanStageScope {
        target: workspace.root().display().to_string(),
        paths: options.paths.clone(),
    }
}

fn scan_stage_plan(input: &Value, selected: &SastTaskSelection) -> ScanStagePlan {
    let selection = input
        .get("taskMode")
        .or_else(|| input.get("task_mode"))
        .and_then(Value::as_str)
        .unwrap_or("auto")
        .to_string();
    ScanStagePlan {
        selection,
        engines: selected.planned_engine_ids(),
    }
}

fn scan_stage_engines(
    reports: &SastPipelineReports,
    run_ids: &SastRunIds,
) -> Result<Vec<ScanStageEngine>> {
    let mut engines = reports
        .engine_ids
        .iter()
        .map(|engine| {
            let outcome = reports
                .engine_outcomes
                .get(*engine)
                .copied()
                .with_context(|| format!("Scan engine {engine} did not record an outcome"))?;
            Ok(ScanStageEngine {
                engine: (*engine).to_string(),
                outcome,
                run_ref: scan_engine_run_ref(engine, run_ids),
                detail: scan_engine_outcome_detail(outcome),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    engines.extend(
        reports
            .skipped_engines
            .iter()
            .map(|skipped| ScanStageEngine {
                engine: skipped.id.to_string(),
                outcome: ScanEngineStageOutcome::Skipped,
                run_ref: None,
                detail: Some(skipped.warning.clone()),
            }),
    );
    Ok(engines)
}

fn scan_engine_outcome_detail(outcome: ScanEngineStageOutcome) -> Option<String> {
    match outcome {
        ScanEngineStageOutcome::Complete => None,
        ScanEngineStageOutcome::Partial => Some("child retained a usable partial result".into()),
        ScanEngineStageOutcome::Skipped => Some("child reported a skipped result".into()),
        ScanEngineStageOutcome::Failed => Some("child reported a failed result".into()),
    }
}

fn scan_stage_outcome(reports: &SastPipelineReports) -> SastPhaseStageOutcome {
    use ScanEngineStageOutcome::Failed;
    if reports
        .engine_outcomes
        .values()
        .any(|outcome| *outcome == Failed)
    {
        return SastPhaseStageOutcome::Failed;
    }
    if reports
        .engine_outcomes
        .iter()
        .any(|(engine, outcome)| reports.engine_degrades_scan(engine, *outcome))
    {
        SastPhaseStageOutcome::Partial
    } else {
        SastPhaseStageOutcome::Completed
    }
}

fn scan_engine_run_ref(engine: &str, run_ids: &SastRunIds) -> Option<String> {
    match engine {
        "agentic" => run_ids.agentic.clone(),
        "offense-review" => run_ids.carlini.clone(),
        "taint-iris-next" => run_ids.taint_iris_next.clone(),
        "systems-hunt" => run_ids.systems_hunt.clone(),
        _ => run_ids.native.clone(),
    }
}

/// Buckets the attempt's findings by severity, highest band first, zero
/// buckets omitted — the shape the Scan cockpit renders as chips.
fn scan_severity_counts(findings: &[crate::findings::Finding]) -> Vec<ScanSeverityCount> {
    let mut counts = std::collections::BTreeMap::new();
    for finding in findings {
        *counts.entry(finding.severity).or_insert(0u64) += 1;
    }
    counts
        .into_iter()
        .rev()
        .map(|(severity, count)| ScanSeverityCount { severity, count })
        .collect()
}

fn scan_finding_delta(
    before: &BTreeSet<String>,
    findings: &[crate::findings::Finding],
) -> ScanFindingDelta {
    let produced = findings
        .iter()
        .map(|finding| finding.fingerprint.as_str())
        .collect::<BTreeSet<_>>();
    let updated = produced
        .iter()
        .filter(|fingerprint| before.contains(**fingerprint))
        .count() as u64;
    ScanFindingDelta {
        added: produced.len() as u64 - updated,
        updated,
    }
}

fn scan_artifact_inventory(
    target: &std::path::Path,
    run_refs: &[String],
) -> Result<BTreeSet<(String, String)>> {
    let mut inventory = BTreeSet::new();
    for run_ref in run_refs {
        for artifact in crate::run_artifacts::load_run_artifacts(target, run_ref)? {
            inventory.insert((run_ref.clone(), artifact.path));
        }
    }
    Ok(inventory)
}

fn scan_artifact_delta(
    target: &std::path::Path,
    run_refs: &[String],
    before: &BTreeSet<(String, String)>,
) -> Result<Vec<ScanArtifactDelta>> {
    Ok(scan_artifact_inventory(target, run_refs)?
        .difference(before)
        .map(|(run_ref, path)| ScanArtifactDelta {
            run_ref: run_ref.clone(),
            path: path.clone(),
        })
        .collect())
}

fn scan_stage_cost(reports: &SastPipelineReports) -> Result<Option<ScanStageCost>> {
    let mut total = crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO);
    for report in sast_engine_cost_reports(reports)? {
        total = total.checked_add(report, "Scan stage aggregated cost")?;
    }
    Ok((!total.is_unavailable()).then(|| ScanStageCost {
        observed_usd: total.observed_usd(),
        complete: total.is_complete(),
    }))
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

impl ExecutedSastScan {
    fn into_result(
        self,
        workspace: &crate::workspace::WorkspaceTarget,
        whitebox_static: Option<&WhiteboxStaticPolicy>,
    ) -> Result<(SastRunArtifacts, Value)> {
        let ExecutedSastScan {
            primary_run_id,
            run_ids,
            artifacts,
            reports,
            tally,
            core_findings,
            whitebox_artifacts,
            post_processing,
            lines,
        } = self;
        let result = sast_scan_result(SastScanResultParts {
            primary_run_id,
            run_ids,
            workspace,
            reports: &reports,
            whitebox_static,
            tally,
            core_findings,
            whitebox_artifacts,
            post_processing: &post_processing,
            artifacts: &artifacts,
            lines,
        })?;
        Ok((artifacts, result))
    }
}

fn sast_workspace<'a>(
    ctx: &'a ToolExecutionContext<'_>,
) -> Result<&'a crate::workspace::WorkspaceTarget> {
    ctx.workspace
        .context(crate::workspace::active_workspace_required_message(
            "sast:scan",
        ))
}

fn sast_store<'a>(ctx: &'a ToolExecutionContext<'_>) -> Result<&'a crate::findings::FindingStore> {
    ctx.findings_store
        .context("sast:scan requires a findings store")
}

fn sast_subtool_options(
    ctx: &ToolExecutionContext<'_>,
    workspace: &crate::workspace::WorkspaceTarget,
) -> Result<crate::options::ToolOptionStore> {
    let paths = tool_context_config_paths(ctx, Some(workspace.root()))?;
    persistent_tool_options_for_paths(&paths)
}

fn write_sast_whitebox_artifacts(
    input: &Value,
    workspace: &crate::workspace::WorkspaceTarget,
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
    whitebox_static: bool,
) -> Result<WhiteboxArtifacts> {
    WhiteboxArtifacts::write(whitebox_static, input, workspace, store, run_ids, artifacts)
}

struct SastScanResultParts<'a> {
    primary_run_id: String,
    run_ids: SastRunIds,
    workspace: &'a crate::workspace::WorkspaceTarget,
    reports: &'a SastPipelineReports,
    whitebox_static: Option<&'a WhiteboxStaticPolicy>,
    tally: SastFindingTally,
    core_findings: Vec<crate::findings::Finding>,
    whitebox_artifacts: WhiteboxArtifacts,
    post_processing: &'a SastPostProcessing,
    artifacts: &'a SastRunArtifacts,
    lines: Vec<String>,
}

fn sast_scan_result(parts: SastScanResultParts<'_>) -> Result<Value> {
    let cost = sast_cost_report(parts.reports, parts.post_processing)?;
    let output = parts.lines.join("\n");
    let summary = output
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("sast:scan completed")
        .to_string();
    let mut warnings = sast_scan_warnings(parts.reports);
    warnings.extend(threat_model_feedback_warning(parts.post_processing));
    let partial = sast_scan_has_partial_engine(parts.reports);
    let data = sast_scan_data(parts)?;
    let mut result = sast_scan_result_envelope(summary, output, warnings, data, partial);
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    Ok(result)
}

fn sast_scan_warnings(reports: &SastPipelineReports) -> Vec<Value> {
    let mut warnings = reports
        .skipped_engines
        .iter()
        .map(|skipped| json!(skipped.warning))
        .collect::<Vec<_>>();
    warnings.extend(
        reports
            .engine_outcomes
            .iter()
            .filter_map(|(engine, outcome)| match outcome {
                ScanEngineStageOutcome::Partial => {
                    Some(json!(format!("{engine} returned a usable partial result")))
                }
                ScanEngineStageOutcome::Skipped => Some(json!(skipped_engine_warning(
                    engine,
                    reports.engine_skip_reasons.get(engine)
                ))),
                ScanEngineStageOutcome::Complete | ScanEngineStageOutcome::Failed => None,
            }),
    );
    warnings
}

fn skipped_engine_warning(engine: &str, reason: Option<&String>) -> String {
    match reason {
        Some(reason) => format!("{engine} was skipped: {reason}"),
        None => format!("{engine} was skipped"),
    }
}

fn sast_scan_result_envelope(
    summary: String,
    output: String,
    warnings: Vec<Value>,
    data: Value,
    partial: bool,
) -> Value {
    if partial {
        return crate::module_result::partial_output_result(summary, output, warnings, data);
    }
    let mut result = crate::module_result::completed_output_result(summary, output, data);
    result["warnings"] = Value::Array(warnings);
    result
}

fn sast_scan_has_partial_engine(reports: &SastPipelineReports) -> bool {
    reports
        .engine_outcomes
        .iter()
        .any(|(engine, outcome)| reports.engine_degrades_scan(engine, *outcome))
}

fn sast_scan_data(parts: SastScanResultParts<'_>) -> Result<Value> {
    let paths = parts.whitebox_artifacts.artifact_paths(parts.artifacts);
    let phase_stages = load_sast_phase_stages(parts.artifacts)?;
    Ok(json!({
        "runId": parts.primary_run_id,
        "runIds": sast_run_ids_json(parts.run_ids),
        "phaseStages": phase_stages,
        "target": parts.workspace.root().display().to_string(),
        "mode": whitebox_mode_label(parts.whitebox_static),
        "whiteboxStatic": parts.whitebox_static.map(|policy| policy.to_json()),
        "findingsCount": parts.tally.distinct,
        "observationsCount": parts.tally.observations,
        "coreFindings": parts.core_findings,
        "db": parts.workspace.findings_db_path().display().to_string(),
        "engines": parts.reports.engine_ids.clone(),
        "skippedEngines": parts.reports.skipped_engines.iter().map(|skipped| skipped.id).collect::<Vec<_>>(),
        "agentic": parts.reports.agentic.as_ref().map(|report| json!(report)),
        "carliniThreatHunt": parts.reports.carlini.as_ref().map(|report| json!(report)),
        "taintIrisNext": parts.reports.taint_iris_next.as_ref().map(|report| json!(report)),
        "systemsHunt": parts.reports.systems_hunt.as_ref().map(|report| json!(report)),
        "staticRanking": parts.whitebox_artifacts.static_ranking,
        "staticNarratives": parts.whitebox_artifacts.static_narratives,
        "staticVariants": parts.whitebox_artifacts.static_variants,
        "candidateSemgrepRules": parts.whitebox_artifacts.candidate_semgrep_rules,
        "whiteboxSuppressions": parts.whitebox_artifacts.whitebox_suppressions,
        "whiteboxDiff": parts.whitebox_artifacts.whitebox_diff,
        "triage": triage_json(parts.post_processing),
        "verification": verification_json(parts.post_processing),
        "patch": patch_json(parts.post_processing),
        "threatModelFeedback": threat_model_feedback_json(parts.post_processing),
        "artifacts": sast_artifacts_json(parts.artifacts, paths),
    }))
}

fn sast_cost_report(
    reports: &SastPipelineReports,
    post_processing: &SastPostProcessing,
) -> Result<crate::runtime::RuntimeCostReport> {
    let mut total = crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO);
    for report in sast_engine_cost_reports(reports)? {
        total = total.checked_add(report, "SAST engine aggregated cost")?;
    }
    if let Some(triage) = post_processing.triage.as_ref() {
        total = total.checked_add(tool_output_cost_report(triage)?, "SAST triage cost")?;
    }
    for output in post_processing
        .verification_results
        .iter()
        .chain(post_processing.patch_results.iter())
        .chain(costed_feedback(post_processing))
    {
        total = total.checked_add(tool_output_cost_report(output)?, "SAST post-process cost")?;
    }
    Ok(total)
}

fn sast_engine_cost_reports(
    reports: &SastPipelineReports,
) -> Result<Vec<crate::runtime::RuntimeCostReport>> {
    [
        reports
            .agentic
            .as_ref()
            .map(|report| (report.cost_usd, report.cost_usd_exact, "agentic SAST")),
        reports
            .carlini
            .as_ref()
            .map(|report| (report.cost_usd, report.cost_usd_exact, "Carlini")),
        reports
            .taint_iris_next
            .as_ref()
            .map(|report| (report.cost_usd, report.cost_usd_exact, "taint iris next")),
        reports
            .systems_hunt
            .as_ref()
            .map(|report| (report.cost_usd, report.cost_usd_exact, "systems hunt")),
    ]
    .into_iter()
    .flatten()
    .map(|(cost, exact, label)| cost_report_from_fields(cost, exact, label))
    .collect()
}

fn cost_report_from_fields(
    cost_usd: f64,
    exact: bool,
    label: &str,
) -> Result<crate::runtime::RuntimeCostReport> {
    let observed = crate::runtime::RuntimeCost::from_usd(cost_usd, label)?;
    Ok(if exact {
        crate::runtime::RuntimeCostReport::known(observed)
    } else {
        crate::runtime::RuntimeCostReport::incomplete(observed)
    })
}

fn tool_output_cost_report(output: &Value) -> Result<crate::runtime::RuntimeCostReport> {
    crate::run_artifacts::tool_run_output_cost_report(output)
}

fn sast_run_ids_json(run_ids: SastRunIds) -> Value {
    json!({
        "parent": run_ids.primary,
        "native": run_ids.native,
        "agentic": run_ids.agentic,
        "carlini": run_ids.carlini,
        "taintIrisNext": run_ids.taint_iris_next,
        "systemsHunt": run_ids.systems_hunt,
    })
}

/// The feedback output only when it carries a cost claim: a refusal
/// synthesized by the scan made no model call and has none.
fn costed_feedback(post_processing: &SastPostProcessing) -> Option<&Value> {
    post_processing
        .threat_model_feedback
        .as_ref()
        .filter(|output| output.get("costUsd").is_some() || output.get("observedCostUsd").is_some())
}

fn threat_model_feedback_json(post_processing: &SastPostProcessing) -> Option<Value> {
    let output = post_processing.threat_model_feedback.as_ref()?;
    Some(json!({
        "status": output.get("status").cloned().unwrap_or(Value::Null),
        "summary": output.get("summary").cloned().unwrap_or(Value::Null),
        "refineDelta": output.pointer("/data/document/provenance/refineDelta").cloned(),
    }))
}

fn threat_model_feedback_warning(post_processing: &SastPostProcessing) -> Option<Value> {
    let output = post_processing.threat_model_feedback.as_ref()?;
    let status = output.get("status").and_then(Value::as_str).unwrap_or("unknown");
    (status != "completed").then(|| {
        let summary = output.get("summary").and_then(Value::as_str).unwrap_or(status);
        json!(format!("threat-model feedback did not complete: {summary}"))
    })
}

fn triage_json(post_processing: &SastPostProcessing) -> Option<Value> {
    post_processing
        .triage
        .as_ref()
        .and_then(|value| value.get("data"))
        .cloned()
}

fn verification_json(post_processing: &SastPostProcessing) -> Value {
    json!({
        "verified": post_processing.verification_results.len(),
        "results": post_processing.verification_results
            .iter()
            .filter_map(|value| value.get("data").cloned())
            .collect::<Vec<_>>(),
    })
}

fn patch_json(post_processing: &SastPostProcessing) -> Value {
    json!({
        "patched": post_processing.patch_results.len(),
        "results": post_processing.patch_results
            .iter()
            .filter_map(|value| value.get("data").cloned())
            .collect::<Vec<_>>(),
    })
}

fn sast_artifacts_json(artifacts: &SastRunArtifacts, paths: WhiteboxArtifactPaths) -> Value {
    json!({
        "dir": artifacts.dir.display().to_string(),
        "input": artifacts.scan_input.display().to_string(),
        "summary": artifacts.sast_summary.display().to_string(),
        "findings": artifacts.dir.join("findings.json").display().to_string(),
        "staticNarratives": paths.static_narratives,
        "staticVariants": paths.static_variants,
        "candidateSemgrepRules": paths.candidate_semgrep_rules,
        "whiteboxSuppressions": paths.whitebox_suppressions,
        "whiteboxDiff": paths.whitebox_diff,
        "triageJsonl": artifacts.triage_jsonl.display().to_string(),
        "verifyJsonl": artifacts.verify_jsonl.display().to_string(),
        "patchJsonl": artifacts.patch_jsonl.display().to_string(),
        "phaseStagesJsonl": artifacts.dir.join(SAST_PHASE_STAGES_JSONL_FILE).display().to_string(),
    })
}

#[cfg(test)]
mod execution_model_tests {
    use super::*;

    #[test]
    fn scanner_only_scan_does_not_claim_the_configured_model() {
        let input = json!({
            "taskMode": "manual",
            "tasks": ["secret-scan", "iac-scan"],
            "triage": false,
            "verify": false,
            "autoPatch": false,
        });

        assert_eq!(sast_execution_model(&input, Some("openai:gpt-5.5")), None);
    }

    #[test]
    fn runtime_scan_records_the_effective_model() {
        let configured = json!({ "triage": true });
        assert_eq!(
            sast_execution_model(&configured, Some("openai:gpt-5.5")),
            Some("openai:gpt-5.5".to_string())
        );

        let explicit = json!({ "triage": true, "model": "anthropic:claude-sonnet-4-6" });
        assert_eq!(
            sast_execution_model(&explicit, Some("openai:gpt-5.5")),
            Some("anthropic:claude-sonnet-4-6".to_string())
        );
    }
}

#[cfg(test)]
mod scan_result_outcome_tests {
    use super::*;
    use crate::{tool_result_status, ToolResultStatus};
    use std::collections::BTreeMap;

    #[test]
    fn optional_preflight_skip_warns_without_making_the_scan_partial() {
        let result = sast_scan_result_envelope(
            "scan retained usable results".to_string(),
            "scan retained usable results".to_string(),
            vec![json!("cargo-audit skipped")],
            json!({"phaseStages": [{"phase": "scan", "outcome": "completed"}]}),
            false,
        );

        assert_eq!(result["status"], "completed");
        assert_eq!(result["ok"], true);
        assert_eq!(result["warnings"], json!(["cargo-audit skipped"]));
        assert_eq!(tool_result_status(&result), ToolResultStatus::Completed);
    }

    #[test]
    fn typed_engine_outcomes_retain_recorded_partial_and_failed_status() {
        let reports = reports_with_outcomes(&[
            ("agentic", ScanEngineStageOutcome::Partial),
            ("systems-hunt", ScanEngineStageOutcome::Failed),
        ]);
        let run_ids = reports.run_ids("parent".to_string());

        let engines = scan_stage_engines(&reports, &run_ids).unwrap();

        assert_eq!(engines[0].engine, "agentic");
        assert_eq!(engines[0].outcome, ScanEngineStageOutcome::Partial);
        assert_eq!(engines[1].engine, "systems-hunt");
        assert_eq!(engines[1].outcome, ScanEngineStageOutcome::Failed);
        assert_eq!(scan_stage_outcome(&reports), PhaseStageOutcome::Failed);
    }

    #[test]
    fn partial_child_makes_scan_stage_and_composite_result_partial() {
        let reports = reports_with_outcomes(&[("agentic", ScanEngineStageOutcome::Partial)]);

        let warnings = sast_scan_warnings(&reports);
        let result = sast_scan_result_envelope(
            "partial".into(),
            "partial".into(),
            warnings,
            json!({}),
            true,
        );

        assert_eq!(scan_stage_outcome(&reports), PhaseStageOutcome::Partial);
        assert_eq!(tool_result_status(&result), ToolResultStatus::Partial);
    }

    #[test]
    fn operator_cancellation_marks_unsettled_engine_tasks_canceled() {
        let (status, detail) =
            scan_pipeline_stop_task_terminal(Some(crate::scan::CancellationDisposition::Canceled));

        assert_eq!(status, crate::run_lifecycle::RunItemStatus::Canceled);
        assert_eq!(detail, "engine stopped after scan cancellation");
    }

    #[test]
    fn abnormal_pipeline_stop_keeps_unsettled_engine_tasks_interrupted() {
        let (status, _) = scan_pipeline_stop_task_terminal(None);

        assert_eq!(status, crate::run_lifecycle::RunItemStatus::Interrupted);
    }

    #[test]
    fn an_inapplicable_engine_skip_keeps_the_scan_complete() {
        let mut reports = reports_with_outcomes(&[
            ("agentic", ScanEngineStageOutcome::Complete),
            ("systems-hunt", ScanEngineStageOutcome::Skipped),
        ]);
        reports.engines_not_applicable.insert("systems-hunt");

        assert!(!sast_scan_has_partial_engine(&reports));
        assert_eq!(scan_stage_outcome(&reports), PhaseStageOutcome::Completed);
    }

    #[test]
    fn any_other_engine_skip_still_makes_the_scan_partial() {
        let reports = reports_with_outcomes(&[
            ("agentic", ScanEngineStageOutcome::Complete),
            ("systems-hunt", ScanEngineStageOutcome::Skipped),
        ]);

        assert!(sast_scan_has_partial_engine(&reports));
        assert_eq!(scan_stage_outcome(&reports), PhaseStageOutcome::Partial);
    }

    fn post_processing_with_feedback(feedback: Option<Value>) -> SastPostProcessing {
        SastPostProcessing {
            triage: None,
            verification_results: Vec::new(),
            patch_results: Vec::new(),
            threat_model_feedback: feedback,
        }
    }

    #[test]
    fn a_completed_refine_reports_its_delta_without_a_warning() {
        let processed = post_processing_with_feedback(Some(json!({
            "status": "completed",
            "summary": "threat-model:build complete",
            "data": {"document": {"provenance": {"refineDelta": {"variantPatterns": 2}}}},
        })));

        assert!(threat_model_feedback_warning(&processed).is_none());
        let data = threat_model_feedback_json(&processed).unwrap();
        assert_eq!(data["refineDelta"]["variantPatterns"], 2);
        assert!(threat_model_feedback_json(&post_processing_with_feedback(None)).is_none());
    }

    #[test]
    fn a_refused_refine_is_a_visible_warning_without_a_cost_claim() {
        let processed = post_processing_with_feedback(Some(json!({
            "ok": false,
            "status": "failed",
            "summary": "threat-model refine failed: run a full build first",
        })));

        assert_eq!(
            threat_model_feedback_warning(&processed).unwrap(),
            "threat-model feedback did not complete: threat-model refine failed: run a full build first"
        );
        assert!(costed_feedback(&processed).is_none());
    }

    fn reports_with_outcomes(
        outcomes: &[(&'static str, ScanEngineStageOutcome)],
    ) -> SastPipelineReports {
        SastPipelineReports {
            native: None,
            agentic: None,
            carlini: None,
            taint_iris_next: None,
            systems_hunt: None,
            engine_ids: outcomes.iter().map(|(engine, _)| *engine).collect(),
            engine_outcomes: outcomes.iter().copied().collect::<BTreeMap<_, _>>(),
            skipped_engines: Vec::new(),
            engine_skip_reasons: Default::default(),
            engines_not_applicable: Default::default(),
        }
    }
}

#[cfg(test)]
mod scan_severity_count_tests {
    use super::*;
    use crate::findings::{Finding, Severity};

    #[test]
    fn buckets_order_highest_band_first_and_omit_empty_bands() {
        let findings = [
            Severity::Medium,
            Severity::Critical,
            Severity::Medium,
            Severity::Unknown,
        ]
        .into_iter()
        .map(|severity| Finding {
            severity,
            ..Finding::default()
        })
        .collect::<Vec<_>>();

        let counts = scan_severity_counts(&findings);

        assert_eq!(
            counts,
            vec![
                ScanSeverityCount {
                    severity: Severity::Critical,
                    count: 1,
                },
                ScanSeverityCount {
                    severity: Severity::Medium,
                    count: 2,
                },
                ScanSeverityCount {
                    severity: Severity::Unknown,
                    count: 1,
                },
            ]
        );
        assert!(scan_severity_counts(&[]).is_empty());
    }
}
