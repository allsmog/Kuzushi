use super::*;
use crate::WorkspaceTarget;

pub(in crate::modules) fn run_sast_scan_with_registry(
    registry: &ModuleRegistry,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let (mut input, whitebox_static) = apply_whitebox_static_sast_policy(input)?;
    let workspace = sast_workspace(ctx)?;
    let store = sast_store(ctx)?;
    let primary_run_id = canonical_sast_run_id(&input, ctx);
    set_canonical_sast_run_id(&mut input, &primary_run_id);
    ensure_sast_run_started(registry, workspace, &primary_run_id, &input, ctx)?;
    let result = run_started_sast_scan(
        registry,
        input,
        ctx,
        runtime,
        workspace,
        store,
        primary_run_id.clone(),
        whitebox_static,
    );
    match result {
        Ok(output) => Ok(output),
        Err(error) => {
            let persistence = persist_sast_terminal_error(
                workspace,
                &primary_run_id,
                &error,
                sast_execution_was_canceled(ctx),
            );
            Err(error_with_persistence(error, persistence))
        }
    }
}

fn sast_execution_was_canceled(ctx: &ToolExecutionContext<'_>) -> bool {
    ctx.cancellation
        .is_some_and(crate::scan::ScanCancellation::is_cancelled)
}

fn persist_sast_terminal_error(
    workspace: &WorkspaceTarget,
    run_id: &str,
    error: &anyhow::Error,
    canceled: bool,
) -> Result<()> {
    let record =
        crate::run_artifacts::ToolRunRecord::new(workspace.root(), run_id, "scan", "sast:scan");
    if canceled {
        return crate::run_artifacts::try_record_tool_run_canceled(record, &error.to_string());
    }
    crate::run_artifacts::try_record_tool_run_failed(record, &error.to_string())
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
) -> Result<Value> {
    let requests = SastScanRequests::from_input(&input)?;
    let options = sast_scan_options(&input, whitebox_static.is_some())?;
    let option_store = sast_subtool_options(ctx, workspace)?;
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
    })?;
    let findings_count = executed.findings_count;
    let (artifacts, result) = executed.into_result(workspace, whitebox_static.as_ref())?;
    let summary_artifact = write_sast_summary(workspace, &primary_run_id, &artifacts, &result)?;
    write_sast_run_metadata(
        workspace,
        &primary_run_id,
        findings_count,
        &artifacts,
        summary_artifact,
        &result,
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
}

impl SastScanExecutionInput<'_> {
    fn reports(&self) -> Result<SastPipelineReports> {
        run_sast_pipeline_reports(
            self.registry,
            self.input,
            self.ctx,
            self.runtime,
            self.option_store,
            self.workspace,
            self.store,
            self.options,
        )
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
        )
    }

    fn output_lines(
        &self,
        primary_run_id: &str,
        findings_count: usize,
        reports: &SastPipelineReports,
        whitebox_artifacts: &WhiteboxArtifacts,
        post_processing: &SastPostProcessing,
    ) -> Vec<String> {
        sast_output_lines(
            primary_run_id,
            findings_count,
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
    findings_count: usize,
    core_findings: Vec<crate::findings::Finding>,
    whitebox_artifacts: WhiteboxArtifacts,
    post_processing: SastPostProcessing,
    lines: Vec<String>,
}

fn execute_sast_scan(input: SastScanExecutionInput<'_>) -> Result<ExecutedSastScan> {
    let primary_run_id = input.primary_run_id.to_string();
    let artifacts = SastRunArtifacts::create(input.workspace, &primary_run_id)?;
    write_sast_scan_input(input.workspace, &primary_run_id, &artifacts, input.input)?;
    let reports = input.reports()?;
    let run_ids = reports.run_ids(primary_run_id.clone());
    let whitebox_artifacts = input.whitebox_artifacts(&run_ids, &artifacts)?;
    let post_processing = input.post_processing(&run_ids, &artifacts)?;
    let core_findings = findings_for_sast_runs(input.store, &run_ids)?;
    let findings_count = core_findings.len();
    let lines = input.output_lines(
        primary_run_id.as_str(),
        findings_count,
        &reports,
        &whitebox_artifacts,
        &post_processing,
    );
    Ok(ExecutedSastScan {
        primary_run_id,
        run_ids,
        artifacts,
        reports,
        findings_count,
        core_findings,
        whitebox_artifacts,
        post_processing,
        lines,
    })
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
            findings_count,
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
            findings_count,
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
    findings_count: usize,
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
    let warnings = parts
        .reports
        .skipped_engines
        .iter()
        .map(|skipped| json!(skipped.warning))
        .collect::<Vec<_>>();
    let mut result =
        crate::module_result::completed_output_result(summary, output, sast_scan_data(parts)?);
    result["warnings"] = json!(warnings);
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    Ok(result)
}

fn sast_scan_data(parts: SastScanResultParts<'_>) -> Result<Value> {
    let paths = parts.whitebox_artifacts.artifact_paths(parts.artifacts);
    Ok(json!({
        "runId": parts.primary_run_id,
        "runIds": sast_run_ids_json(parts.run_ids),
        "target": parts.workspace.root().display().to_string(),
        "mode": whitebox_mode_label(parts.whitebox_static),
        "whiteboxStatic": parts.whitebox_static.map(|policy| policy.to_json()),
        "findingsCount": parts.findings_count,
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
        "staticNarratives": paths.static_narratives,
        "staticVariants": paths.static_variants,
        "candidateSemgrepRules": paths.candidate_semgrep_rules,
        "whiteboxSuppressions": paths.whitebox_suppressions,
        "whiteboxDiff": paths.whitebox_diff,
        "triageJsonl": artifacts.triage_jsonl.display().to_string(),
        "verifyJsonl": artifacts.verify_jsonl.display().to_string(),
        "patchJsonl": artifacts.patch_jsonl.display().to_string(),
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
