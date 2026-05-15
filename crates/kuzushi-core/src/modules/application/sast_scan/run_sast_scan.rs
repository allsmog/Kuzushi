use super::*;

pub(in crate::modules) fn run_sast_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let (input, whitebox_static) = apply_whitebox_static_sast_policy(input)?;
    let workspace = sast_workspace(ctx)?;
    let store = sast_store(ctx)?;
    let requests = SastScanRequests::from_input(&input)?;
    let options = sast_scan_options(&input, whitebox_static.is_some())?;
    let executed = execute_sast_scan(SastScanExecutionInput {
        input: &input,
        ctx,
        runtime,
        workspace,
        store,
        requests: &requests,
        options: &options,
        whitebox_static: whitebox_static.is_some(),
    })?;
    let primary_run_id = executed.primary_run_id.clone();
    let findings_count = executed.findings_count;
    let (artifacts, result) = executed.into_result(workspace, whitebox_static.as_ref());
    let summary_artifact = write_sast_summary(workspace, &primary_run_id, &artifacts, &result)?;
    write_sast_run_metadata(
        workspace,
        &primary_run_id,
        findings_count,
        summary_artifact,
        &result,
    )?;
    Ok(result)
}

struct SastScanExecutionInput<'a> {
    input: &'a Value,
    ctx: &'a ToolExecutionContext<'a>,
    runtime: Option<&'a dyn AgentRuntime>,
    workspace: &'a crate::workspace::WorkspaceTarget,
    store: &'a crate::findings::FindingStore,
    requests: &'a SastScanRequests,
    options: &'a ScanRunOptions,
    whitebox_static: bool,
}

impl SastScanExecutionInput<'_> {
    fn reports(&self) -> Result<SastPipelineReports> {
        run_sast_pipeline_reports(
            self.input,
            self.ctx,
            self.runtime,
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
            self.requests,
            self.input,
            self.ctx,
            self.runtime,
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
    let reports = input.reports()?;
    let findings_count = reports.findings_count();
    let primary_run_id = reports.primary_run_id()?;
    let run_ids = reports.run_ids(primary_run_id.clone());
    let artifacts = SastRunArtifacts::create(input.workspace, &primary_run_id)?;
    write_sast_scan_input(&artifacts, input.input)?;
    let whitebox_artifacts = input.whitebox_artifacts(&run_ids, &artifacts)?;
    let post_processing = input.post_processing(&run_ids, &artifacts)?;
    let core_findings = findings_for_sast_runs(input.store, &run_ids)?;
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
    ) -> (SastRunArtifacts, Value) {
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
        });
        (artifacts, result)
    }
}

fn sast_workspace<'a>(
    ctx: &'a ToolExecutionContext<'_>,
) -> Result<&'a crate::workspace::WorkspaceTarget> {
    ctx.workspace.context(
        "sast:scan requires a workspace target; pass --target <repo> or start the shell with --target <repo>",
    )
}

fn sast_store<'a>(
    ctx: &'a ToolExecutionContext<'_>,
) -> Result<&'a crate::findings::FindingStore> {
    ctx.findings_store
        .context("sast:scan requires a findings store")
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

fn sast_scan_result(parts: SastScanResultParts<'_>) -> Value {
    json!({
        "ok": true,
        "output": parts.lines.join("\n"),
        "data": sast_scan_data(parts),
    })
}

fn sast_scan_data(parts: SastScanResultParts<'_>) -> Value {
    let paths = parts.whitebox_artifacts.artifact_paths(parts.artifacts);
    json!({
        "runId": parts.primary_run_id,
        "runIds": sast_run_ids_json(parts.run_ids),
        "target": parts.workspace.root().display().to_string(),
        "mode": whitebox_mode_label(parts.whitebox_static),
        "whiteboxStatic": parts.whitebox_static.map(|policy| policy.to_json()),
        "findingsCount": parts.findings_count,
        "coreFindings": parts.core_findings,
        "db": parts.workspace.findings_db_path().display().to_string(),
        "engines": parts.reports.engine_ids.clone(),
        "agentic": parts.reports.agentic.as_ref().map(|report| json!(report)),
        "carliniThreatHunt": parts.reports.carlini.as_ref().map(|report| json!(report)),
        "taintIris": parts.reports.taint_iris.as_ref().map(|report| json!(report)),
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
    })
}

fn sast_run_ids_json(run_ids: SastRunIds) -> Value {
    json!({
        "native": run_ids.native,
        "agentic": run_ids.agentic,
        "carlini": run_ids.carlini,
        "taintIris": run_ids.taint_iris,
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
        "summary": artifacts.sast_summary.display().to_string(),
        "staticNarratives": paths.static_narratives,
        "staticVariants": paths.static_variants,
        "candidateSemgrepRules": paths.candidate_semgrep_rules,
        "whiteboxSuppressions": paths.whitebox_suppressions,
        "whiteboxDiff": paths.whitebox_diff,
        "triageJsonl": artifacts.triage_jsonl.display().to_string(),
        "verifyJsonl": artifacts.verify_jsonl.display().to_string(),
    })
}
