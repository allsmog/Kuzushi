use super::prelude::*;
use super::*;

pub(in crate::modules) fn run_sast_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let (input, whitebox_static) = apply_whitebox_static_sast_policy(input)?;
    let workspace = ctx
        .workspace
        .context("sast:scan requires a workspace target; pass --target <repo> or start the shell with --target <repo>")?;
    let store = ctx
        .findings_store
        .context("sast:scan requires a findings store")?;
    let requests = SastScanRequests::from_input(&input)?;
    let options = sast_scan_options(&input, whitebox_static.is_some())?;

    let reports = run_sast_pipeline_reports(&input, ctx, runtime, workspace, store, &options)?;
    let findings_count = reports.findings_count();
    let primary_run_id = reports.primary_run_id()?;
    let run_ids = reports.run_ids(primary_run_id.clone());
    let artifacts = SastRunArtifacts::create(workspace, &primary_run_id)?;
    write_sast_scan_input(&artifacts, &input)?;
    let whitebox_artifacts = WhiteboxArtifacts::write(
        whitebox_static.is_some(),
        &input,
        workspace,
        store,
        &run_ids,
        &artifacts,
    )?;
    let post_processing =
        run_sast_post_processing(&requests, &input, ctx, runtime, store, &run_ids, &artifacts)?;
    let lines = sast_output_lines(
        &primary_run_id,
        findings_count,
        workspace,
        &reports,
        whitebox_static.is_some(),
        &whitebox_artifacts,
        &post_processing,
        &requests,
    );
    let whitebox_artifact_paths = whitebox_artifacts.artifact_paths(&artifacts);

    let result = json!({
        "ok": true,
        "output": lines.join("\n"),
        "data": {
            "runId": primary_run_id,
            "runIds": {
                "native": run_ids.native,
                "agentic": run_ids.agentic,
                "carlini": run_ids.carlini,
                "taintIris": run_ids.taint_iris,
                "taintIrisNext": run_ids.taint_iris_next,
                "systemsHunt": run_ids.systems_hunt,
            },
            "target": workspace.root().display().to_string(),
            "mode": whitebox_mode_label(whitebox_static.as_ref()),
            "whiteboxStatic": whitebox_static.as_ref().map(|policy| policy.to_json()),
            "findingsCount": findings_count,
            "db": workspace.findings_db_path().display().to_string(),
            "engines": reports.engine_ids,
            "agentic": reports.agentic.as_ref().map(|report| json!(report)),
            "carliniThreatHunt": reports.carlini.as_ref().map(|report| json!(report)),
            "taintIris": reports.taint_iris.as_ref().map(|report| json!(report)),
            "taintIrisNext": reports.taint_iris_next.as_ref().map(|report| json!(report)),
            "systemsHunt": reports.systems_hunt.as_ref().map(|report| json!(report)),
            "staticRanking": whitebox_artifacts.static_ranking,
            "staticNarratives": whitebox_artifacts.static_narratives,
            "staticVariants": whitebox_artifacts.static_variants,
            "candidateSemgrepRules": whitebox_artifacts.candidate_semgrep_rules,
            "whiteboxSuppressions": whitebox_artifacts.whitebox_suppressions,
            "whiteboxDiff": whitebox_artifacts.whitebox_diff,
            "triage": post_processing.triage.as_ref().and_then(|value| value.get("data")).cloned(),
            "verification": {
                "verified": post_processing.verification_results.len(),
                "results": post_processing.verification_results
                    .iter()
                    .filter_map(|value| value.get("data").cloned())
                    .collect::<Vec<_>>(),
            },
            "patch": {
                "patched": post_processing.patch_results.len(),
                "results": post_processing.patch_results
                    .iter()
                    .filter_map(|value| value.get("data").cloned())
                    .collect::<Vec<_>>(),
            },
            "artifacts": {
                "dir": artifacts.dir.display().to_string(),
                "summary": artifacts.summary.display().to_string(),
                "staticNarratives": whitebox_artifact_paths.static_narratives,
                "staticVariants": whitebox_artifact_paths.static_variants,
                "candidateSemgrepRules": whitebox_artifact_paths.candidate_semgrep_rules,
                "whiteboxSuppressions": whitebox_artifact_paths.whitebox_suppressions,
                "whiteboxDiff": whitebox_artifact_paths.whitebox_diff,
                "triageJsonl": artifacts.triage_jsonl.display().to_string(),
                "verifyJsonl": artifacts.verify_jsonl.display().to_string(),
            },
        },
    });
    write_sast_summary(&artifacts, &result)?;

    Ok(result)
}
