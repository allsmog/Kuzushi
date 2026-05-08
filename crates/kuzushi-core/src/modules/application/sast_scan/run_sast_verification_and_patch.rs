use super::*;

pub(in crate::modules) fn run_sast_verification_and_patch(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
    requests: &SastScanRequests,
) -> Result<(Vec<Value>, Vec<Value>)> {
    let mut verification_results = Vec::new();
    let mut patch_results = Vec::new();
    for fingerprint in true_positive_fingerprints_for_sast_runs(store, run_ids)? {
        let fingerprint_for_patch = fingerprint.clone();
        let verification = run_verify_finding(json!({ "fingerprint": fingerprint }), ctx, runtime)?;
        write_verify_jsonl(artifacts, &verification)?;
        let exploitable = verification
            .pointer("/data/exploitable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        verification_results.push(verification);

        if requests.auto_patch && exploitable {
            let patch = run_patch_finding(
                sast_patch_input(input, &fingerprint_for_patch),
                ctx,
                runtime,
            )?;
            write_patch_jsonl(artifacts, &fingerprint_for_patch, &patch)?;
            patch_results.push(patch);
        }
    }
    Ok((verification_results, patch_results))
}

pub(in crate::modules) fn sast_output_lines(
    primary_run_id: &str,
    findings_count: usize,
    workspace: &crate::workspace::WorkspaceTarget,
    reports: &SastPipelineReports,
    whitebox_enabled: bool,
    whitebox_artifacts: &WhiteboxArtifacts,
    post_processing: &SastPostProcessing,
    requests: &SastScanRequests,
) -> Vec<String> {
    let mut lines = vec![format!(
        "sast:scan {} completed: {} finding(s), db {}",
        primary_run_id,
        findings_count,
        workspace.findings_db_path().display()
    )];
    if whitebox_enabled {
        whitebox_artifacts.append_output_lines(&mut lines);
    }
    lines.push(format!("  Engines: {}", reports.engine_ids.join(", ")));
    append_triage_output_line(&mut lines, post_processing.triage.as_ref());
    if requests.needs_verification() {
        lines.push(format!(
            "      verified={} patched={}",
            post_processing.verification_results.len(),
            post_processing.patch_results.len()
        ));
    }
    lines
}

pub(in crate::modules) fn append_triage_output_line(
    lines: &mut Vec<String>,
    triage: Option<&Value>,
) {
    if let Some(triage_output) = triage
        .and_then(|value| value.get("output"))
        .and_then(Value::as_str)
    {
        lines.push(triage_output.to_string());
    }
}

pub(in crate::modules) fn whitebox_mode_label(
    whitebox_static: Option<&WhiteboxStaticPolicy>,
) -> &str {
    whitebox_static.map_or("standard", |policy| policy.mode.as_str())
}
