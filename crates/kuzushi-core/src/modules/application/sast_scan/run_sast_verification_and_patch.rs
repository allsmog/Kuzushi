use super::*;

pub(in crate::modules) fn run_sast_verification_and_patch(
    registry: &ModuleRegistry,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
    requests: &SastScanRequests,
) -> Result<(Vec<Value>, Vec<Value>)> {
    let mut verification_results = Vec::new();
    let mut patch_results = Vec::new();
    for fingerprint in true_positive_fingerprints_for_sast_runs(store, run_ids)? {
        let result = run_sast_verification_for_fingerprint(
            registry,
            input,
            ctx,
            runtime,
            option_store,
            artifacts,
            requests,
            fingerprint,
        )?;
        verification_results.push(result.verification);
        patch_results.extend(result.patch);
    }
    Ok((verification_results, patch_results))
}

struct SastVerificationResult {
    verification: Value,
    patch: Option<Value>,
}

fn run_sast_verification_for_fingerprint(
    registry: &ModuleRegistry,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    artifacts: &SastRunArtifacts,
    requests: &SastScanRequests,
    fingerprint: String,
) -> Result<SastVerificationResult> {
    let verification = run_sast_verifier(
        registry,
        input,
        ctx,
        runtime,
        option_store,
        fingerprint.clone(),
    )?;
    write_verify_jsonl(artifacts, &verification)?;
    let patch = run_optional_sast_patch(
        registry,
        input,
        ctx,
        runtime,
        option_store,
        artifacts,
        requests,
        &fingerprint,
        &verification,
    )?;
    Ok(SastVerificationResult {
        verification,
        patch,
    })
}

fn run_sast_verifier(
    registry: &ModuleRegistry,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    fingerprint: String,
) -> Result<Value> {
    let verify_input = with_sast_prompt_override(
        json!({ "fingerprint": fingerprint }),
        input,
        ctx,
        "verify",
        "VERIFY_PROMPT",
    )?;
    run_sast_subtool(
        registry,
        "verify:finding",
        verify_input,
        ctx,
        runtime,
        option_store,
    )
}

fn run_optional_sast_patch(
    registry: &ModuleRegistry,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    artifacts: &SastRunArtifacts,
    requests: &SastScanRequests,
    fingerprint: &str,
    verification: &Value,
) -> Result<Option<Value>> {
    if !requests.auto_patch || !sast_verification_exploitable(verification) {
        return Ok(None);
    }
    let patch = run_sast_subtool(
        registry,
        "patch:finding",
        sast_patch_input(input, fingerprint),
        ctx,
        runtime,
        option_store,
    )?;
    write_patch_jsonl(artifacts, fingerprint, &patch)?;
    Ok(Some(patch))
}

fn sast_verification_exploitable(verification: &Value) -> bool {
    verification
        .pointer("/data/exploitable")
        .and_then(Value::as_bool)
        .unwrap_or(false)
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
