use super::*;

pub(in crate::modules) struct WhiteboxArtifactPaths {
    pub(in crate::modules) static_narratives: Option<String>,
    pub(in crate::modules) static_variants: Option<String>,
    pub(in crate::modules) candidate_semgrep_rules: Option<String>,
    pub(in crate::modules) whitebox_suppressions: Option<String>,
    pub(in crate::modules) whitebox_diff: Option<String>,
}

pub(in crate::modules) fn optional_positive_count(value: &Option<Value>, key: &str) -> Option<u64> {
    value
        .as_ref()
        .and_then(|value| value.get(key))
        .and_then(Value::as_u64)
        .filter(|count| *count > 0)
}

pub(in crate::modules) fn json_u64(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or_default()
}

pub(in crate::modules) fn json_pointer_u64(value: &Value, pointer: &str) -> u64 {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .unwrap_or_default()
}

pub(in crate::modules) fn artifact_path_if_present(
    value: &Option<Value>,
    artifacts: &SastRunArtifacts,
    filename: &str,
) -> Option<String> {
    value
        .as_ref()
        .map(|_| artifacts.dir.join(filename).display().to_string())
}

pub(in crate::modules) struct SastPostProcessing {
    pub(in crate::modules) triage: Option<Value>,
    pub(in crate::modules) verification_results: Vec<Value>,
    pub(in crate::modules) patch_results: Vec<Value>,
}

pub(in crate::modules) fn run_sast_post_processing(
    registry: &ModuleRegistry,
    requests: &SastScanRequests,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<SastPostProcessing> {
    let triage = run_optional_sast_triage(
        registry,
        requests,
        input,
        ctx,
        runtime,
        option_store,
        store,
        run_ids,
        artifacts,
    )?;
    let (verification_results, patch_results) = run_optional_sast_verification_and_patch(
        registry,
        requests,
        input,
        ctx,
        runtime,
        option_store,
        store,
        run_ids,
        artifacts,
    )?;
    Ok(SastPostProcessing {
        triage,
        verification_results,
        patch_results,
    })
}

fn run_optional_sast_triage(
    registry: &ModuleRegistry,
    requests: &SastScanRequests,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<Option<Value>> {
    if !requests.triage {
        return Ok(None);
    }
    run_sast_triage(
        registry,
        input,
        ctx,
        runtime,
        option_store,
        store,
        run_ids,
        artifacts,
    )
    .map(Some)
}

fn run_optional_sast_verification_and_patch(
    registry: &ModuleRegistry,
    requests: &SastScanRequests,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<(Vec<Value>, Vec<Value>)> {
    if !requests.needs_verification() {
        return Ok((Vec::new(), Vec::new()));
    }
    run_sast_verification_and_patch(
        registry,
        input,
        ctx,
        runtime,
        option_store,
        store,
        run_ids,
        artifacts,
        requests,
    )
}

pub(in crate::modules) fn run_sast_triage(
    registry: &ModuleRegistry,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<Value> {
    let fingerprints = fingerprints_for_sast_runs(store, run_ids)?;
    let triage_input = if fingerprints.is_empty() {
        json!({ "scanId": run_ids.primary.clone() })
    } else {
        json!({ "fingerprints": fingerprints })
    };
    let triage_input =
        with_sast_prompt_override(triage_input, input, ctx, "triage", "TRIAGE_PROMPT")?;
    let output = run_sast_subtool(
        registry,
        "triage:run",
        triage_input,
        ctx,
        runtime,
        option_store,
    )?;
    write_triage_jsonl(artifacts, &output)?;
    Ok(output)
}

pub(in crate::modules) fn run_sast_subtool(
    registry: &ModuleRegistry,
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
) -> Result<Value> {
    registry.execute_tool_with_runtime_and_options(name, input, ctx, runtime, Some(option_store))
}
