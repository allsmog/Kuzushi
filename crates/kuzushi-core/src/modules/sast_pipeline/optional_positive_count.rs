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
    requests: &SastScanRequests,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<SastPostProcessing> {
    let triage = if requests.triage {
        Some(run_sast_triage(ctx, runtime, store, run_ids, artifacts)?)
    } else {
        None
    };
    let (verification_results, patch_results) = if requests.needs_verification() {
        run_sast_verification_and_patch(input, ctx, runtime, store, run_ids, artifacts, requests)?
    } else {
        (Vec::new(), Vec::new())
    };

    Ok(SastPostProcessing {
        triage,
        verification_results,
        patch_results,
    })
}

pub(in crate::modules) fn run_sast_triage(
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
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
    let output = run_triage(triage_input, ctx, runtime)?;
    write_triage_jsonl(artifacts, &output)?;
    Ok(output)
}
