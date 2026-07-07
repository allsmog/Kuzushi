use serde_json::Value;

pub(super) fn failure_handoff_summary(value: &Value) -> Option<String> {
    let status = value.get("status").and_then(Value::as_str)?;
    let failures = value.get("failures").and_then(Value::as_array)?;
    let mut parts = vec![format!("status {status}"), format!("{} failure(s)", failures.len())];
    parts.extend(named_segment("stages", failed_stage_summary(failures)));
    parts.extend(named_segment("proof limits", allowed_proof_level_summary(failures)));
    parts.extend(named_count("available artifacts", failures, available_artifact_count));
    parts.extend(named_count("missing artifacts", failures, missing_artifact_count));
    parts.extend(named_count("next artifacts", failures, next_artifact_count));
    parts.extend(named_count("what failed", failures, what_failed_count));
    parts.extend(named_count("recovery options", failures, recovery_option_count));
    parts.extend(named_count("fallback prompts", failures, fallback_prompt_count));
    parts.extend(named_count("claims forbidden", failures, forbidden_claim_count));
    Some(parts.join(", "))
}

fn named_segment(name: &str, value: Option<String>) -> Option<String> {
    value.map(|value| format!("{name} {value}"))
}

fn named_count(
    name: &str,
    failures: &[Value],
    count: fn(&Value) -> usize,
) -> Option<String> {
    let total = failures.iter().map(count).sum::<usize>();
    (total > 0).then(|| format!("{name} {total}"))
}

fn failed_stage_summary(failures: &[Value]) -> Option<String> {
    let stages = failures
        .iter()
        .filter_map(failed_stage)
        .take(3)
        .collect::<Vec<_>>();
    (!stages.is_empty()).then(|| stages.join(", "))
}

fn failed_stage(failure: &Value) -> Option<String> {
    failure
        .pointer("/agentThreadContext/failedStage")
        .or_else(|| failure.get("tool"))
        .and_then(Value::as_str)
        .filter(|stage| !stage.trim().is_empty())
        .map(str::to_string)
}

fn available_artifact_count(failure: &Value) -> usize {
    context_array_len(failure, "artifactsAvailable")
}

fn missing_artifact_count(failure: &Value) -> usize {
    context_array_len(failure, "missingArtifacts")
}

fn next_artifact_count(failure: &Value) -> usize {
    context_array_len(failure, "nextFilesOrArtifactsToInspect")
}

fn what_failed_count(failure: &Value) -> usize {
    context_string_present(failure, "whatFailed")
}

fn recovery_option_count(failure: &Value) -> usize {
    context_array_len(failure, "recoveryOptions")
}

fn fallback_prompt_count(failure: &Value) -> usize {
    context_string_present(failure, "fallbackPrompt")
}

fn forbidden_claim_count(failure: &Value) -> usize {
    context_array_len(failure, "claimsForbidden")
}

fn allowed_proof_level_summary(failures: &[Value]) -> Option<String> {
    let levels = failures
        .iter()
        .filter_map(allowed_proof_level)
        .take(3)
        .collect::<Vec<_>>();
    (!levels.is_empty()).then(|| levels.join(", "))
}

fn allowed_proof_level(failure: &Value) -> Option<String> {
    failure_context(failure)
        .and_then(|context| context.get("allowedProofLevel"))
        .and_then(Value::as_str)
        .filter(|level| !level.trim().is_empty())
        .map(str::to_string)
}

fn context_array_len(failure: &Value, field: &str) -> usize {
    failure_context(failure)
        .and_then(|context| context.get(field))
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

fn context_string_present(failure: &Value, field: &str) -> usize {
    usize::from(
        failure_context(failure)
            .and_then(|context| context.get(field))
            .and_then(Value::as_str)
            .is_some_and(|text| !text.trim().is_empty()),
    )
}

fn failure_context(failure: &Value) -> Option<&Value> {
    failure.get("agentThreadContext")
}
