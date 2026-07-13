use super::*;

pub(crate) fn query_deep_semantic_findings(
    runtime: &dyn AgentRuntime,
    model: String,
    input: &Value,
    target: &Path,
    cwes: &[DeepSemanticCweSelection],
    system_prompt: &str,
) -> Result<CostedStructuredJson<Value>> {
    let inventory = collect_inventory(target, 80, 2048)?;
    query_required_structured_json_with_cost(
        runtime,
        AgentQueryRequest::new(
            model,
            target.to_path_buf(),
            system_prompt.to_string(),
            deep_semantic_hunt_prompt(cwes, &inventory),
        )
        .with_tool_policy(whitebox_static_policy_for_target(target))
        .with_thinking_level(agentic_hunter_thinking_level(input)),
        StructuredJsonContract::new(
            "systems-hunt:deep-semantic-hunt",
            "DeepSemanticFindings",
            findings_schema(),
        ),
        require_json_object,
    )
}

pub(crate) fn deep_semantic_hunt_prompt(
    cwes: &[DeepSemanticCweSelection],
    inventory: &[(String, String)],
) -> String {
    format!(
        "Find verified variants of these native-code CWE classes. Return JSON with findings[].\n\nCWEs:\n{}\n\n{}",
        format_deep_semantic_cwes(cwes),
        format_inventory(inventory)
    )
}

pub(crate) fn format_deep_semantic_cwes(cwes: &[DeepSemanticCweSelection]) -> String {
    cwes.iter()
        .map(|cwe| format!("- {} {}: {}", cwe.id, cwe.name, cwe.reason))
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn apply_deep_semantic_whitebox_profile(
    input: &Value,
    findings: &mut [Finding],
) -> Result<()> {
    if whitebox_static_profile_requested(input)? {
        mark_whitebox_static_findings(findings, StaticProofState::CodeCited)?;
    }
    Ok(())
}
