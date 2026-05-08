use super::prelude::*;
use super::*;

pub(crate) fn query_deep_semantic_findings(
    runtime: &dyn AgentRuntime,
    model: String,
    input: &Value,
    target: &Path,
    cwes: &[DeepSemanticCweSelection],
) -> Result<Value> {
    let inventory = collect_inventory(target, 80, 2048)?;
    query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            target.to_path_buf(),
            DEEP_SEMANTIC_HUNT_SYSTEM_PROMPT.to_string(),
            deep_semantic_hunt_prompt(cwes, &inventory),
        )
        .with_tool_policy(agent_tool_policy_for_input(input)?),
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
