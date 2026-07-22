use super::*;

pub fn analysis_mode_from_input(input: &Value) -> Result<AnalysisMode> {
    if truthy_bool(input, &["whiteboxStatic", "whitebox_static"])? {
        return Ok(AnalysisMode::WhiteboxStatic);
    }

    let raw = input
        .get("mode")
        .or_else(|| input.get("preset"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("standard");
    match raw {
        "standard" | "default" | "sast" => Ok(AnalysisMode::Standard),
        "whitebox-static" => Ok(AnalysisMode::WhiteboxStatic),
        other => anyhow::bail!(
            "analysis mode {other:?} is unsupported; valid modes: standard, whitebox-static"
        ),
    }
}

pub fn whitebox_static_enabled(input: &Value) -> Result<bool> {
    Ok(analysis_mode_from_input(input)? == AnalysisMode::WhiteboxStatic)
}

pub fn default_whitebox_static_agent_tool_policy() -> AgentToolPolicy {
    AgentToolPolicy::new(
        WHITEBOX_STATIC_AGENT_TOOL_PROFILE,
        WHITEBOX_STATIC_READ_ONLY_AGENT_TOOLS.iter().copied(),
    )
}

/// Whitebox-static base policy with the conditional MCP attachment
/// plan baked in. Use this in every model-backed analysis tool that
/// would benefit from cpg / codeql / context / entry-points /
/// threat-model / threat-intel / x-ray MCPs — the probe attaches each
/// server only when its backing artifact exists, so calling this on a
/// fresh workspace is a no-op (just the constant treesitter MCP is
/// attached) and there's no penalty for the unconditional migration.
pub fn whitebox_static_policy_for_target(target: &std::path::Path) -> AgentToolPolicy {
    default_whitebox_static_agent_tool_policy().with_mcps_for_target(target)
}

/// Like `agent_tool_policy_for_input` but layers in the conditional
/// MCP attachment plan for `target`. Prefer this over the bare
/// `agent_tool_policy_for_input` for any model-backed tool that
/// benefits from the MCP surface.
pub fn agent_tool_policy_for_input_and_target(
    input: &Value,
    target: &std::path::Path,
) -> Result<AgentToolPolicy> {
    Ok(agent_tool_policy_for_input(input)?.with_mcps_for_target(target))
}

pub fn agentic_hunter_thinking_level(input: &Value) -> String {
    for key in ["thinkingLevel", "reasoningEffort", "effort"] {
        if let Some(value) = input.get(key).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    "high".to_string()
}

pub fn whitebox_static_triage_system_prompt() -> String {
    whitebox_static_triage_system_prompt_text()
}

pub fn whitebox_static_triage_prompt_block() -> &'static str {
    WHITEBOX_STATIC_TRIAGE_PROMPT_BLOCK
}

pub fn agent_tool_policy_for_input(input: &Value) -> Result<AgentToolPolicy> {
    if whitebox_static_profile_requested(input)? {
        let policy = default_whitebox_static_agent_tool_policy();
        validate_whitebox_static_agent_tool_policy(&policy)?;
        Ok(policy)
    } else {
        Ok(AgentToolPolicy::default())
    }
}

pub fn whitebox_static_profile_requested(input: &Value) -> Result<bool> {
    for key in ["whiteboxStatic", "whitebox_static"] {
        if let Some(value) = input.get(key) {
            if let Some(enabled) = value.get("enabled").and_then(Value::as_bool) {
                return Ok(enabled);
            }
            return value
                .as_bool()
                .with_context(|| format!("{key} must be a boolean or policy object"));
        }
    }

    let raw_mode = input
        .get("mode")
        .or_else(|| input.get("preset"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    Ok(raw_mode == AnalysisMode::WhiteboxStatic.as_str())
}

pub fn validate_whitebox_static_agent_tool_policy(policy: &AgentToolPolicy) -> Result<()> {
    if policy.profile != WHITEBOX_STATIC_AGENT_TOOL_PROFILE {
        anyhow::bail!(
            "whitebox-static agent tool policy must use profile {WHITEBOX_STATIC_AGENT_TOOL_PROFILE:?}"
        );
    }
    if policy.tools.is_empty() {
        anyhow::bail!("whitebox-static agent tool policy must include read-only repo tools");
    }

    for tool in &policy.tools {
        if is_forbidden_agent_tool(tool) {
            anyhow::bail!(
                "whitebox-static agent tool policy cannot include execution or write tool {tool:?}"
            );
        }
        if !WHITEBOX_STATIC_READ_ONLY_AGENT_TOOLS
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(tool))
        {
            anyhow::bail!(
                "whitebox-static agent tool policy can only include read-only repo tools; unsupported tool {tool:?}"
            );
        }
    }
    Ok(())
}

pub fn whitebox_static_proof_state_from_str(value: &str) -> Result<StaticProofState> {
    if is_execution_proof_state(value) {
        return Ok(StaticProofState::NeedsRuntimeEvidence);
    }
    StaticProofState::try_from(value)
}
