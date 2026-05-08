use super::*;

pub fn whitebox_static_proof_state_from_input(input: &Value) -> Result<Option<StaticProofState>> {
    for key in [
        "staticProofState",
        "static_proof_state",
        "proofState",
        "proof_state",
    ] {
        let Some(value) = input.get(key) else {
            continue;
        };
        let Some(raw) = value.as_str() else {
            anyhow::bail!("whitebox-static {key} must be a string");
        };
        return Ok(Some(whitebox_static_proof_state_from_str(raw)?));
    }
    Ok(None)
}

pub fn mark_whitebox_static_findings(
    findings: &mut [Finding],
    default_state: StaticProofState,
) -> Result<()> {
    for finding in findings {
        let state = finding.static_proof_state.unwrap_or(default_state);
        finding.set_static_proof_state(state);
    }
    Ok(())
}

pub(crate) fn is_forbidden_agent_tool(tool: &str) -> bool {
    let normalized = normalize_agent_tool_name(tool);
    WHITEBOX_STATIC_FORBIDDEN_AGENT_TOOLS
        .iter()
        .any(|forbidden| *forbidden == normalized)
}
