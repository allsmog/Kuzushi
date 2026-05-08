use super::prelude::*;
use super::*;

pub(crate) async fn indexed_taint_path_found(
    facade: &mut kuzushi_codeindex::IndexFacade,
    surface: &RankedSystemsSurface,
) -> bool {
    if !surface_warrants_taint_check(surface) {
        return false;
    }
    facade
        .taint_paths("argv|recv|read|fread", "memcpy|strcat|strcpy", Some(5))
        .await
        .map(|value| value.get("paths").is_some())
        .unwrap_or(false)
}

pub(crate) fn surface_warrants_taint_check(surface: &RankedSystemsSurface) -> bool {
    let needles = ["memcpy", "strcat", "strcpy"];
    surface
        .reasons
        .iter()
        .any(|reason| needles.iter().any(|needle| reason.contains(needle)))
}

pub(crate) fn query_systems_triggers(
    runtime: &dyn AgentRuntime,
    model: &str,
    target: &Path,
    context: &SystemsContextOutput,
    invariants: &SystemsInvariantOutput,
    options: &SystemsHuntInput,
    agent_tool_policy: AgentToolPolicy,
) -> Result<SystemsTriggerOutput> {
    let raw = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model.to_string(),
            target.to_path_buf(),
            SYSTEMS_TRIGGER_SYSTEM_PROMPT.to_string(),
            format!(
            "Synthesize at most {} attacker trigger hypotheses per surface. Return JSON with triggers[].\n\nContext:\n{}\n\nInvariants:\n{}",
            options.max_trigger_hypotheses_per_surface,
            serde_json::to_string_pretty(context)?,
            serde_json::to_string_pretty(invariants)?,
        ),
        )
        .with_tool_policy(agent_tool_policy),
        StructuredJsonContract::new(
            "systems-hunt:systems-trigger-synth",
            "SystemsTriggers",
            triggers_schema(),
        ),
        require_json_object,
    )?;
    Ok(SystemsTriggerOutput {
        triggers: parse_triggers(&raw),
    })
}

pub(crate) fn build_systems_hunt_prompt(
    target: &Path,
    context: &SystemsContextOutput,
    invariants: &SystemsInvariantOutput,
    triggers: &SystemsTriggerOutput,
    options: &SystemsHuntInput,
) -> Result<String> {
    let inventory = collect_inventory(target, 80, 2048)?;
    Ok(format!(
        "Hunt for concrete memory-safety, integer-boundary, parser-state, resource-provenance, or hardening-bypass vulnerabilities. Return JSON with findings[]. Limit to {} findings.\n\nContext:\n{}\n\nInvariants:\n{}\n\nTriggers:\n{}\n\nRepository snippets:\n{}",
        options.max_findings,
        serde_json::to_string_pretty(context)?,
        serde_json::to_string_pretty(invariants)?,
        serde_json::to_string_pretty(triggers)?,
        format_inventory(&inventory)
    ))
}
