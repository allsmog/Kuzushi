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

pub(crate) fn query_systems_triggers_with_cost(
    runtime: &dyn AgentRuntime,
    model: &str,
    target: &Path,
    context: &SystemsContextOutput,
    invariants: &SystemsInvariantOutput,
    options: &SystemsHuntInput,
    agent_tool_policy: AgentToolPolicy,
    thinking_level: &str,
) -> Result<CostedStructuredJson<SystemsTriggerOutput>> {
    query_required_structured_json_with_cost(
        runtime,
        AgentQueryRequest::new(
            model.to_string(),
            target.to_path_buf(),
            options.trigger_system_prompt.clone(),
            format!(
                "Synthesize at most {} attacker trigger hypotheses per surface. Return JSON with triggers[].\n\n\
                 For each surface you have file_path + line_number markers; use Read to fetch source as needed (line text is not embedded to keep this prompt small).\n\n\
                 Context:\n{}\n\nInvariants:\n{}",
                options.max_trigger_hypotheses_per_surface,
                lean_prompt_payload(context)?,
                lean_prompt_payload(invariants)?,
            ),
        )
        .with_tool_policy(agent_tool_policy)
        .with_thinking_level(thinking_level.to_string()),
        StructuredJsonContract::new(
            "systems-hunt:systems-trigger-synth",
            "SystemsTriggers",
            triggers_schema(),
        ),
        |raw| {
            require_json_object(raw).map(|raw| SystemsTriggerOutput {
                triggers: parse_triggers(&raw),
            })
        },
    )
}

pub(crate) fn build_systems_hunt_prompt(
    _target: &Path,
    context: &SystemsContextOutput,
    invariants: &SystemsInvariantOutput,
    triggers: &SystemsTriggerOutput,
    options: &SystemsHuntInput,
) -> Result<String> {
    let mut sections = vec![systems_hunt_task_header(context, options)];
    push_systems_hunt_hints(&mut sections, context);
    sections.push(systems_hunt_payload_block(context, invariants, triggers)?);
    Ok(sections.join("\n\n"))
}

fn systems_hunt_task_header(context: &SystemsContextOutput, options: &SystemsHuntInput) -> String {
    format!(
        "Hunt for concrete memory-safety, integer-boundary, parser-state, resource-provenance, or hardening-bypass vulnerabilities. Return JSON with findings[]. Limit to {max_findings} findings.\n\n\
        Process:\n\
        1. Skim the {surface_count} surfaces below and pick at most the {investigate_cap} that look most exploitable.\n\
        2. For each chosen surface, Read the cited file once at the relevant line span.\n\
        3. Decide go/no-go quickly per surface and move on.\n\
        4. Emit final `{{\"findings\":[...]}}` JSON in one shot at the end of your turn.\n\n\
        For each surface in the context below you have its file_path, start_line, and one or more line_number markers in `evidence[]`. Use the Read tool to fetch surrounding source for any line you actually need to reason about; the prompt deliberately does not embed source text. Use Glob/Grep only when broadening outside the listed surfaces.",
        max_findings = options.max_findings,
        surface_count = context.surfaces.len(),
        investigate_cap = options.max_findings.saturating_mul(2).min(context.surfaces.len()),
    )
}

fn push_systems_hunt_hints(sections: &mut Vec<String>, context: &SystemsContextOutput) {
    let Some(hints) =
        crate::prompts::hunt_hints_for_paths(context.surfaces.iter().map(|s| s.file_path.as_str()))
    else {
        return;
    };
    sections.push(hints);
}

fn systems_hunt_payload_block(
    context: &SystemsContextOutput,
    invariants: &SystemsInvariantOutput,
    triggers: &SystemsTriggerOutput,
) -> Result<String> {
    Ok(format!(
        "Context:\n{context}\n\nInvariants:\n{invariants}\n\nTriggers:\n{triggers}",
        context = lean_prompt_payload(context)?,
        invariants = lean_prompt_payload(invariants)?,
        triggers = lean_prompt_payload(triggers)?,
    ))
}

#[cfg(test)]
pub(crate) fn format_context_for_prompt(context: &SystemsContextOutput) -> Result<String> {
    let surfaces = context
        .surfaces
        .iter()
        .map(compact_surface_for_prompt)
        .collect::<Vec<_>>();
    let surface_packs = context
        .surface_packs
        .iter()
        .map(compact_surface_pack_for_prompt)
        .collect::<Vec<_>>();
    Ok(serde_json::to_string(&json!({
        "metadata": &context.metadata,
        "surfaces": surfaces,
        "surfacePacks": surface_packs,
    }))?)
}

#[cfg(test)]
fn compact_surface_for_prompt(surface: &RankedSystemsSurface) -> Value {
    json!({
        "id": &surface.id,
        "filePath": &surface.file_path,
        "startLine": surface.start_line,
        "kind": &surface.kind,
        "score": surface.score,
        "domains": &surface.domains,
        "reasons": &surface.reasons,
        "attackerControlledFields": &surface.attacker_controlled_fields,
        "hardeningSignals": surface.hardening_signals.iter().take(4).collect::<Vec<_>>(),
        "evidence": surface.evidence.iter().take(4).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
fn compact_surface_pack_for_prompt(pack: &SystemsSurfacePack) -> Value {
    json!({
        "surfaceId": &pack.surface_id,
        "anchorFilePath": &pack.anchor_file_path,
        "anchorStartLine": pack.anchor_start_line,
        "relatedFiles": &pack.related_files,
        "unsafeSites": pack.unsafe_sites.iter().take(4).collect::<Vec<_>>(),
        "resourceProvenanceSites": pack.resource_provenance_sites.iter().take(4).collect::<Vec<_>>(),
        "hardeningSites": pack.hardening_sites.iter().take(4).collect::<Vec<_>>(),
        "inputSites": pack.input_sites.iter().take(4).collect::<Vec<_>>(),
        "helperTemplates": &pack.helper_templates,
    })
}
