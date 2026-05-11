use super::*;

pub(crate) fn run_deep_semantic_cwe_select(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<DeepSemanticCweOutput> {
    let target = resolve_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    let runtime = runtime.context(
        "systems-hunt:deep-semantic-cwe-select requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = resolve_model(
        "systems-hunt:deep-semantic-cwe-select",
        input,
        ctx,
        &options,
    )?;
    let inventory = collect_inventory(&target, 80, 2048)?;
    let raw = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            target.clone(),
            DEEP_SEMANTIC_CWE_SYSTEM_PROMPT.to_string(),
            format!(
            "Select relevant native-code CWE classes for this repository. Return JSON with cwes[].\n\n{}",
            format_inventory(&inventory)
        ),
        )
        .with_tool_policy(agent_tool_policy_for_input(input)?),
        StructuredJsonContract::new(
            "systems-hunt:deep-semantic-cwe-select",
            "DeepSemanticCweSelection",
            cwes_schema(),
        ),
        require_json_object,
    )?;
    Ok(DeepSemanticCweOutput {
        cwes: parse_cwe_selections(&raw)
            .into_iter()
            .take(options.max_cwe_classes)
            .collect(),
    })
}

pub(crate) fn run_deep_semantic_hunt_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<SystemsHuntReport> {
    let target = resolve_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    let runtime = runtime.context(
        "systems-hunt:deep-semantic-hunt requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = resolve_model("systems-hunt:deep-semantic-hunt", input, ctx, &options)?;
    let cwes = selected_deep_semantic_cwes(input, ctx, runtime, &options)?;

    if cwes.is_empty() {
        // Was a silent `Ok(empty_report)` — the operator had no way to
        // tell whether (a) the model legitimately found no CWEs worth
        // hunting, (b) the cwe-select agent returned malformed JSON and
        // the inner Result got `.unwrap_or_default()`-ed, or (c) the
        // runtime errored and the fallback path swallowed it. Bail
        // loudly with the resolved options so the operator can see
        // what cap was in effect.
        anyhow::bail!(
            "systems-hunt:deep-semantic-hunt: CWE selection returned 0 \
             classes for target {}. The deep-semantic agent either \
             produced no candidates or its response failed to parse. \
             Re-run with an explicit `cwes` input (array of CWE strings) \
             to bypass selection, or raise `maxCweClasses` (currently {}).",
            target.display(),
            options.max_cwe_classes,
        );
    }

    let raw = query_deep_semantic_findings(runtime, model, input, &target, &cwes)?;
    let artifact_root = artifact_root(&target, &options.artifact_dir)?;
    let (mut findings, artifacts) =
        normalize_deep_semantic_findings(raw, &target, &artifact_root, options.max_findings)?;
    apply_deep_semantic_whitebox_profile(input, &mut findings)?;
    let persisted = persist_systems_findings(&target, &findings, ctx)?;

    Ok(SystemsHuntReport {
        target: target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        artifacts,
        cost_usd: 0.0,
    })
}

pub(crate) fn selected_deep_semantic_cwes(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
    options: &SystemsHuntInput,
) -> Result<Vec<DeepSemanticCweSelection>> {
    let cwes = match cwes_from_input(input) {
        Some(cwes) => cwes,
        None => fallback_deep_semantic_cwes(input, ctx, runtime)?,
    };
    Ok(cwes.into_iter().take(options.max_cwe_classes).collect())
}

pub(crate) fn fallback_deep_semantic_cwes(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
) -> Result<Vec<DeepSemanticCweSelection>> {
    // Used to be `.unwrap_or_default()` — any failure inside
    // `run_deep_semantic_cwe_select` (bridge crash, structured-JSON
    // contract failure, model 429, parse error) silently produced an
    // empty Vec, which the caller turned into a 0-finding success.
    // Surface the underlying cause so the operator can fix it instead
    // of staring at "0 findings, ok: true".
    let output = run_deep_semantic_cwe_select(input, ctx, Some(runtime))
        .context("systems-hunt:deep-semantic-cwe-select failed; cannot fall back to empty CWE list because that hides agent/bridge errors")?;
    Ok(output.cwes)
}

