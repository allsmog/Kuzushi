use super::*;

pub fn run_carlini_threat_hunt(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    Ok(run_carlini_threat_hunt_report(&input, ctx, runtime)?.to_tool_json())
}

pub fn run_carlini_threat_hunt_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<CarliniThreatHuntReport> {
    let target = resolve_carlini_target(input, ctx)?;
    let document = resolve_threat_model_document(input, &target)?;
    let actors = actors_from_document(&document);
    if actors.all_actors.is_empty() {
        return empty_carlini_threat_hunt_report(&target, ctx);
    }

    let options = CarliniInput::from_tool_input(input, ctx, &target)?;
    let runtime = require_carlini_runtime(runtime)?;
    let model = require_carlini_model(&options)?;
    let capped = capped_actor_hunts(actors, options.max_actors);
    let inventory = collect_repo_inventory(&target, 80, 2048)?;
    let total_runs = capped.len() * options.runs_per_actor;
    let mut findings = run_carlini_actor_hunts(
        runtime, input, &target, &options, &model, &inventory, &capped,
    )?;
    finalize_carlini_findings(input, &mut findings, options.max_findings)?;
    carlini_threat_hunt_report(target, ctx, options, capped.len(), total_runs, findings)
}

pub(crate) fn resolve_carlini_target(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PathBuf> {
    let target = resolve_target(input, ctx)?;
    ensure_carlini_target_dir(&target)?;
    Ok(target)
}

pub(crate) fn ensure_carlini_target_dir(target: &Path) -> Result<()> {
    if !target.is_dir() {
        anyhow::bail!(
            "carlini-threat-hunt: target is not a directory: {}",
            target.display()
        );
    }
    Ok(())
}

pub(crate) fn empty_carlini_threat_hunt_report(
    target: &Path,
    ctx: &ToolExecutionContext<'_>,
) -> Result<CarliniThreatHuntReport> {
    Ok(CarliniThreatHuntReport {
        target: target.display().to_string(),
        count: 0,
        actors: 0,
        actor_runs: 0,
        findings: Vec::new(),
        persisted: persist_findings(target, &[], ctx)?,
        kb_context: Some(ctx.artifact_knowledge_context(
            target,
            "carlini threat hunt actor flows threat model x-ray context",
            5,
        )),
        cost_usd: 0.0,
    })
}

pub(crate) fn require_carlini_runtime(
    runtime: Option<&dyn AgentRuntime>,
) -> Result<&dyn AgentRuntime> {
    runtime.context(
        "carlini-threat-hunt:run requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )
}

pub(crate) fn require_carlini_model(options: &CarliniInput) -> Result<String> {
    crate::runtime::resolve_explicit_model("carlini-threat-hunt:run", options.model.clone(), None)
}
