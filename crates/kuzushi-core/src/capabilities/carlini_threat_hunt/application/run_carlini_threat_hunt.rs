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
    let parent_step = ctx.trace.map(|trace| {
        trace
            .step(
                "tool",
                "run",
                format!(
                    "carlini-threat-hunt:run start · target={}",
                    target.display()
                ),
            )
            .emit()
    });
    let document = resolve_threat_model_document(input, &target)?;
    let actors = actors_from_document(&document);
    if actors.all_actors.is_empty() {
        if let Some(trace) = ctx.trace {
            let _ = trace
                .step(
                    "refused",
                    "run",
                    "carlini-threat-hunt:run refused · no actors in threat model",
                )
                .emit();
        }
        anyhow::bail!(
            "carlini-threat-hunt: threat model at {} has no actors to hunt. \
             Expected at least one node with `type: external-entity` or with a \
             trust zone matching untrusted/external/internet/public. Found {} \
             total node(s). Re-run threat-model:build with a methodology that \
             emits DFD actors, or hand-edit the threat-model artifact to \
             declare external actors before re-running carlini.",
            target.display(),
            document
                .pointer("/dfd/nodes")
                .and_then(Value::as_array)
                .map(|nodes| nodes.len())
                .unwrap_or(0),
        );
    }
    if actors.prioritized.is_empty() {
        if let Some(trace) = ctx.trace {
            let _ = trace
                .step(
                    "refused",
                    "run",
                    "carlini-threat-hunt:run refused · no high-priority actor threats",
                )
                .emit();
        }
        anyhow::bail!(
            "carlini-threat-hunt: threat model at {} has {} actor(s) but no \
             high/critical threats reference them. Either the impact/severity \
             fields didn't match the expected enum (critical|high) and didn't \
             match any high-severity keywords (arbitrary code execution, \
             memory corruption, use-after-free, …), or no threat declared an \
             `affectedNodeIds`/`targetElementIds` pointing at an actor. \
             Re-run threat-model:build or hand-edit threat impact fields.",
            target.display(),
            actors.all_actors.len(),
        );
    }

    let options = CarliniInput::from_tool_input(input, ctx, &target)?;
    let runtime = require_carlini_runtime(runtime)?;
    let model = require_carlini_model(&options)?;
    let capped = capped_actor_hunts(actors, options.max_actors);
    if let (Some(trace), Some(parent)) = (ctx.trace, parent_step) {
        let _ = trace
            .child(parent)
            .step(
                "reasoning",
                "run",
                format!(
                    "actor-spawn · {} actors · {} runs/actor",
                    capped.len(),
                    options.runs_per_actor
                ),
            )
            .emit();
    }
    let inventory = collect_repo_inventory(&target, 80, 2048)?;
    let total_runs = capped.len() * options.runs_per_actor;
    // Push a scope so each per-actor LLM round-trip lands under the
    // actor-spawn header in the feed. Per-actor children would require
    // threading the per-actor parent_step into run_carlini_actor_hunts;
    // for now the scope means every LLM call surfaces under the run.
    let _actor_scope = match (ctx.trace, parent_step) {
        (Some(trace), Some(parent)) => {
            let phase = trace
                .child(parent)
                .step("reasoning", "run", "compose · tool-call · defender-critic")
                .emit();
            Some(trace.parent_scope(phase))
        }
        _ => None,
    };
    let mut findings = run_carlini_actor_hunts(
        runtime, input, &target, &options, &model, &inventory, &capped,
    )?;
    drop(_actor_scope);
    finalize_carlini_findings(input, &mut findings, options.max_findings)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "run",
                format!(
                    "carlini-threat-hunt:run complete · {} findings",
                    findings.len()
                ),
            )
            .emit();
    }
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
