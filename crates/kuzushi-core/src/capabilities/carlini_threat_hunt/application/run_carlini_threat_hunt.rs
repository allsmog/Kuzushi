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
    let run = prepare_carlini_threat_hunt_run(input, ctx, runtime)?;
    execute_carlini_threat_hunt_run(input, ctx, run)
}

struct CarliniThreatHuntRun<'a> {
    target: PathBuf,
    parent_step: Option<usize>,
    options: CarliniInput,
    runtime: &'a dyn AgentRuntime,
    model: String,
    capped: Vec<ActorHunt>,
    inventory: Vec<(String, String)>,
}

struct CarliniThreatHuntScope {
    target: PathBuf,
    parent_step: Option<usize>,
    actors: ActorsResult,
}

struct CarliniExecutionInputs<'a> {
    options: CarliniInput,
    runtime: &'a dyn AgentRuntime,
    model: String,
    inventory: Vec<(String, String)>,
}

fn prepare_carlini_threat_hunt_run<'a>(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<CarliniThreatHuntRun<'a>> {
    let scope = prepare_carlini_threat_hunt_scope(input, ctx)?;
    let execution = prepare_carlini_execution_inputs(input, ctx, runtime, &scope.target)?;
    let capped = capped_actor_hunts(scope.actors, execution.options.max_actors);
    emit_carlini_actor_spawn(
        ctx,
        scope.parent_step,
        capped.len(),
        execution.options.runs_per_actor,
    );

    Ok(CarliniThreatHuntRun {
        target: scope.target,
        parent_step: scope.parent_step,
        options: execution.options,
        runtime: execution.runtime,
        model: execution.model,
        capped,
        inventory: execution.inventory,
    })
}

fn prepare_carlini_threat_hunt_scope(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<CarliniThreatHuntScope> {
    let target = resolve_carlini_target(input, ctx)?;
    let parent_step = emit_carlini_start_step(ctx, &target);
    let actors = resolve_carlini_actor_hunts(input, ctx, &target)?;

    Ok(CarliniThreatHuntScope {
        target,
        parent_step,
        actors,
    })
}

fn prepare_carlini_execution_inputs<'a>(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
    target: &Path,
) -> Result<CarliniExecutionInputs<'a>> {
    let options = CarliniInput::from_tool_input(input, ctx, &target)?;
    let (runtime, model) = resolve_carlini_runtime_model(runtime, &options)?;
    let inventory = collect_repo_inventory(&target, 80, 2048)?;

    Ok(CarliniExecutionInputs {
        options,
        runtime,
        model,
        inventory,
    })
}

fn resolve_carlini_runtime_model<'a>(
    runtime: Option<&'a dyn AgentRuntime>,
    options: &CarliniInput,
) -> Result<(&'a dyn AgentRuntime, String)> {
    let runtime = require_carlini_runtime(runtime)?;
    let model = require_carlini_model(options)?;
    Ok((runtime, model))
}

fn resolve_carlini_actor_hunts(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
) -> Result<ActorsResult> {
    let document = resolve_threat_model_document(input, target)?;
    let actors = actors_from_document(&document);
    ensure_carlini_actor_inputs(&document, target, &actors, ctx)?;
    Ok(actors)
}

fn execute_carlini_threat_hunt_run(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    run: CarliniThreatHuntRun<'_>,
) -> Result<CarliniThreatHuntReport> {
    let total_runs = carlini_actor_run_count(run.capped.len(), run.options.runs_per_actor);
    // Push a scope so each per-actor LLM round-trip lands under the
    // actor-spawn header in the feed. Per-actor children would require
    // threading the per-actor parent_step into run_carlini_actor_hunts;
    // for now the scope means every LLM call surfaces under the run.
    let _actor_scope = begin_carlini_actor_scope(ctx, run.parent_step);
    let mut findings = run_carlini_actor_hunts(
        run.runtime,
        input,
        &run.target,
        &run.options,
        &run.model,
        &run.inventory,
        &run.capped,
    )?;
    drop(_actor_scope);
    finalize_carlini_findings(input, &mut findings, run.options.max_findings)?;
    emit_carlini_completion(ctx, findings.len());
    carlini_threat_hunt_report(
        run.target,
        ctx,
        run.options,
        run.capped.len(),
        total_runs,
        findings,
    )
}

fn emit_carlini_start_step(ctx: &ToolExecutionContext<'_>, target: &Path) -> Option<usize> {
    ctx.trace.map(|trace| {
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
    })
}

fn ensure_carlini_actor_inputs(
    document: &Value,
    target: &Path,
    actors: &ActorsResult,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    ensure_carlini_actors_present(document, target, actors, ctx)?;
    ensure_carlini_prioritized_actors(target, actors, ctx)
}

fn ensure_carlini_actors_present(
    document: &Value,
    target: &Path,
    actors: &ActorsResult,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    if !actors.all_actors.is_empty() {
        return Ok(());
    }

    emit_carlini_refusal(
        ctx,
        "carlini-threat-hunt:run refused · no actors in threat model",
    );
    anyhow::bail!(
        "carlini-threat-hunt: threat model at {} has no actors to hunt. \
         Expected at least one node with `type: external-entity` or with a \
         trust zone matching untrusted/external/internet/public. Found {} \
         total node(s). Re-run threat-model:build with a methodology that \
         emits DFD actors, or hand-edit the threat-model artifact to \
         declare external actors before re-running carlini.",
        target.display(),
        threat_model_node_count(document),
    );
}

fn threat_model_node_count(document: &Value) -> usize {
    document
        .pointer("/dfd/nodes")
        .and_then(Value::as_array)
        .map(|nodes| nodes.len())
        .unwrap_or(0)
}

fn ensure_carlini_prioritized_actors(
    target: &Path,
    actors: &ActorsResult,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    if !actors.prioritized.is_empty() {
        return Ok(());
    }

    emit_carlini_refusal(
        ctx,
        "carlini-threat-hunt:run refused · no high-priority actor threats",
    );
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

fn emit_carlini_refusal(ctx: &ToolExecutionContext<'_>, label: &str) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step("refused", "run", label).emit();
    }
}

fn emit_carlini_actor_spawn(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    actor_count: usize,
    runs_per_actor: usize,
) {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return;
    };

    let _ = trace
        .child(parent)
        .step(
            "reasoning",
            "run",
            format!("actor-spawn · {actor_count} actors · {runs_per_actor} runs/actor"),
        )
        .emit();
}

fn carlini_actor_run_count(actor_count: usize, runs_per_actor: usize) -> usize {
    actor_count * runs_per_actor
}

fn begin_carlini_actor_scope(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
) -> Option<crate::run_artifacts::ParentScope> {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return None;
    };

    let phase = trace
        .child(parent)
        .step("reasoning", "run", "compose · tool-call · defender-critic")
        .emit();
    Some(trace.parent_scope(phase))
}

fn emit_carlini_completion(ctx: &ToolExecutionContext<'_>, finding_count: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "run",
                format!("carlini-threat-hunt:run complete · {finding_count} findings"),
            )
            .emit();
    }
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
