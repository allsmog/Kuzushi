use super::*;

pub fn run_carlini_threat_hunt(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_target(&input, ctx)?;
    crate::workspace::source_snapshot::run_source_bound_tool(
        ctx,
        "carlini-threat-hunt:run",
        &target,
        || Ok(run_carlini_threat_hunt_report(&input, ctx, runtime)?.to_tool_json()),
    )
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
    parent_step: Option<crate::run_lifecycle::RunItemId>,
    debug_artifacts: Option<CarliniDebugArtifacts>,
    options: CarliniInput,
    runtime: &'a dyn AgentRuntime,
    model: String,
    capped: Vec<ActorHunt>,
    inventory: Vec<(String, String)>,
    threat_model_warning: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct CarliniDebugArtifacts {
    pub(crate) target: PathBuf,
    pub(crate) run_id: String,
}

struct CarliniThreatHuntScope {
    target: PathBuf,
    parent_step: Option<crate::run_lifecycle::RunItemId>,
    actors: ActorsResult,
    threat_model_warning: Option<String>,
}

struct CarliniExecutionInputs<'a> {
    options: CarliniInput,
    runtime: &'a dyn AgentRuntime,
    model: String,
}

fn prepare_carlini_threat_hunt_run<'a>(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<CarliniThreatHuntRun<'a>> {
    let scope = prepare_carlini_threat_hunt_scope(input, ctx)?;
    let execution = prepare_carlini_execution_inputs(input, ctx, runtime, &scope.target)?;
    let capped = capped_actor_hunts(scope.actors, execution.options.max_actors);
    emit_carlini_progress(
        ctx,
        scope.parent_step,
        "inventory · collect actor-focused snippets",
    );
    let inventory = collect_carlini_inventory(&scope.target, &capped)?;
    emit_carlini_progress(
        ctx,
        scope.parent_step,
        format!("inventory · {} snippets loaded", inventory.len()),
    );
    emit_carlini_actor_spawn(
        ctx,
        scope.parent_step,
        capped.len(),
        execution.options.runs_per_actor,
    );

    Ok(CarliniThreatHuntRun {
        target: scope.target,
        parent_step: scope.parent_step,
        debug_artifacts: ctx.trace.and_then(|trace| {
            trace
                .run_artifact_location()
                .map(|(target, run_id)| CarliniDebugArtifacts { target, run_id })
        }),
        options: execution.options,
        runtime: execution.runtime,
        model: execution.model,
        capped,
        inventory,
        threat_model_warning: scope.threat_model_warning,
    })
}

fn prepare_carlini_threat_hunt_scope(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<CarliniThreatHuntScope> {
    let target = resolve_carlini_target(input, ctx)?;
    let parent_step = emit_carlini_start_step(ctx, &target);
    emit_carlini_progress(ctx, parent_step, "threat-model · load actors and threats");
    let (actors, threat_model_warning) = resolve_carlini_actor_hunts(input, ctx, &target)?;
    emit_carlini_progress(
        ctx,
        parent_step,
        format!(
            "threat-model · {} actors · {} prioritized",
            actors.all_actors.len(),
            actors.prioritized.len()
        ),
    );

    Ok(CarliniThreatHuntScope {
        target,
        parent_step,
        actors,
        threat_model_warning,
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

    Ok(CarliniExecutionInputs {
        options,
        runtime,
        model,
    })
}

pub(crate) fn collect_carlini_inventory(
    target: &Path,
    hunts: &[ActorHunt],
) -> Result<Vec<(String, String)>> {
    const MAX_TOTAL_FILES: usize = 80;
    const MAX_FOCUSED_FILES: usize = 24;
    const MAX_FOCUSED_BYTES: usize = 4096;
    const MAX_GENERIC_BYTES: usize = 2048;

    let mut inventory =
        collect_threat_focused_inventory(target, hunts, MAX_FOCUSED_FILES, MAX_FOCUSED_BYTES)?;
    let mut seen = inventory
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<BTreeSet<_>>();
    for (path, snippet) in collect_repo_inventory(target, MAX_TOTAL_FILES, MAX_GENERIC_BYTES)? {
        if inventory.len() >= MAX_TOTAL_FILES {
            break;
        }
        if seen.insert(path.clone()) {
            inventory.push((path, snippet));
        }
    }
    Ok(inventory)
}

fn collect_threat_focused_inventory(
    target: &Path,
    hunts: &[ActorHunt],
    max_files: usize,
    max_bytes_per_file: usize,
) -> Result<Vec<(String, String)>> {
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    let affected = threat_affected_file_paths(hunts)
        .into_iter()
        .flat_map(|relative| expand_affected_path(target, relative))
        .filter(|relative| seen.insert(relative.clone()));
    for relative in affected {
        if files.len() >= max_files {
            break;
        }
        files.extend(read_threat_focused_snippet(target, &relative, max_bytes_per_file)?);
    }
    Ok(files)
}

/// A threat may cite a directory (`routes`) rather than a file. Its direct
/// regular files stand in for it, in name order and confined to the target;
/// the caller's file budget still bounds how many are read.
fn expand_affected_path(target: &Path, relative: PathBuf) -> Vec<PathBuf> {
    let is_dir = std::fs::symlink_metadata(target.join(&relative))
        .is_ok_and(|metadata| metadata.is_dir());
    if !is_dir {
        return vec![relative];
    }
    let Ok(entries) = crate::bounded_file::read_dir_within(target, &target.join(&relative)) else {
        return Vec::new();
    };
    let mut files = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| relative.join(entry.file_name()))
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn threat_affected_file_paths(hunts: &[ActorHunt]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for hunt in hunts {
        for threat in &hunt.threats {
            for key in ["affectedFiles", "affected_files"] {
                for raw in object_string_array(threat, &[key]) {
                    if let Some(relative) = normalize_threat_file_path(&raw) {
                        paths.push(relative);
                    }
                }
            }
        }
    }
    paths
}

fn threat_focused_inventory_count(inventory: &[(String, String)], hunts: &[ActorHunt]) -> usize {
    let focused = threat_affected_file_paths(hunts)
        .into_iter()
        .map(|path| path.display().to_string())
        .collect::<BTreeSet<_>>();
    inventory
        .iter()
        .filter(|(path, _)| focused.contains(path))
        .count()
}

fn normalize_threat_file_path(raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim().trim_start_matches("./");
    if trimmed.is_empty()
        || trimmed.contains('*')
        || trimmed.contains('?')
        || trimmed.contains('[')
        || trimmed.contains(']')
    {
        return None;
    }
    let path = Path::new(trimmed);
    if path.is_absolute() {
        return None;
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => normalized.push(part),
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }
    (!normalized.as_os_str().is_empty()).then_some(normalized)
}

fn read_threat_focused_snippet(
    target: &Path,
    relative: &Path,
    max_bytes_per_file: usize,
) -> Result<Option<(String, String)>> {
    let path = target.join(relative);
    let snippet = match crate::bounded_file::read_source_text_prefix_within(
        target,
        &path,
        max_bytes_per_file,
    ) {
        Ok(Some(snippet)) => snippet,
        Ok(None) => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "could not read Carlini threat-focused source {}",
                    relative.display()
                )
            });
        }
    };
    Ok(Some((relative.display().to_string(), snippet)))
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
) -> Result<(ActorsResult, Option<String>)> {
    let document = resolve_threat_model_document(input, target)?;
    let actors = actors_from_document(&document);
    ensure_carlini_actor_inputs(&document, target, &actors, ctx)?;
    // Consumption honesty: a stale or verification-failed threat model still
    // grounds the hunt, but every actor prompt leads with the warning.
    let warning = crate::capabilities::threat_model::verification_warning(&document, target);
    Ok((actors, warning))
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
    let _actor_scope =
        begin_carlini_actor_scope(ctx, run.parent_step, run.capped.len(), total_runs);
    // The repository inventory is identical for every actor, so render its
    // untrusted-repo block once here and reuse it across the whole loop
    // instead of rebuilding the same large payload once per actor.
    let mut inventory_block = render_carlini_inventory_block(&run.inventory);
    if let Some(warning) = &run.threat_model_warning {
        inventory_block = format!("{warning}\n\n{inventory_block}");
    }
    let outcome = run_carlini_actor_hunts(
        run.runtime,
        input,
        &run.target,
        &run.options,
        &run.model,
        &inventory_block,
        &run.capped,
        run.debug_artifacts.as_ref(),
    )?;
    drop(_actor_scope);
    finish_carlini_threat_hunt_run(input, ctx, run, total_runs, outcome)
}

fn finish_carlini_threat_hunt_run(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    run: CarliniThreatHuntRun<'_>,
    total_runs: usize,
    outcome: CarliniActorHuntsOutcome,
) -> Result<CarliniThreatHuntReport> {
    let mut findings = outcome.findings;
    finalize_carlini_findings(input, &mut findings, run.options.max_findings)?;
    emit_carlini_rejections(ctx, &outcome.rejection_reasons, outcome.rejected_count);
    emit_carlini_completion(ctx, findings.len(), outcome.rejected_count);
    carlini_threat_hunt_report(
        run.target,
        ctx,
        run.options,
        run.capped.len(),
        total_runs,
        run.inventory.len(),
        threat_focused_inventory_count(&run.inventory, &run.capped),
        findings,
        outcome.rejected_count,
        outcome.rejection_reasons,
        outcome.cost_usd,
        outcome.cost_usd_exact,
    )
}

fn emit_carlini_start_step(
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
) -> Option<crate::run_lifecycle::RunItemId> {
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

fn emit_carlini_progress(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<crate::run_lifecycle::RunItemId>,
    label: impl Into<String>,
) {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return;
    };

    let _ = trace
        .child(parent)
        .step("tool-progress", "run", label.into())
        .emit();
}

fn emit_carlini_actor_spawn(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<crate::run_lifecycle::RunItemId>,
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
    parent_step: Option<crate::run_lifecycle::RunItemId>,
    actor_count: usize,
    total_runs: usize,
) -> Option<crate::run_artifacts::ParentScope> {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return None;
    };

    // Honest phase header: this scope groups the real per-actor LLM calls,
    // not a compose/defender-critic pipeline that does not exist here.
    let phase = trace
        .child(parent)
        .step(
            "reasoning",
            "run",
            format!("actor hunts · {actor_count} actors · {total_runs} runs"),
        )
        .emit();
    Some(trace.parent_scope(phase))
}

fn emit_carlini_rejections(
    ctx: &ToolExecutionContext<'_>,
    rejection_reasons: &[String],
    rejected_count: usize,
) {
    let Some(trace) = ctx.trace else {
        return;
    };
    for reason in rejection_reasons {
        let _ = trace
            .step(
                "finding-rejected",
                "run",
                format!("finding rejected by normalizer · {reason}"),
            )
            .with_severity("warn")
            .emit();
    }
    if rejected_count > rejection_reasons.len() {
        let _ = trace
            .step(
                "finding-rejected",
                "run",
                format!(
                    "… {} more findings rejected by normalizer",
                    rejected_count - rejection_reasons.len()
                ),
            )
            .with_severity("warn")
            .emit();
    }
}

fn emit_carlini_completion(
    ctx: &ToolExecutionContext<'_>,
    finding_count: usize,
    rejected_count: usize,
) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "run",
                format!(
                    "carlini-threat-hunt:run complete · {finding_count} findings · {rejected_count} rejected by schema"
                ),
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
        "carlini-threat-hunt:run requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies.",
    )
}

pub(crate) fn require_carlini_model(options: &CarliniInput) -> Result<String> {
    crate::runtime::resolve_explicit_model("carlini-threat-hunt:run", options.model.clone(), None)
}

#[cfg(test)]
mod affected_path_tests {
    use super::*;

    #[test]
    fn a_cited_directory_expands_to_its_direct_files_in_order() {
        let target = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(target.path().join("routes/nested")).unwrap();
        std::fs::write(target.path().join("routes/b.ts"), "b").unwrap();
        std::fs::write(target.path().join("routes/a.ts"), "a").unwrap();
        std::fs::write(target.path().join("routes/nested/c.ts"), "c").unwrap();

        assert_eq!(
            expand_affected_path(target.path(), PathBuf::from("routes")),
            vec![PathBuf::from("routes/a.ts"), PathBuf::from("routes/b.ts")]
        );
        assert_eq!(
            expand_affected_path(target.path(), PathBuf::from("routes/a.ts")),
            vec![PathBuf::from("routes/a.ts")]
        );
        assert_eq!(
            expand_affected_path(target.path(), PathBuf::from("missing.ts")),
            vec![PathBuf::from("missing.ts")],
            "a missing file stays a skipped read, not an error"
        );
    }
}
