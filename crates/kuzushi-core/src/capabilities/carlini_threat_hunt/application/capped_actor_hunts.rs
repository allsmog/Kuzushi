use super::run_carlini_threat_hunt::CarliniDebugArtifacts;
use super::*;

pub(crate) fn capped_actor_hunts(actors: ActorsResult, max_actors: usize) -> Vec<ActorHunt> {
    actor_hunts(actors).into_iter().take(max_actors).collect()
}

pub(crate) fn actor_hunts(actors: ActorsResult) -> Vec<ActorHunt> {
    if actors.prioritized.is_empty() {
        return actors
            .all_actors
            .into_iter()
            .map(unprioritized_actor_hunt)
            .collect();
    }
    actors.prioritized
}

pub(crate) fn unprioritized_actor_hunt(actor: DfdNode) -> ActorHunt {
    ActorHunt {
        actor,
        threats: Vec::new(),
        flows: Vec::new(),
    }
}

/// Aggregated outcome of one carlini run: the findings plus the
/// total cost across every actor's iterations. Returned together so the
/// caller can persist the cost into the report instead of dropping it.
pub(crate) struct CarliniActorHuntsOutcome {
    pub(crate) findings: Vec<Finding>,
    /// Reasons for every normalizer-rejected finding — surfaced in trace,
    /// receipt, and report; never dropped silently.
    pub(crate) rejected: Vec<String>,
    pub(crate) cost_usd: f64,
    pub(crate) cost_usd_exact: bool,
}

pub(crate) fn run_carlini_actor_hunts(
    runtime: &dyn AgentRuntime,
    input: &Value,
    target: &Path,
    options: &CarliniInput,
    model: &str,
    inventory_block: &str,
    actors: &[ActorHunt],
    debug_artifacts: Option<&CarliniDebugArtifacts>,
) -> Result<CarliniActorHuntsOutcome> {
    let mut state = CarliniActorRunState::default();
    for actor_hunt in actors {
        run_carlini_actor_hunt(
            runtime,
            input,
            target,
            options,
            model,
            inventory_block,
            actor_hunt,
            debug_artifacts,
            &mut state,
        )?;
    }
    Ok(CarliniActorHuntsOutcome {
        findings: state.findings,
        rejected: state.rejected,
        cost_usd: state.cost.observed_usd(),
        cost_usd_exact: state.cost.is_complete(),
    })
}

pub(crate) struct CarliniActorRunState {
    pub(crate) findings: Vec<Finding>,
    pub(crate) rejected: Vec<String>,
    pub(crate) seen: BTreeSet<String>,
    pub(crate) run_index: usize,
    pub(crate) cost: RuntimeCostReport,
}

impl Default for CarliniActorRunState {
    fn default() -> Self {
        Self {
            findings: Vec::new(),
            rejected: Vec::new(),
            seen: BTreeSet::new(),
            run_index: 0,
            cost: RuntimeCostReport::known(RuntimeCost::ZERO),
        }
    }
}

pub(crate) fn run_carlini_actor_hunt(
    runtime: &dyn AgentRuntime,
    input: &Value,
    target: &Path,
    options: &CarliniInput,
    model: &str,
    inventory_block: &str,
    actor_hunt: &ActorHunt,
    debug_artifacts: Option<&CarliniDebugArtifacts>,
    state: &mut CarliniActorRunState,
) -> Result<()> {
    for _ in 0..options.runs_per_actor {
        run_carlini_actor_iteration(
            runtime,
            input,
            target,
            options,
            model,
            inventory_block,
            actor_hunt,
            debug_artifacts,
            state,
        )?;
    }
    Ok(())
}

pub(crate) fn run_carlini_actor_iteration(
    runtime: &dyn AgentRuntime,
    input: &Value,
    target: &Path,
    options: &CarliniInput,
    model: &str,
    inventory_block: &str,
    actor_hunt: &ActorHunt,
    debug_artifacts: Option<&CarliniDebugArtifacts>,
    state: &mut CarliniActorRunState,
) -> Result<()> {
    let actor_fingerprint = build_actor_fingerprint(&actor_hunt.actor, state.run_index);
    if resume_actor_from_checkpoint(target, options, &actor_fingerprint, state)? {
        state.run_index += 1;
        return Ok(());
    }
    let value = paid_actor_query(
        runtime,
        input,
        target,
        options,
        model,
        inventory_block,
        actor_hunt,
        &actor_fingerprint,
        debug_artifacts,
        state,
    )?;
    record_normalized_actor_findings(state, target, options, &actor_fingerprint, value)?;
    state.run_index += 1;
    Ok(())
}

fn resume_actor_from_checkpoint(
    target: &Path,
    options: &CarliniInput,
    actor_fingerprint: &str,
    state: &mut CarliniActorRunState,
) -> Result<bool> {
    let stage_id = format!("actor:{actor_fingerprint}");
    let checkpoints = crate::run_artifacts::active_stage_checkpoints();
    reuse_checkpointed_actor_response(
        checkpoints.as_deref(),
        &stage_id,
        target,
        options,
        actor_fingerprint,
        state,
    )
}

/// One paid actor query: accumulates its cost and checkpoints the response
/// payload so a later failure in this run never re-buys it.
#[allow(clippy::too_many_arguments)]
fn paid_actor_query(
    runtime: &dyn AgentRuntime,
    input: &Value,
    target: &Path,
    options: &CarliniInput,
    model: &str,
    inventory_block: &str,
    actor_hunt: &ActorHunt,
    actor_fingerprint: &str,
    debug_artifacts: Option<&CarliniDebugArtifacts>,
    state: &mut CarliniActorRunState,
) -> Result<Value> {
    let stage_id = format!("actor:{actor_fingerprint}");
    let checkpoints = crate::run_artifacts::active_stage_checkpoints();
    let checkpoints = checkpoints.as_deref();
    let stage = checkpoints.map(|handle| handle.stage(&stage_id));
    let query = query_carlini_actor(
        runtime,
        input,
        target,
        options,
        model,
        inventory_block,
        actor_hunt,
        actor_fingerprint,
        debug_artifacts,
    )?;
    state.cost = state
        .cost
        .checked_add(query.cost, "Carlini actor fan-out cost")?;
    checkpoint_actor_response(checkpoints, stage, &stage_id, &query.value);
    Ok(query.value)
}

fn checkpoint_actor_response(
    handle: Option<&crate::run_artifacts::StageCheckpointHandle>,
    stage: Option<crate::run_artifacts::StageGuard<'_>>,
    stage_id: &str,
    payload: &Value,
) {
    if let (Some(handle), Some(stage)) = (handle, stage) {
        let artifacts = handle
            .write_stage_payload(stage_id, payload)
            .into_iter()
            .collect();
        stage.complete(artifacts);
    }
}

/// A prior failed run already paid for this actor's response: re-normalize
/// the persisted payload instead of re-querying the model. Records a
/// Skipped receipt so the reuse is visible in stages.jsonl.
fn reuse_checkpointed_actor_response(
    handle: Option<&crate::run_artifacts::StageCheckpointHandle>,
    stage_id: &str,
    target: &Path,
    options: &CarliniInput,
    actor_fingerprint: &str,
    state: &mut CarliniActorRunState,
) -> Result<bool> {
    let Some(handle) = handle else {
        return Ok(false);
    };
    let Some(receipt) = handle.completed_stage(stage_id) else {
        return Ok(false);
    };
    let Some(payload) = handle.read_stage_payload(&receipt) else {
        return Ok(false);
    };
    let source = handle.resumed_from().unwrap_or_else(|| "prior run".to_string());
    handle
        .stage(stage_id)
        .skip(&format!("reused checkpointed actor response from {source}"));
    record_normalized_actor_findings(state, target, options, actor_fingerprint, payload)?;
    Ok(true)
}

fn record_normalized_actor_findings(
    state: &mut CarliniActorRunState,
    target: &Path,
    options: &CarliniInput,
    actor_fingerprint: &str,
    payload: Value,
) -> Result<()> {
    let normalized = normalize_findings(payload, target, options.max_findings, actor_fingerprint)?;
    state.rejected.extend(
        normalized
            .rejected
            .into_iter()
            .map(|reason| format!("{actor_fingerprint}: {reason}")),
    );
    record_unique_carlini_findings(state, normalized.kept);
    Ok(())
}
