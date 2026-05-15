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
    pub(crate) cost_usd: f64,
}

pub(crate) fn run_carlini_actor_hunts(
    runtime: &dyn AgentRuntime,
    input: &Value,
    target: &Path,
    options: &CarliniInput,
    model: &str,
    inventory: &[(String, String)],
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
            inventory,
            actor_hunt,
            debug_artifacts,
            &mut state,
        )?;
    }
    Ok(CarliniActorHuntsOutcome {
        findings: state.findings,
        cost_usd: state.cost_usd,
    })
}

#[derive(Default)]
pub(crate) struct CarliniActorRunState {
    pub(crate) findings: Vec<Finding>,
    pub(crate) seen: BTreeSet<String>,
    pub(crate) run_index: usize,
    pub(crate) cost_usd: f64,
}

pub(crate) fn run_carlini_actor_hunt(
    runtime: &dyn AgentRuntime,
    input: &Value,
    target: &Path,
    options: &CarliniInput,
    model: &str,
    inventory: &[(String, String)],
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
            inventory,
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
    inventory: &[(String, String)],
    actor_hunt: &ActorHunt,
    debug_artifacts: Option<&CarliniDebugArtifacts>,
    state: &mut CarliniActorRunState,
) -> Result<()> {
    let actor_fingerprint = build_actor_fingerprint(&actor_hunt.actor, state.run_index);
    let query = query_carlini_actor(
        runtime,
        input,
        target,
        options,
        model,
        inventory,
        actor_hunt,
        &actor_fingerprint,
        debug_artifacts,
    )?;
    state.cost_usd += query.cost_usd;
    let normalized = normalize_findings(query.value, target, options.max_findings, &actor_fingerprint)?;
    record_unique_carlini_findings(state, normalized);
    state.run_index += 1;
    Ok(())
}
