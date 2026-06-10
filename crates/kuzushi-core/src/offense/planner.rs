//! LLM-planned attack chains: the autonomous layer over the declarative floor.
//!
//! Instead of the operator authoring every hop, the model proposes the next
//! play from the goal and the observations so far; Kuzushi builds and executes
//! it through the same scope-gated [`Play`]/transport seam, feeds the result
//! back, and asks for the next. Same guarantees as a declarative chain — the
//! target is authorized once, every hop's evidence threads forward, a landed
//! chain persists at the same proof level — only the *plan* is dynamic.
//!
//! Bounds keep an autonomous loop honest: a hard `max_steps`, a stop when the
//! model declares the goal reached or proposes nothing, and the same
//! refuse-by-default scope gate on the resolved target. The model is derived
//! from `ctx.config.model` (no silent fallback); each step is one structured
//! query whose output is a [`PlaySpec`].

use super::chain::ChainOutcome;
use super::observer::HopObserver;
use super::play::PlayOutcome;
use super::play_context::PlayContext;
use super::spec::PlaySpec;
use super::transport::PlayTransport;
use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::structured_output::{query_required_structured_json, StructuredJsonContract};
use anyhow::Result;
use serde::Deserialize;
use serde_json::{json, Value};

const PLANNER_SYSTEM_PROMPT: &str = "You are Kuzushi's autonomous attack-chain planner operating against an authorized target during a sanctioned engagement. Given the goal and the observations from prior steps, propose the SINGLE next HTTP play to run, or declare the goal reached. Build on what prior steps revealed. Never propose a step against a different host. Return only the JSON contract.";

/// The model's decision for one step: either run a play or stop.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannerStep {
    /// True when the planner judges the goal reached (or unreachable) and the
    /// loop should stop without running another play.
    #[serde(default)]
    pub done: bool,
    #[serde(default)]
    pub rationale: String,
    /// The next play to run, when `done` is false.
    #[serde(default)]
    pub play: Option<PlaySpec>,
}

/// Bounds for an autonomous run.
#[derive(Debug, Clone, Copy)]
pub struct PlannerBudget {
    pub max_steps: u32,
}

/// Drive the autonomous loop. The target is already authorized (the caller
/// holds the [`PlayContext`]); each step queries the planner, builds the
/// proposed play, executes it through `transport`, and threads the
/// observation back. Stops on `done`, on no proposed play, or at `max_steps`.
pub fn run_planned_chain(
    chain_name: &str,
    goal: &str,
    ctx: &PlayContext,
    runtime: &dyn AgentRuntime,
    model: &str,
    workspace_root: &std::path::Path,
    transport: &dyn PlayTransport,
    budget: PlannerBudget,
    observer: &dyn HopObserver,
) -> Result<ChainOutcome> {
    let mut steps: Vec<PlayOutcome> = Vec::new();
    let mut observations: Vec<String> = Vec::new();
    let mut stopped_by_planner = false;
    observer.on_chain_start(chain_name, &ctx.target().to_string());

    for _ in 0..budget.max_steps.max(1) {
        observer.on_planning(steps.len());
        let decision = plan_next_step(goal, &observations, runtime, model, workspace_root)?;
        if decision.done {
            stopped_by_planner = true;
            break;
        }
        let Some(spec) = decision.play else {
            stopped_by_planner = true;
            break;
        };
        let outcome = execute_planned_step(&spec, ctx, transport)?;
        observer.on_hop(steps.len(), &outcome);
        observations.push(observation_line(&outcome));
        let landed = outcome.exploited;
        steps.push(outcome);
        if !landed {
            break;
        }
    }

    Ok(finish_planned_chain(chain_name, ctx, steps, stopped_by_planner))
}

fn plan_next_step(
    goal: &str,
    observations: &[String],
    runtime: &dyn AgentRuntime,
    model: &str,
    workspace_root: &std::path::Path,
) -> Result<PlannerStep> {
    let prompt = planner_prompt(goal, observations);
    query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            workspace_root.to_path_buf(),
            PLANNER_SYSTEM_PROMPT.to_string(),
            prompt,
        ),
        StructuredJsonContract::new("offense:plan", "PlannerStep", planner_step_schema()),
        |raw| Ok(serde_json::from_value::<PlannerStep>(raw)?),
    )
}

fn execute_planned_step(
    spec: &PlaySpec,
    ctx: &PlayContext,
    transport: &dyn PlayTransport,
) -> Result<PlayOutcome> {
    let play = spec
        .build_play()
        .map_err(|reason| anyhow::anyhow!("planner proposed an invalid play: {reason}"))?;
    play.execute(ctx, transport)
        .map_err(|reason| anyhow::anyhow!(reason))
}

fn planner_prompt(goal: &str, observations: &[String]) -> String {
    let history = if observations.is_empty() {
        "No steps run yet.".to_string()
    } else {
        observations.join("\n")
    };
    format!("Goal: {goal}\n\nObservations so far:\n{history}\n\nPropose the next play or set done=true.")
}

fn observation_line(outcome: &PlayOutcome) -> String {
    format!(
        "{} [{}]: {}{}",
        outcome.play,
        if outcome.exploited { "landed" } else { "miss" },
        outcome.summary,
        outcome
            .observation
            .as_ref()
            .map(|o| format!(" | {o}"))
            .unwrap_or_default()
    )
}

fn finish_planned_chain(
    chain_name: &str,
    ctx: &PlayContext,
    steps: Vec<PlayOutcome>,
    stopped_by_planner: bool,
) -> ChainOutcome {
    let landed = steps.iter().filter(|s| s.exploited).count();
    // A planned chain "completed" when the planner stopped on its own terms
    // with at least one landed step and no failed step forced the break.
    let last_failed = steps.last().is_some_and(|s| !s.exploited);
    let completed = stopped_by_planner && landed > 0 && !last_failed;
    let summary = format!(
        "planned chain: {landed}/{} step(s) landed{}",
        steps.len(),
        if stopped_by_planner { ", planner stopped" } else { ", step budget exhausted" }
    );
    ChainOutcome {
        chain: chain_name.to_string(),
        target: ctx.target().to_string(),
        steps,
        completed,
        summary,
    }
}

fn planner_step_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": true,
        "properties": {
            "done": {"type": "boolean"},
            "rationale": {"type": "string"},
            "play": {"type": ["object", "null"]}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::engagement_scope::{EngagementScope, ScopeEntry, ScopeTarget};
    use super::super::observer::NoopObserver;
    use super::super::transport::{PlayRequest, PlayResponse};
    use crate::findings::TriageOutcome;
    use crate::runtime::{AgentQueryResponse, AgentRuntime, TriageRequest};
    use std::path::Path;
    use std::sync::Mutex;

    struct ScriptedRuntime {
        replies: Mutex<Vec<Value>>,
    }
    impl ScriptedRuntime {
        fn new(replies: Vec<Value>) -> Self {
            Self {
                replies: Mutex::new(replies),
            }
        }
    }
    impl AgentRuntime for ScriptedRuntime {
        fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            let mut replies = self.replies.lock().unwrap();
            let value = if replies.is_empty() {
                json!({"done": true, "rationale": "no more"})
            } else {
                replies.remove(0)
            };
            Ok(AgentQueryResponse {
                structured: Some(value),
                ..Default::default()
            })
        }
        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            unreachable!("planner does not triage")
        }
    }

    struct OkTransport;
    impl PlayTransport for OkTransport {
        fn send(&self, _t: &ScopeTarget, _r: &PlayRequest) -> Result<PlayResponse, String> {
            Ok(PlayResponse {
                status: 200,
                headers: Vec::new(),
                body: "welcome admin".to_string(),
                elapsed_ms: 1,
            })
        }
    }

    fn ctx() -> PlayContext {
        let scope = EngagementScope {
            authorized: true,
            authorization_ref: "lab".to_string(),
            in_scope: vec![ScopeEntry::parse("10.0.0.5").unwrap()],
            ..Default::default()
        };
        let authorized = scope.authorize(ScopeTarget::parse("10.0.0.5"), 1).unwrap();
        PlayContext::new(authorized, "run-1")
    }

    fn probe_step(name: &str) -> Value {
        json!({
            "done": false,
            "play": {"name": name, "path": "/admin", "expectStatus": 200, "expectSignals": ["admin"]}
        })
    }

    #[test]
    fn planner_runs_proposed_steps_until_done() {
        let runtime = ScriptedRuntime::new(vec![
            probe_step("recon"),
            probe_step("exploit"),
            json!({"done": true, "rationale": "goal reached"}),
        ]);
        let outcome = run_planned_chain(
            "auto",
            "get admin",
            &ctx(),
            &runtime,
            "openai:gpt-test",
            Path::new("/tmp/ws"),
            &OkTransport,
            PlannerBudget { max_steps: 10 },
            &NoopObserver,
        )
        .unwrap();
        assert_eq!(outcome.steps.len(), 2);
        assert!(outcome.completed);
    }

    #[test]
    fn planner_loop_respects_the_step_budget() {
        // Always proposes another landing step; only the budget stops it.
        let runtime = ScriptedRuntime::new(vec![
            probe_step("s1"),
            probe_step("s2"),
            probe_step("s3"),
            probe_step("s4"),
        ]);
        let outcome = run_planned_chain(
            "auto",
            "goal",
            &ctx(),
            &runtime,
            "openai:gpt-test",
            Path::new("/tmp/ws"),
            &OkTransport,
            PlannerBudget { max_steps: 2 },
            &NoopObserver,
        )
        .unwrap();
        assert_eq!(outcome.steps.len(), 2);
        assert!(outcome.summary.contains("budget exhausted"));
    }

    #[test]
    fn done_on_first_step_runs_nothing() {
        let runtime = ScriptedRuntime::new(vec![json!({"done": true})]);
        let outcome = run_planned_chain(
            "auto",
            "goal",
            &ctx(),
            &runtime,
            "openai:gpt-test",
            Path::new("/tmp/ws"),
            &OkTransport,
            PlannerBudget { max_steps: 5 },
            &NoopObserver,
        )
        .unwrap();
        assert!(outcome.steps.is_empty());
        assert!(!outcome.completed);
    }
}
