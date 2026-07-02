use super::*;
use crate::modules::registry::ToolDispatchResult;

/// The live-target offense module. Today it exposes `offense:chain`, which
/// runs an operator-authored attack chain against an authorized target. Every
/// play clears the engagement-scope gate before any traffic is sent.
pub(crate) fn offense_module() -> BuiltinModule {
    builtin_module(
        "offense",
        "Offense",
        ModuleKind::Offense,
        "Authorized live-target operations: run declarative attack chains (auth-bypass -> IDOR -> RCE) against a host the engagement scope allows.",
        vec![offense_chain_tool()],
        vec![],
    )
}

fn offense_chain_tool() -> ToolDescriptor {
    let mut options = vec![
        opt("target", OptionType::String, "Target host (IP or hostname) to operate against.")
            .aliases(&["targetHost", "target_host"])
            .required(),
        opt(
            "chain",
            OptionType::Json,
            "Inline chain spec: {name, plays:[{name, kind?(http-probe|prompt-injection), method?, path, headers?, body?, expectStatus?, expectSignals?, canary?, refusalSignals?}]}.",
        ),
        opt(
            "chainFile",
            OptionType::String,
            "Name of a chain spec under .kuzushi/plays/<name>.json (used when 'chain' is absent).",
        )
        .aliases(&["chain_file", "play"]),
        opt(
            "goal",
            OptionType::String,
            "Autonomous mode: a natural-language objective. When set, the model plans each next play toward it (requires the runtime); otherwise a declarative chain runs.",
        ),
    ];
    options.extend(offense_chain_advanced_options());
    tool_with_options(
        "offense:chain",
        "Run an attack chain against an authorized target — a declarative spec or, with 'goal', an autonomous LLM-planned loop. Requires an engagement scope (.kuzushi/engagement-scope.json or inline) that allows the target; a denied target never sends traffic.",
        options,
    )
}

fn offense_chain_advanced_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "maxSteps",
            OptionType::Int,
            "Autonomous mode: max planned steps (1-24).",
        )
        .aliases(&["max_steps"])
        .default(json!(8))
        .advanced(),
        opt(
            "scope",
            OptionType::Json,
            "Inline engagement scope; overrides .kuzushi/engagement-scope.json.",
        )
        .advanced(),
        opt(
            "timeoutMs",
            OptionType::Int,
            "Per-play network timeout in milliseconds.",
        )
        .aliases(&["timeout_ms"])
        .default(json!(15000))
        .advanced(),
        opt(
            "runId",
            OptionType::String,
            "Run id to record chain evidence under.",
        )
        .aliases(&["run_id"])
        .advanced(),
    ]
}

pub(in crate::modules) fn dispatch_offense_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "offense:chain" => Some(run_offense_chain(input, ctx, runtime)),
        _ => None,
    }
}

/// A non-empty `goal` selects autonomous (LLM-planned) mode; otherwise the
/// declarative chain spec runs.
fn run_offense_chain(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message("offense:chain"))?;
    let observer = TraceHopObserver { trace: ctx.trace };
    let goal = input
        .get("goal")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|goal| !goal.is_empty());

    let Some(goal) = goal else {
        return Ok(crate::offense::execute_offense_chain(
            input,
            workspace.root(),
            ctx.findings_store,
            &observer,
        ));
    };

    let runtime = runtime.context(
        "offense:chain autonomous mode (goal) requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or run a declarative chain instead.",
    )?;
    let model =
        crate::runtime::require_configured_model("offense:chain", ctx.config.model.as_deref())?;
    Ok(crate::offense::execute_offense_planned(
        input,
        workspace.root(),
        ctx.findings_store,
        runtime,
        &model,
        goal,
        &observer,
    ))
}

/// Streams chain progress into the Activity view: a parent `start` step for
/// the chain, a `reasoning` step when the planner is thinking, and a `done`
/// step per hop (severity-tagged so a landed hop stands out).
struct TraceHopObserver<'a> {
    trace: Option<&'a crate::run_artifacts::TraceHandle>,
}

impl crate::offense::HopObserver for TraceHopObserver<'_> {
    fn on_chain_start(&self, chain: &str, target: &str) {
        if let Some(trace) = self.trace {
            let _ = trace
                .step(
                    "tool",
                    "chain",
                    format!("offense:chain start · {chain} → {target}"),
                )
                .emit();
        }
    }

    fn on_planning(&self, step_index: usize) {
        if let Some(trace) = self.trace {
            let _ = trace
                .step(
                    "reasoning",
                    "chain",
                    format!("planning hop {}", step_index + 1),
                )
                .emit();
        }
    }

    fn on_hop(&self, step_index: usize, outcome: &crate::offense::PlayOutcome) {
        let Some(trace) = self.trace else {
            return;
        };
        let verdict = if outcome.exploited { "landed" } else { "miss" };
        let _ = trace
            .step(
                "done",
                "chain",
                format!("hop {} · {} · {}", step_index + 1, outcome.play, verdict),
            )
            .emit();
    }
}
