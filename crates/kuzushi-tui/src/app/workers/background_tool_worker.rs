use super::*;

#[derive(Debug)]
pub(crate) enum ScanEvent {
    Stage(String),
    Finished {
        run_id: String,
        findings_count: usize,
    },
    Failed {
        error: String,
    },
}

#[derive(Debug)]
pub(crate) enum ToolEvent {
    Finished {
        tool_name: String,
        result: serde_json::Value,
    },
    Failed {
        tool_name: String,
        error: String,
    },
}

#[derive(Debug)]
pub(crate) enum AgentEvent {
    Answered {
        text: String,
        audit: AgentCallAudit,
    },
    Failed {
        error: String,
        audit: AgentCallAudit,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct AgentCallAudit {
    pub(crate) model: String,
    pub(crate) provider: String,
    pub(crate) prompt_hash: String,
    pub(crate) cost_usd: Option<f64>,
}

impl AgentCallAudit {
    pub(crate) fn for_prompt(model: &str, system_prompt: &str, prompt: &str) -> Self {
        Self {
            model: model.to_string(),
            provider: kuzushi_core::model_provider(model).to_string(),
            prompt_hash: kuzushi_core::prompt_pair_hash(system_prompt, prompt),
            cost_usd: None,
        }
    }

    pub(crate) fn with_cost_usd(mut self, cost_usd: f64) -> Self {
        self.cost_usd = (cost_usd > 0.0).then_some(cost_usd);
        self
    }
}

#[derive(Debug)]
pub(crate) enum PlanEvent {
    Proposed(PlanProposal),
    Failed { error: String },
}

#[derive(Debug)]
pub(crate) enum ThreatPatchEvent {
    Proposed(ThreatPatch),
    Answer { text: String },
    Failed { error: String },
}

pub(crate) fn background_tool_worker(
    registry: ModuleRegistry,
    config: V2Config,
    workspace: WorkspaceTarget,
    tool_name: String,
    input: serde_json::Value,
    run_id: String,
    thinking_level: Option<String>,
    tx: Sender<ToolEvent>,
    trace_handle: Option<TraceHandle>,
) {
    let result = run_background_tool(
        registry,
        config,
        &workspace,
        &tool_name,
        input,
        &run_id,
        thinking_level,
        trace_handle,
    );
    let event = match result {
        Ok(result) => ToolEvent::Finished { tool_name, result },
        Err(error) => ToolEvent::Failed {
            tool_name,
            // `{:#}` walks the full anyhow chain so operators see the
            // underlying provider/bridge cause (e.g. "Anthropic API 429
            // Too Many Requests"), not just the topmost wrap
            // ("agent loop step 0 failed"). Without this, debugging
            // model-side failures from the shell requires digging into
            // `.kuzushi/runs/<id>/trace.jsonl` or rerunning under `kuzushi run`.
            error: format!("{error:#}"),
        },
    };
    let _ = tx.send(event);
}
