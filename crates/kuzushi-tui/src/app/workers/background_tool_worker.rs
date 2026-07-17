use super::*;

#[derive(Debug)]
pub(crate) enum ScanEvent {
    Stage(String),
    Finished { result: serde_json::Value },
    Failed { error: String },
}

#[derive(Debug)]
#[allow(dead_code)] // Legacy/unobserved variants remain for in-crate compatibility tests.
pub(crate) enum ToolEvent {
    Finished {
        tool_name: String,
        result: serde_json::Value,
    },
    Failed {
        tool_name: String,
        error: String,
    },
    Refused {
        tool_name: String,
        error: String,
    },
    ObservedFinished {
        tool_name: String,
        result: serde_json::Value,
        completion: kuzushi_core::PendingToolCallCompletion,
    },
    ObservedFailed {
        tool_name: String,
        error: String,
        completion: kuzushi_core::PendingToolCallCompletion,
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
    pub(crate) cost: kuzushi_core::runtime::RuntimeCostReport,
    pub(crate) call_attempted: bool,
}

impl AgentCallAudit {
    pub(crate) fn for_prompt(model: &str, system_prompt: &str, prompt: &str) -> Self {
        Self {
            model: model.to_string(),
            provider: kuzushi_core::model_provider(model).to_string(),
            prompt_hash: kuzushi_core::prompt_pair_hash(system_prompt, prompt),
            cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
            call_attempted: false,
        }
    }

    pub(crate) fn with_cost(mut self, cost: kuzushi_core::runtime::RuntimeCostReport) -> Self {
        self.cost = cost;
        self.call_attempted = true;
        self
    }

    pub(crate) fn with_outcome(
        mut self,
        cost: kuzushi_core::runtime::RuntimeCostReport,
        call_attempted: bool,
    ) -> Self {
        self.cost = cost;
        self.call_attempted = call_attempted;
        self
    }

    pub(crate) fn settlement_cost(&self) -> kuzushi_core::runtime::RuntimeCostReport {
        if !self.call_attempted {
            return kuzushi_core::runtime::RuntimeCostReport::known(
                kuzushi_core::runtime::RuntimeCost::ZERO,
            );
        }
        if self.cost.is_unavailable() {
            kuzushi_core::runtime::RuntimeCostReport::INCOMPLETE_ZERO
        } else {
            self.cost
        }
    }

    #[cfg(test)]
    pub(crate) fn test() -> Self {
        Self::for_prompt("test:model", "system", "prompt")
    }
}

pub(crate) type CostedWorkerResult<T> =
    Result<(T, kuzushi_core::runtime::RuntimeCostReport), CostedWorkerError>;

#[derive(Debug)]
pub(crate) struct CostedWorkerError {
    pub(crate) error: anyhow::Error,
    pub(crate) cost: kuzushi_core::runtime::RuntimeCostReport,
    pub(crate) call_attempted: bool,
}

impl CostedWorkerError {
    pub(crate) fn before_call(error: anyhow::Error) -> Self {
        Self {
            error,
            cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
            call_attempted: false,
        }
    }

    pub(crate) fn unresolved(error: anyhow::Error) -> Self {
        Self {
            error,
            cost: kuzushi_core::runtime::RuntimeCostReport::INCOMPLETE_ZERO,
            call_attempted: true,
        }
    }

    pub(crate) fn observed(
        error: anyhow::Error,
        cost: kuzushi_core::runtime::RuntimeCostReport,
    ) -> Self {
        Self {
            error,
            cost,
            call_attempted: true,
        }
    }
}

#[derive(Debug)]
pub(crate) enum PlanEvent {
    Proposed {
        plan: PlanProposal,
        audit: AgentCallAudit,
    },
    Failed {
        error: String,
        audit: AgentCallAudit,
    },
}

#[derive(Debug)]
pub(crate) enum ThreatPatchEvent {
    Proposed {
        patch: ThreatPatch,
        audit: AgentCallAudit,
    },
    Answer {
        text: String,
        audit: AgentCallAudit,
    },
    Failed {
        error: String,
        audit: AgentCallAudit,
    },
}

pub(crate) fn background_tool_worker(
    registry: ModuleRegistry,
    config: V2Config,
    workspace: WorkspaceTarget,
    tool_name: String,
    input: PreparedToolInput,
    run_id: String,
    thinking_level: Option<String>,
    authorization: ExecutionAuthorization,
    sink: JobEventSink,
    trace_handle: Option<TraceHandle>,
    cancel: ScanCancellation,
) {
    if cancel.is_cancelled() {
        sink.send(ShellEvent::Tool(ToolEvent::Failed {
            tool_name,
            error: "tool run cancelled before start".to_string(),
        }));
        return;
    }
    let result = run_background_tool_observed(
        registry,
        config,
        &workspace,
        &tool_name,
        input,
        &run_id,
        thinking_level,
        authorization,
        trace_handle,
        cancel.clone(),
    );
    send_tool_event(&sink, tool_result_event(tool_name, result));
}

fn send_tool_event(sink: &JobEventSink, event: ToolEvent) {
    sink.send(ShellEvent::Tool(event));
}

fn tool_result_event(
    tool_name: String,
    result: Result<kuzushi_core::ObservedDispatchOutcome>,
) -> ToolEvent {
    match result {
        Ok(outcome) => match outcome.execution {
            Ok(result) => ToolEvent::ObservedFinished {
                tool_name,
                result,
                completion: outcome.completion,
            },
            Err(error) => ToolEvent::ObservedFailed {
                tool_name,
                error: format!("{error:#}"),
                completion: outcome.completion,
            },
        },
        Err(error) => failed_tool_event(tool_name, error),
    }
}

fn failed_tool_event(tool_name: String, error: anyhow::Error) -> ToolEvent {
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<kuzushi_core::modules::AutonomyRefusal>()
            .is_some()
    }) {
        return ToolEvent::Refused {
            tool_name,
            error: format!("{error:#}"),
        };
    }
    ToolEvent::Failed {
        tool_name,
        // `{:#}` walks the full anyhow chain so operators see the
        // underlying provider/bridge cause (e.g. "Anthropic API 429
        // Too Many Requests"), not just the topmost wrap
        // ("agent loop step 0 failed"). Without this, debugging
        // model-side failures from the shell requires digging into
        // `.kuzushi/v3/runs/<id>/trace.jsonl` or rerunning under `kuzushi run`.
        error: format!("{error:#}"),
    }
}
