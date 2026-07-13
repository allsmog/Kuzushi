use super::*;

pub fn run_tool_loop(
    runtime: &dyn AgentRuntime,
    request: &AgentToolLoopRequest,
    handler: &mut dyn ToolCallHandler,
) -> Result<AgentLoopOutcome> {
    ensure_tool_loop_runtime(runtime)?;

    let cap = request.max_steps.max(1);
    let mut accumulator = LoopAccumulator::default();
    for step in 0..cap {
        let outcome = next_loop_step(runtime, request, &accumulator.transcript, step)?;
        if let Some(final_outcome) = accumulator.apply_step(outcome, handler, step + 1)? {
            return Ok(final_outcome);
        }
    }

    Ok(accumulator.truncated(cap))
}

struct LoopAccumulator {
    transcript: Vec<LoopHistoryEntry>,
    cost: RuntimeCostReport,
}

impl Default for LoopAccumulator {
    fn default() -> Self {
        Self {
            transcript: Vec::new(),
            cost: RuntimeCostReport::known(RuntimeCost::ZERO),
        }
    }
}

impl LoopAccumulator {
    fn apply_step(
        &mut self,
        outcome: AgentLoopStep,
        handler: &mut dyn ToolCallHandler,
        steps_used: u32,
    ) -> Result<Option<AgentLoopOutcome>> {
        match outcome {
            AgentLoopStep::ToolCall { call, cost_usd } => {
                self.apply_tool_call(call, cost_usd, handler)?;
                Ok(None)
            }
            AgentLoopStep::Final {
                text,
                structured,
                cost_usd,
            } => self
                .final_outcome(text, structured, cost_usd, steps_used)
                .map(Some),
        }
    }

    fn apply_tool_call(
        &mut self,
        call: ToolCall,
        cost_usd: Option<f64>,
        handler: &mut dyn ToolCallHandler,
    ) -> Result<()> {
        self.add_cost(cost_usd)?;
        self.transcript
            .push(LoopHistoryEntry::AssistantToolCall(call.clone()));
        let result = handler
            .run(&call)
            .unwrap_or_else(|err| tool_error_result(&call, err));
        self.transcript.push(LoopHistoryEntry::ToolResult(result));
        Ok(())
    }

    fn final_outcome(
        &mut self,
        text: String,
        structured: Option<serde_json::Value>,
        cost_usd: Option<f64>,
        steps_used: u32,
    ) -> Result<AgentLoopOutcome> {
        self.add_cost(cost_usd)?;
        if !text.is_empty() {
            self.transcript
                .push(LoopHistoryEntry::AssistantText(text.clone()));
        }
        Ok(AgentLoopOutcome {
            text,
            structured,
            steps_used,
            truncated: false,
            cost_usd: self.cost.observed_usd(),
            cost_usd_exact: self.cost.is_complete(),
            transcript: std::mem::take(&mut self.transcript),
        })
    }

    fn truncated(mut self, steps_used: u32) -> AgentLoopOutcome {
        AgentLoopOutcome {
            text: String::new(),
            structured: None,
            steps_used,
            truncated: true,
            cost_usd: self.cost.observed_usd(),
            cost_usd_exact: self.cost.is_complete(),
            transcript: std::mem::take(&mut self.transcript),
        }
    }

    fn add_cost(&mut self, cost_usd: Option<f64>) -> Result<()> {
        self.cost = self.cost.checked_add(
            RuntimeCostReport::from_optional(cost_usd, "agent loop step cost")?,
            "agent tool-loop accumulated cost",
        )?;
        Ok(())
    }
}

fn ensure_tool_loop_runtime(runtime: &dyn AgentRuntime) -> Result<()> {
    if !runtime.supports_tools() {
        anyhow::bail!(
            "runtime does not support tool-augmented loops (set supports_tools() = true \
             and implement next_step_blocking)"
        );
    }
    Ok(())
}

fn next_loop_step(
    runtime: &dyn AgentRuntime,
    request: &AgentToolLoopRequest,
    transcript: &[LoopHistoryEntry],
    step: u32,
) -> Result<AgentLoopStep> {
    runtime
        .next_step_blocking(request, transcript)
        .with_context(|| format!("agent loop step {step} failed"))
        .and_then(AgentLoopStep::validate_cost)
}

fn tool_error_result(call: &ToolCall, err: anyhow::Error) -> ToolResult {
    ToolResult {
        call_id: call.call_id.clone(),
        output: serde_json::json!({ "error": err.to_string() }),
        is_error: true,
    }
}
