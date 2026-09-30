use super::*;

#[derive(Debug, thiserror::Error)]
#[error("agent tool loop interrupted; final provider spend is unresolved: {cause}")]
pub struct AgentLoopFailure {
    pub outcome: AgentLoopOutcome,
    pub usage: ModelTokenUsage,
    #[source]
    cause: anyhow::Error,
}

pub fn run_tool_loop(
    runtime: &dyn AgentRuntime,
    request: &AgentToolLoopRequest,
    handler: &mut dyn ToolCallHandler,
) -> Result<AgentLoopOutcome> {
    run_tool_loop_observed(runtime, request, handler).map(Observed::into_value)
}

pub fn run_tool_loop_observed(
    runtime: &dyn AgentRuntime,
    request: &AgentToolLoopRequest,
    handler: &mut dyn ToolCallHandler,
) -> Result<Observed<AgentLoopOutcome>> {
    ensure_tool_loop_runtime(runtime)?;

    let cap = request.max_steps.max(1);
    let checkpoint = super::loop_checkpoint::LoopCheckpointStore::discover(request);
    let _lease = checkpoint
        .as_ref()
        .map(|store| store.acquire_lease())
        .transpose()?;
    let mut accumulator = LoopAccumulator::resumed_from(&checkpoint);
    let first_step = super::loop_checkpoint::restored_step_count(&accumulator.transcript);
    for step in first_step..cap {
        let outcome = next_loop_step(runtime, request, &accumulator.transcript, step)
            .map_err(|error| accumulator.failure(error, step))?;
        if let Some(final_outcome) = accumulator
            .apply_step(outcome, handler, step + 1, &checkpoint)
            .map_err(|error| accumulator.failure(error, step + 1))?
        {
            clear_checkpoint(&checkpoint);
            return Ok(final_outcome);
        }
        save_checkpoint(&checkpoint, &accumulator.transcript)
            .map_err(|error| accumulator.failure(error, step + 1))?;
    }

    clear_checkpoint(&checkpoint);
    Ok(accumulator.truncated(cap))
}

fn save_checkpoint(
    checkpoint: &Option<super::loop_checkpoint::LoopCheckpointStore>,
    transcript: &[LoopHistoryEntry],
) -> Result<()> {
    if let Some(store) = checkpoint {
        store.save(transcript)?;
    }
    Ok(())
}

fn clear_checkpoint(checkpoint: &Option<super::loop_checkpoint::LoopCheckpointStore>) {
    if let Some(store) = checkpoint {
        store.clear();
    }
}

struct LoopAccumulator {
    transcript: Vec<LoopHistoryEntry>,
    cost: RuntimeCostReport,
    usage: ModelTokenUsage,
}

impl Default for LoopAccumulator {
    fn default() -> Self {
        Self {
            transcript: Vec::new(),
            cost: RuntimeCostReport::known(RuntimeCost::ZERO),
            usage: ModelTokenUsage::default(),
        }
    }
}

impl LoopAccumulator {
    fn failure(&self, cause: anyhow::Error, steps_used: u32) -> AgentLoopFailure {
        AgentLoopFailure {
            cause,
            usage: self.usage,
            outcome: AgentLoopOutcome {
                text: String::new(),
                structured: None,
                steps_used,
                truncated: true,
                cost_usd: self.cost.observed_usd(),
                cost_usd_exact: false,
                transcript: self.transcript.clone(),
            },
        }
    }

    /// Seed the transcript from an interrupted run of the identical request.
    /// Restored rounds were paid for by the previous run, so cost/usage stay
    /// zero here — this run reports only what it spends itself.
    fn resumed_from(checkpoint: &Option<super::loop_checkpoint::LoopCheckpointStore>) -> Self {
        let mut accumulator = Self::default();
        if let Some(transcript) = checkpoint.as_ref().and_then(|store| store.load()) {
            accumulator.transcript = transcript;
        }
        accumulator
    }
}

impl LoopAccumulator {
    fn apply_step(
        &mut self,
        outcome: Observed<AgentLoopStep>,
        handler: &mut dyn ToolCallHandler,
        steps_used: u32,
        checkpoint: &Option<super::loop_checkpoint::LoopCheckpointStore>,
    ) -> Result<Option<Observed<AgentLoopOutcome>>> {
        self.usage = self
            .usage
            .checked_add(outcome.usage, "agent tool-loop accumulated")?;
        match outcome.value {
            AgentLoopStep::ToolCall { call, cost_usd } => {
                self.apply_tool_call(call, cost_usd, handler, checkpoint)?;
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
        checkpoint: &Option<super::loop_checkpoint::LoopCheckpointStore>,
    ) -> Result<()> {
        self.add_cost(cost_usd)?;
        self.transcript
            .push(LoopHistoryEntry::AssistantToolCall(call.clone()));
        // An unfinished intent is never replayed automatically. If completion
        // persistence fails, recovery requires reconciliation of this call ID.
        save_checkpoint(checkpoint, &self.transcript)?;
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
    ) -> Result<Observed<AgentLoopOutcome>> {
        self.add_cost(cost_usd)?;
        if !text.is_empty() {
            self.transcript
                .push(LoopHistoryEntry::AssistantText(text.clone()));
        }
        Ok(Observed::new(
            AgentLoopOutcome {
                text,
                structured,
                steps_used,
                truncated: false,
                cost_usd: self.cost.observed_usd(),
                cost_usd_exact: self.cost.is_complete(),
                transcript: std::mem::take(&mut self.transcript),
            },
            self.usage,
        ))
    }

    fn truncated(mut self, steps_used: u32) -> Observed<AgentLoopOutcome> {
        Observed::new(
            AgentLoopOutcome {
                text: String::new(),
                structured: None,
                steps_used,
                truncated: true,
                cost_usd: self.cost.observed_usd(),
                cost_usd_exact: self.cost.is_complete(),
                transcript: std::mem::take(&mut self.transcript),
            },
            self.usage,
        )
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
) -> Result<Observed<AgentLoopStep>> {
    runtime
        .next_step_observed_blocking(request, transcript)
        .with_context(|| format!("agent loop step {step} failed"))
        .and_then(|observed| observed.try_map(AgentLoopStep::validate_cost))
}

fn tool_error_result(call: &ToolCall, err: anyhow::Error) -> ToolResult {
    ToolResult {
        call_id: call.call_id.clone(),
        output: serde_json::json!({ "error": err.to_string() }),
        is_error: true,
    }
}
