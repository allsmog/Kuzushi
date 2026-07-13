use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTool {
    /// Tool identifier exposed to the model (e.g. `read_source`).
    pub name: String,
    pub description: String,
    /// JSON Schema for the tool's input. Forwarded verbatim to Anthropic /
    /// OpenAI's tool-use API.
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub input: Value,
    /// Provider-supplied id used to thread the result back into the next
    /// turn (Anthropic `tool_use.id`, OpenAI `tool_call.id`).
    pub call_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub call_id: String,
    pub output: Value,
    #[serde(default)]
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentToolLoopRequest {
    pub model: String,
    pub cwd: PathBuf,
    pub system_prompt: String,
    pub prompt: String,
    #[serde(default)]
    pub tools: Vec<AgentTool>,
    /// Hard upper bound on the number of model round-trips. The driver
    /// stops here and surfaces the partial transcript even if the model
    /// hasn't returned a final.
    pub max_steps: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_options: Option<AgentRuntimeOptions>,
    /// Sampling temperature for every round-trip in the loop. None
    /// means "use the provider default". Set near 0 for audit / triage
    /// flows where determinism matters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum AgentLoopStep {
    /// Model invoked a tool — host should execute and call `next_step`
    /// again with the result attached.
    ToolCall {
        #[serde(flatten)]
        call: ToolCall,
        /// Cost of this intermediate round-trip, when the bridge surfaces it.
        /// Accounting must not wait for the terminal `Final`: a loop that hits
        /// `max_steps` (or errors) still incurred the spend of every tool round
        /// it made, so the driver folds this into the running total per step.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cost_usd: Option<f64>,
    },
    /// Model returned a final answer — driver should exit the loop.
    Final {
        #[serde(default)]
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        structured: Option<Value>,
        /// Optional cost surfaced by the bridge for spend-ledger settlement.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cost_usd: Option<f64>,
    },
}

impl AgentLoopStep {
    pub fn validate_cost(self) -> Result<Self> {
        if let Some(cost_usd) = self.cost_usd() {
            super::RuntimeCost::from_usd(cost_usd, "agent loop step cost")?;
        }
        Ok(self)
    }

    pub fn cost_usd(&self) -> Option<f64> {
        match self {
            Self::ToolCall { cost_usd, .. } | Self::Final { cost_usd, .. } => *cost_usd,
        }
    }

    pub fn checked_cost_report(&self) -> Result<super::RuntimeCostReport> {
        super::RuntimeCostReport::from_optional(self.cost_usd(), "agent loop step cost")
    }
}

pub trait ToolCallHandler: Send {
    fn run(&mut self, call: &ToolCall) -> Result<ToolResult>;
}

impl<F> ToolCallHandler for F
where
    F: FnMut(&ToolCall) -> Result<ToolResult> + Send,
{
    fn run(&mut self, call: &ToolCall) -> Result<ToolResult> {
        (self)(call)
    }
}

pub struct ToolBox {
    pub(crate) tools: BTreeMap<String, Box<dyn FnMut(&ToolCall) -> Result<ToolResult> + Send>>,
}

impl Default for ToolBox {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolBox {
    pub fn new() -> Self {
        Self {
            tools: BTreeMap::new(),
        }
    }

    pub fn register<F>(&mut self, name: impl Into<String>, handler: F) -> &mut Self
    where
        F: FnMut(&ToolCall) -> Result<ToolResult> + Send + 'static,
    {
        self.tools.insert(name.into(), Box::new(handler));
        self
    }
}

impl ToolCallHandler for ToolBox {
    fn run(&mut self, call: &ToolCall) -> Result<ToolResult> {
        match self.tools.get_mut(&call.name) {
            Some(handler) => handler(call),
            None => Ok(ToolResult {
                call_id: call.call_id.clone(),
                output: serde_json::json!({
                    "error": format!("unknown tool {:?}", call.name)
                }),
                is_error: true,
            }),
        }
    }
}
