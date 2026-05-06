use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::findings::{Finding, TriageOutcome};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageRequest {
    pub model: String,
    pub cwd: PathBuf,
    pub finding: Finding,
    pub prompt_template: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentQueryRequest {
    pub model: String,
    pub cwd: PathBuf,
    pub system_prompt: String,
    pub prompt: String,
    #[serde(default)]
    pub tool_policy: AgentToolPolicy,
}

impl AgentQueryRequest {
    pub fn new(
        model: impl Into<String>,
        cwd: impl Into<PathBuf>,
        system_prompt: impl Into<String>,
        prompt: impl Into<String>,
    ) -> Self {
        Self {
            model: model.into(),
            cwd: cwd.into(),
            system_prompt: system_prompt.into(),
            prompt: prompt.into(),
            tool_policy: AgentToolPolicy::default(),
        }
    }

    pub fn with_tool_policy(mut self, tool_policy: AgentToolPolicy) -> Self {
        self.tool_policy = tool_policy;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentToolPolicy {
    pub profile: String,
    #[serde(default)]
    pub tools: Vec<String>,
}

impl AgentToolPolicy {
    pub fn new(
        profile: impl Into<String>,
        tools: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            profile: profile.into(),
            tools: tools.into_iter().map(Into::into).collect(),
        }
    }

    pub fn is_default(&self) -> bool {
        self.profile == "default" && self.tools.is_empty()
    }
}

impl Default for AgentToolPolicy {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
            tools: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentQueryResponse {
    pub text: String,
    pub structured: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub input: Value,
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
    pub max_steps: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum AgentLoopStep {
    ToolCall {
        #[serde(flatten)]
        call: ToolCall,
    },
    Final {
        #[serde(default)]
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        structured: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cost_usd: Option<f64>,
    },
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
    tools: BTreeMap<String, Box<dyn FnMut(&ToolCall) -> Result<ToolResult> + Send>>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoopHistoryEntry {
    AssistantToolCall(ToolCall),
    ToolResult(ToolResult),
    AssistantText(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentLoopOutcome {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured: Option<Value>,
    pub steps_used: u32,
    pub truncated: bool,
    #[serde(default)]
    pub cost_usd: f64,
    pub transcript: Vec<LoopHistoryEntry>,
}

#[async_trait]
pub trait AgentRuntime: Send + Sync {
    fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        anyhow::bail!("agent runtime does not support generic pi-agent-core queries")
    }

    async fn query(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.query_blocking(request)
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome>;

    async fn triage_finding(&self, request: TriageRequest) -> Result<TriageOutcome> {
        self.triage_finding_blocking(request)
    }

    /// Run triage and additionally classify the rationale for refusal-language
    /// (e.g. "I cannot", "skipped because"). Default impl is heuristic-only:
    /// it does not issue a follow-up agent call. Concrete runtimes that want
    /// to invoke a structured follow-up turn override this method.
    fn triage_finding_with_refusal_blocking(
        &self,
        request: TriageRequest,
    ) -> Result<(TriageOutcome, crate::findings::RefusalReport)> {
        let outcome = self.triage_finding_blocking(request)?;
        let refusal = crate::findings::detect_refusal_in_text(&outcome.rationale);
        Ok((outcome, refusal))
    }

    fn supports_tools(&self) -> bool {
        false
    }

    fn next_step_blocking(
        &self,
        _request: &AgentToolLoopRequest,
        _history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        anyhow::bail!(
            "agent runtime does not support tool-augmented loops; implement next_step_blocking"
        )
    }
}

pub fn run_tool_loop(
    runtime: &dyn AgentRuntime,
    request: &AgentToolLoopRequest,
    handler: &mut dyn ToolCallHandler,
) -> Result<AgentLoopOutcome> {
    if !runtime.supports_tools() {
        anyhow::bail!("runtime does not support tool-augmented loops");
    }

    let mut transcript: Vec<LoopHistoryEntry> = Vec::new();
    let mut cost_usd = 0.0f64;
    let cap = request.max_steps.max(1);

    for step in 0..cap {
        let outcome = runtime
            .next_step_blocking(request, &transcript)
            .with_context(|| format!("agent loop step {step} failed"))?;
        match outcome {
            AgentLoopStep::ToolCall { call } => {
                transcript.push(LoopHistoryEntry::AssistantToolCall(call.clone()));
                let result = handler.run(&call).unwrap_or_else(|err| ToolResult {
                    call_id: call.call_id.clone(),
                    output: serde_json::json!({ "error": err.to_string() }),
                    is_error: true,
                });
                transcript.push(LoopHistoryEntry::ToolResult(result));
            }
            AgentLoopStep::Final {
                text,
                structured,
                cost_usd: step_cost,
            } => {
                if let Some(c) = step_cost {
                    cost_usd += c;
                }
                if !text.is_empty() {
                    transcript.push(LoopHistoryEntry::AssistantText(text.clone()));
                }
                return Ok(AgentLoopOutcome {
                    text,
                    structured,
                    steps_used: step + 1,
                    truncated: false,
                    cost_usd,
                    transcript,
                });
            }
        }
    }

    Ok(AgentLoopOutcome {
        text: String::new(),
        structured: None,
        steps_used: cap,
        truncated: true,
        cost_usd,
        transcript,
    })
}
