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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentQueryResponse {
    pub text: String,
    pub structured: Option<Value>,
}

// ---------------------------------------------------------------------------
// Tool-augmented agent loop (Phase 4 plumbing).
//
// The deep auditor in Phase 5 will give the model a small set of read-only
// code-navigation tools (read_source, read_definition, find_references,
// list_definitions). Each "step" is one round-trip to the model: the model
// either calls a tool (the host runs it locally and feeds the result back)
// or returns a final answer.
//
// The trait method is default-erroring so existing runtimes that don't
// implement tool use continue to compile — `PiAgentCoreRuntime` overrides
// it in Phase 5 with the bridge envelope. The driver `run_tool_loop`
// lives outside the trait so dispatch logic can evolve without breaking
// downstream impls.
// ---------------------------------------------------------------------------

/// Schema description for one tool the model may call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTool {
    /// Tool identifier exposed to the model (e.g. `read_source`).
    pub name: String,
    pub description: String,
    /// JSON Schema for the tool's input. Forwarded verbatim to Anthropic /
    /// OpenAI's tool-use API.
    pub input_schema: Value,
}

/// One pending tool call from the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub input: Value,
    /// Provider-supplied id used to thread the result back into the next
    /// turn (Anthropic `tool_use.id`, OpenAI `tool_call.id`).
    pub call_id: String,
}

/// Result of executing a tool call locally. Forwarded back to the model on
/// the next step.
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
}

/// Bridge response for one step.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum AgentLoopStep {
    /// Model invoked a tool — host should execute and call `next_step`
    /// again with the result attached.
    ToolCall {
        #[serde(flatten)]
        call: ToolCall,
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

/// Trait implemented by hosts that can dispatch a single round-trip.
/// Stateless from the trait's POV — history is provided by the driver.
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

/// Map-backed handler — for tests + simple cases. Each tool is a closure.
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

/// One transcript entry — used by the driver and forwarded to the runtime
/// so each step can reconstruct the conversation history. The shape is
/// intentionally close to the Anthropic message format so the bridge can
/// pass it through without re-shaping.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoopHistoryEntry {
    AssistantToolCall(ToolCall),
    ToolResult(ToolResult),
    AssistantText(String),
}

/// Final outcome of [`run_tool_loop`]. `transcript` is always populated —
/// callers get the full step history even on truncation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentLoopOutcome {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured: Option<Value>,
    pub steps_used: u32,
    pub truncated: bool,
    /// Sum of per-step costs surfaced by the bridge.
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

    /// Whether this runtime supports tool-augmented loops.
    fn supports_tools(&self) -> bool {
        false
    }

    /// One round-trip in a tool-augmented loop. The runtime is responsible
    /// for talking to the model with `request.tools` and the running
    /// `history`; it must not execute the tools itself. Default impl is
    /// errored so existing impls don't have to change until they need it.
    fn next_step_blocking(
        &self,
        _request: &AgentToolLoopRequest,
        _history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        anyhow::bail!(
            "agent runtime does not support tool-augmented loops; \
             implement next_step_blocking or call query_blocking instead"
        )
    }
}

/// Drive a tool-augmented loop to completion (or `max_steps`). The driver
/// is the canonical loop body — runtime impls only handle one step at a
/// time, so they don't need to know about `ToolBox` or history shape.
pub fn run_tool_loop(
    runtime: &dyn AgentRuntime,
    request: &AgentToolLoopRequest,
    handler: &mut dyn ToolCallHandler,
) -> Result<AgentLoopOutcome> {
    if !runtime.supports_tools() {
        anyhow::bail!(
            "runtime does not support tool-augmented loops (set supports_tools() = true \
             and implement next_step_blocking)"
        );
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

    // Hit max_steps without a Final.
    Ok(AgentLoopOutcome {
        text: String::new(),
        structured: None,
        steps_used: cap,
        truncated: true,
        cost_usd,
        transcript,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mock runtime that walks a scripted sequence of [`AgentLoopStep`] outputs
    /// — used to exercise the driver without a real bridge.
    struct ScriptedRuntime {
        steps: Mutex<Vec<AgentLoopStep>>,
        seen: Mutex<Vec<usize>>, // history length seen by each call
    }

    impl ScriptedRuntime {
        fn new(steps: Vec<AgentLoopStep>) -> Self {
            Self {
                steps: Mutex::new(steps),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl AgentRuntime for ScriptedRuntime {
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            unreachable!("not used in these tests")
        }
        fn supports_tools(&self) -> bool {
            true
        }
        fn next_step_blocking(
            &self,
            _request: &AgentToolLoopRequest,
            history: &[LoopHistoryEntry],
        ) -> Result<AgentLoopStep> {
            self.seen.lock().unwrap().push(history.len());
            let mut s = self.steps.lock().unwrap();
            if s.is_empty() {
                anyhow::bail!("scripted runtime exhausted")
            }
            Ok(s.remove(0))
        }
    }

    fn req() -> AgentToolLoopRequest {
        AgentToolLoopRequest {
            model: "anthropic:claude-sonnet-4-6".to_string(),
            cwd: PathBuf::from("/tmp"),
            system_prompt: "you are a tester".to_string(),
            prompt: "do the thing".to_string(),
            tools: vec![AgentTool {
                name: "read_source".to_string(),
                description: "read a file".to_string(),
                input_schema: serde_json::json!({ "type": "object" }),
            }],
            max_steps: 5,
        }
    }

    #[test]
    fn driver_returns_final_in_one_step() {
        let runtime = ScriptedRuntime::new(vec![AgentLoopStep::Final {
            text: "done".to_string(),
            structured: Some(serde_json::json!({"verdict": "tp"})),
            cost_usd: Some(0.01),
        }]);
        let mut tb = ToolBox::new();
        let outcome = run_tool_loop(&runtime, &req(), &mut tb).unwrap();
        assert_eq!(outcome.text, "done");
        assert_eq!(outcome.steps_used, 1);
        assert!(!outcome.truncated);
        assert_eq!(outcome.cost_usd, 0.01);
        assert_eq!(outcome.transcript.len(), 1);
        assert!(matches!(outcome.transcript[0], LoopHistoryEntry::AssistantText(_)));
    }

    #[test]
    fn driver_threads_tool_call_through_handler() {
        let runtime = ScriptedRuntime::new(vec![
            AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "read_source".to_string(),
                    input: serde_json::json!({ "path": "src/foo.rs" }),
                    call_id: "call_1".to_string(),
                },
            },
            AgentLoopStep::Final {
                text: "saw foo".to_string(),
                structured: None,
                cost_usd: None,
            },
        ]);
        let mut tb = ToolBox::new();
        tb.register("read_source", |call| {
            assert_eq!(call.name, "read_source");
            Ok(ToolResult {
                call_id: call.call_id.clone(),
                output: serde_json::json!({ "contents": "fn main() {}" }),
                is_error: false,
            })
        });
        let outcome = run_tool_loop(&runtime, &req(), &mut tb).unwrap();
        assert_eq!(outcome.text, "saw foo");
        assert_eq!(outcome.steps_used, 2);
        // Transcript: ToolCall, ToolResult, AssistantText.
        assert_eq!(outcome.transcript.len(), 3);
        assert!(matches!(
            outcome.transcript[0],
            LoopHistoryEntry::AssistantToolCall(_)
        ));
        assert!(matches!(
            outcome.transcript[1],
            LoopHistoryEntry::ToolResult(_)
        ));
        // History grew between calls — second runtime call should have seen
        // the tool call + result.
        let seen = runtime.seen.lock().unwrap();
        assert_eq!(seen[0], 0);
        assert_eq!(seen[1], 2);
    }

    #[test]
    fn driver_marks_truncation_at_max_steps() {
        // Five tool calls in a row, max_steps=3 → truncate after 3rd ToolCall.
        let runtime = ScriptedRuntime::new(
            (0..5)
                .map(|i| AgentLoopStep::ToolCall {
                    call: ToolCall {
                        name: "read_source".to_string(),
                        input: serde_json::Value::Null,
                        call_id: format!("call_{i}"),
                    },
                })
                .collect(),
        );
        let mut tb = ToolBox::new();
        tb.register("read_source", |call| {
            Ok(ToolResult {
                call_id: call.call_id.clone(),
                output: serde_json::Value::Null,
                is_error: false,
            })
        });
        let mut request = req();
        request.max_steps = 3;
        let outcome = run_tool_loop(&runtime, &request, &mut tb).unwrap();
        assert!(outcome.truncated);
        assert_eq!(outcome.steps_used, 3);
    }

    #[test]
    fn unknown_tool_is_returned_as_error_result_not_panic() {
        let runtime = ScriptedRuntime::new(vec![
            AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "no_such_tool".to_string(),
                    input: serde_json::Value::Null,
                    call_id: "call_x".to_string(),
                },
            },
            AgentLoopStep::Final {
                text: "ok".to_string(),
                structured: None,
                cost_usd: None,
            },
        ]);
        let mut tb = ToolBox::new();
        let outcome = run_tool_loop(&runtime, &req(), &mut tb).unwrap();
        assert_eq!(outcome.text, "ok");
        // The error result must have been threaded through to the next step.
        let result = outcome
            .transcript
            .iter()
            .find_map(|e| match e {
                LoopHistoryEntry::ToolResult(r) => Some(r),
                _ => None,
            })
            .expect("expected a ToolResult in transcript");
        assert!(result.is_error);
        assert!(
            result.output.to_string().contains("unknown tool"),
            "got {:?}",
            result.output
        );
    }

    #[test]
    fn handler_panic_is_caught_as_error_result() {
        // Defence in depth: a tool that panics shouldn't unwind the loop —
        // catch in the handler closure and return a structured error.
        let runtime = ScriptedRuntime::new(vec![
            AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "buggy".to_string(),
                    input: serde_json::Value::Null,
                    call_id: "c1".to_string(),
                },
            },
            AgentLoopStep::Final {
                text: "ok".to_string(),
                structured: None,
                cost_usd: None,
            },
        ]);
        let mut tb = ToolBox::new();
        tb.register("buggy", |_| anyhow::bail!("simulated tool failure"));
        let outcome = run_tool_loop(&runtime, &req(), &mut tb).unwrap();
        let result = outcome
            .transcript
            .iter()
            .find_map(|e| match e {
                LoopHistoryEntry::ToolResult(r) => Some(r),
                _ => None,
            })
            .expect("expected a ToolResult");
        assert!(result.is_error);
        assert!(result.output.to_string().contains("simulated tool failure"));
    }

    #[test]
    fn legacy_runtime_without_supports_tools_is_rejected() {
        struct LegacyRuntime;
        impl AgentRuntime for LegacyRuntime {
            fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
                unreachable!()
            }
        }
        let mut tb = ToolBox::new();
        let err = run_tool_loop(&LegacyRuntime, &req(), &mut tb)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not support tool-augmented loops"), "{err}");
    }
}
