//! Tracing wrapper for `AgentRuntime` that records every LLM call into
//! the live module-progress feed.
//!
//! Constructed by the dispatch wrapper in
//! `crates/kuzushi-core/src/modules/registry/with_v2_builtins/execution.rs`
//! whenever both `ctx.trace.is_some()` and the dispatched tool requested a
//! runtime. The wrapper forwards every method on the `AgentRuntime` trait,
//! emitting a trace step before/after the underlying call so the operator
//! sees per-LLM-call activity in the right pane of the Activity view.

use super::*;
use crate::run_artifacts::TraceHandle;
use std::time::Instant;

/// Wraps an `AgentRuntime` and emits a trace step for every method
/// invocation. The wrapper is `Send + Sync` because it only stores a
/// shared reference plus an owned `TraceHandle` (itself Arc-backed).
pub struct TracedRuntime<'a> {
    inner: &'a dyn AgentRuntime,
    trace: TraceHandle,
}

impl<'a> TracedRuntime<'a> {
    pub fn new(inner: &'a dyn AgentRuntime, trace: TraceHandle) -> Self {
        Self { inner, trace }
    }

    fn record_query(
        &self,
        verb: &str,
        prompt_len: usize,
        result: &Result<AgentQueryResponse>,
        elapsed_ms: u64,
    ) {
        match result {
            Ok(response) => {
                let preview = preview_text(&response.text);
                let label = if preview.is_empty() {
                    format!("{verb} · {prompt_len} chars in")
                } else {
                    format!("{verb} · {preview}")
                };
                let mut builder = self
                    .trace
                    .step("reasoning", verb, label)
                    .with_latency_ms(elapsed_ms);
                if response.cost_usd > 0.0 {
                    builder = builder.with_cost_usd(response.cost_usd);
                }
                let _ = builder.emit();
            }
            Err(error) => {
                let _ = self
                    .trace
                    .step("refused", verb, format!("{verb} failed: {error}"))
                    .with_latency_ms(elapsed_ms)
                    .with_severity("danger")
                    .emit();
            }
        }
    }

    fn record_step(
        &self,
        result: &Result<AgentLoopStep>,
        elapsed_ms: u64,
        history_len: usize,
    ) {
        match result {
            Ok(AgentLoopStep::ToolCall { call }) => {
                let args_summary = preview_value(&call.input);
                let label = if args_summary.is_empty() {
                    format!("tool-call · {} (turn {})", call.name, history_len + 1)
                } else {
                    format!(
                        "tool-call · {}({}) (turn {})",
                        call.name,
                        args_summary,
                        history_len + 1
                    )
                };
                let _ = self
                    .trace
                    .step("tool-progress", "next-step", label)
                    .with_latency_ms(elapsed_ms)
                    .emit();
            }
            Ok(AgentLoopStep::Final { text, cost_usd, .. }) => {
                let preview = preview_text(text);
                let label = if preview.is_empty() {
                    format!("final · turn {}", history_len + 1)
                } else {
                    format!("final · {preview}")
                };
                let mut builder = self
                    .trace
                    .step("done", "next-step", label)
                    .with_latency_ms(elapsed_ms);
                if let Some(cost) = cost_usd {
                    if *cost > 0.0 {
                        builder = builder.with_cost_usd(*cost);
                    }
                }
                let _ = builder.emit();
            }
            Err(error) => {
                let _ = self
                    .trace
                    .step("refused", "next-step", format!("step failed: {error}"))
                    .with_latency_ms(elapsed_ms)
                    .with_severity("danger")
                    .emit();
            }
        }
    }
}

#[async_trait]
impl<'a> AgentRuntime for TracedRuntime<'a> {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        let start = Instant::now();
        let prompt_len = request.prompt.len();
        let result = self.inner.query_blocking(request);
        let elapsed_ms = start.elapsed().as_millis() as u64;
        self.record_query("query", prompt_len, &result, elapsed_ms);
        result
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        let start = Instant::now();
        let label_seed = request.finding.title.clone();
        let result = self.inner.triage_finding_blocking(request);
        let elapsed_ms = start.elapsed().as_millis() as u64;
        match &result {
            Ok(_) => {
                let _ = self
                    .trace
                    .step(
                        "reasoning",
                        "triage",
                        format!("triage · {}", preview_str(&label_seed)),
                    )
                    .with_latency_ms(elapsed_ms)
                    .emit();
            }
            Err(error) => {
                let _ = self
                    .trace
                    .step("refused", "triage", format!("triage failed: {error}"))
                    .with_latency_ms(elapsed_ms)
                    .with_severity("danger")
                    .emit();
            }
        }
        result
    }

    fn supports_tools(&self) -> bool {
        self.inner.supports_tools()
    }

    fn next_step_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        let start = Instant::now();
        let result = self.inner.next_step_blocking(request, history);
        let elapsed_ms = start.elapsed().as_millis() as u64;
        self.record_step(&result, elapsed_ms, history.len());
        result
    }

    fn model_for_tier(&self, tier: ModelTier, configured: &str) -> String {
        self.inner.model_for_tier(tier, configured)
    }

    fn spawn_subagent_blocking(
        &self,
        role: SubagentRole,
        request: AgentQueryRequest,
    ) -> Result<AgentQueryResponse> {
        let start = Instant::now();
        let prompt_len = request.prompt.len();
        let result = self.inner.spawn_subagent_blocking(role, request);
        let elapsed_ms = start.elapsed().as_millis() as u64;
        let verb = match role {
            SubagentRole::Generic => "subagent",
            SubagentRole::UnsafeBlockReasoner => "subagent-unsafe",
            SubagentRole::LifetimeAliasingReasoner => "subagent-lifetime",
            SubagentRole::FfiBoundaryReasoner => "subagent-ffi",
        };
        self.record_query(verb, prompt_len, &result, elapsed_ms);
        result
    }
}

/// First non-empty line of a response, capped at 80 chars. Drops trailing
/// whitespace and collapses internal newlines so feed lines stay short.
fn preview_text(text: &str) -> String {
    preview_str(
        text.lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or(""),
    )
}

fn preview_str(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.chars().count() <= 80 {
        trimmed.to_string()
    } else {
        let mut out: String = trimmed.chars().take(77).collect();
        out.push_str("...");
        out
    }
}

fn preview_value(value: &Value) -> String {
    if value.is_null() {
        return String::new();
    }
    let s = value.to_string();
    if s.chars().count() <= 60 {
        s
    } else {
        let mut out: String = s.chars().take(57).collect();
        out.push_str("...");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_artifacts::{RunTraceStep, TraceSink};
    use std::sync::Arc;
    use std::sync::Mutex;

    #[derive(Default)]
    struct VecSink {
        steps: Mutex<Vec<RunTraceStep>>,
    }
    impl TraceSink for VecSink {
        fn record(&self, step: &RunTraceStep) {
            self.steps.lock().unwrap().push(step.clone());
        }
    }

    struct FakeRuntime {
        responses: Mutex<Vec<Result<AgentQueryResponse>>>,
    }

    #[async_trait]
    impl AgentRuntime for FakeRuntime {
        fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.responses
                .lock()
                .unwrap()
                .pop()
                .unwrap_or_else(|| Ok(AgentQueryResponse::default()))
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            anyhow::bail!("unused in tests")
        }

        fn next_step_blocking(
            &self,
            _request: &AgentToolLoopRequest,
            history: &[LoopHistoryEntry],
        ) -> Result<AgentLoopStep> {
            // Each round trip adds two history entries (tool call + result),
            // so >=4 means the loop has completed two tool calls.
            if history.len() >= 4 {
                Ok(AgentLoopStep::Final {
                    text: "done".to_string(),
                    structured: None,
                    cost_usd: Some(0.01),
                })
            } else {
                Ok(AgentLoopStep::ToolCall {
                    call: ToolCall {
                        name: "read_source".to_string(),
                        input: serde_json::json!({"path": "src/lib.rs"}),
                        call_id: format!("call-{}", history.len()),
                    },
                })
            }
        }
    }

    fn fresh_handle() -> (Arc<VecSink>, TraceHandle) {
        let sink = Arc::new(VecSink::default());
        let handle = TraceHandle::new(sink.clone() as Arc<dyn TraceSink>).for_module("triage");
        (sink, handle)
    }

    #[test]
    fn traced_query_emits_reasoning_step_with_latency() {
        let (sink, handle) = fresh_handle();
        let runtime = FakeRuntime {
            responses: Mutex::new(vec![Ok(AgentQueryResponse {
                text: "verdict=likely-tp".to_string(),
                cost_usd: 0.0023,
                ..Default::default()
            })]),
        };
        let traced = TracedRuntime::new(&runtime, handle);
        let _ = traced
            .query_blocking(AgentQueryRequest::new(
                "claude-sonnet".to_string(),
                std::path::PathBuf::from("."),
                "system".to_string(),
                "what is X?".to_string(),
            ))
            .unwrap();

        let steps = sink.steps.lock().unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].kind, "reasoning");
        assert_eq!(steps[0].verb.as_deref(), Some("query"));
        assert!(steps[0].label.contains("verdict=likely-tp"));
        assert!(steps[0].latency_ms.is_some());
        assert_eq!(steps[0].cost_usd, Some(0.0023));
    }

    #[test]
    fn traced_query_failure_emits_refused_with_danger_severity() {
        let (sink, handle) = fresh_handle();
        let runtime = FakeRuntime {
            responses: Mutex::new(vec![Err(anyhow::anyhow!("model timeout"))]),
        };
        let traced = TracedRuntime::new(&runtime, handle);
        let _ = traced.query_blocking(AgentQueryRequest::new(
            "m".to_string(),
            std::path::PathBuf::from("."),
            "s".to_string(),
            "p".to_string(),
        ));
        let steps = sink.steps.lock().unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].kind, "refused");
        assert_eq!(steps[0].severity.as_deref(), Some("danger"));
    }

    #[test]
    fn traced_next_step_emits_tool_progress_then_done() {
        let (sink, handle) = fresh_handle();
        let runtime = FakeRuntime {
            responses: Mutex::new(vec![]),
        };
        let traced = TracedRuntime::new(&runtime, handle);
        let request = AgentToolLoopRequest {
            model: "claude".to_string(),
            cwd: std::path::PathBuf::from("."),
            system_prompt: "s".to_string(),
            prompt: "p".to_string(),
            tools: vec![],
            max_steps: 5,
        };
        let mut history = Vec::new();
        // Drive the loop manually, like run_tool_loop would.
        for i in 0..3 {
            let step = traced.next_step_blocking(&request, &history).unwrap();
            match step {
                AgentLoopStep::ToolCall { call } => {
                    history.push(LoopHistoryEntry::AssistantToolCall(call.clone()));
                    history.push(LoopHistoryEntry::ToolResult(ToolResult {
                        call_id: call.call_id,
                        output: serde_json::json!({"ok": true}),
                        is_error: false,
                    }));
                }
                AgentLoopStep::Final { .. } => break,
            }
            assert!(i < 2, "loop ran too long");
        }
        let steps = sink.steps.lock().unwrap();
        assert_eq!(steps.len(), 3, "2 tool-progress + 1 done");
        assert_eq!(steps[0].kind, "tool-progress");
        assert!(steps[0].label.contains("tool-call"));
        assert!(steps[0].label.contains("read_source"));
        assert_eq!(steps[1].kind, "tool-progress");
        assert_eq!(steps[2].kind, "done");
        assert!(steps[2].label.contains("final"));
    }

    #[test]
    fn parent_scope_threads_parent_step_into_runtime_calls() {
        let (sink, handle) = fresh_handle();
        let runtime = FakeRuntime {
            responses: Mutex::new(vec![Ok(AgentQueryResponse {
                text: "child output".to_string(),
                ..Default::default()
            })]),
        };
        let phase = handle.step("reasoning", "run", "evidence-collect").emit();
        let _scope = handle.parent_scope(phase);
        let traced = TracedRuntime::new(&runtime, handle.clone());
        let _ = traced.query_blocking(AgentQueryRequest::new(
            "m".to_string(),
            std::path::PathBuf::from("."),
            "s".to_string(),
            "p".to_string(),
        ));
        drop(_scope);

        let steps = sink.steps.lock().unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].label, "evidence-collect");
        assert!(
            steps[1].parent_step.is_some(),
            "child runtime call should reference the phase header"
        );
        assert_eq!(steps[1].parent_step, Some(phase));
    }
}
