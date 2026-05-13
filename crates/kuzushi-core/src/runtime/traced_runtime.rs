use super::*;
use crate::run_artifacts::TraceHandle;
use std::time::Instant;

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
                let mut step = self
                    .trace
                    .step("reasoning", verb, label)
                    .with_latency_ms(elapsed_ms);
                if response.cost_usd > 0.0 {
                    step = step.with_cost_usd(response.cost_usd);
                }
                let _ = step.emit();
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

    fn record_step(&self, result: &Result<AgentLoopStep>, elapsed_ms: u64, history_len: usize) {
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
                let mut step = self
                    .trace
                    .step("done", "next-step", label)
                    .with_latency_ms(elapsed_ms);
                if let Some(cost) = cost_usd {
                    if *cost > 0.0 {
                        step = step.with_cost_usd(*cost);
                    }
                }
                let _ = step.emit();
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
impl AgentRuntime for TracedRuntime<'_> {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        let start = Instant::now();
        let prompt_len = request.prompt.len();
        let result = self.inner.query_blocking(request);
        self.record_query(
            "query",
            prompt_len,
            &result,
            start.elapsed().as_millis() as u64,
        );
        result
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        let start = Instant::now();
        let title = request.finding.title.clone();
        let result = self.inner.triage_finding_blocking(request);
        let elapsed_ms = start.elapsed().as_millis() as u64;
        match &result {
            Ok(_) => {
                let _ = self
                    .trace
                    .step(
                        "reasoning",
                        "triage",
                        format!("triage · {}", preview_str(&title)),
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
        self.record_step(&result, start.elapsed().as_millis() as u64, history.len());
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
        let verb = subagent_trace_verb(role);
        self.record_query(
            verb,
            prompt_len,
            &result,
            start.elapsed().as_millis() as u64,
        );
        result
    }
}

fn subagent_trace_verb(role: SubagentRole) -> &'static str {
    const VERBS: &[(SubagentRole, &str)] = &[
        (SubagentRole::Generic, "subagent"),
        (SubagentRole::UnsafeBlockReasoner, "subagent-unsafe"),
        (SubagentRole::LifetimeAliasingReasoner, "subagent-lifetime"),
        (SubagentRole::FfiBoundaryReasoner, "subagent-ffi"),
    ];
    VERBS
        .iter()
        .find_map(|(candidate, verb)| (*candidate == role).then_some(*verb))
        .unwrap_or("subagent")
}

fn preview_text(text: &str) -> String {
    let mut body = text.trim_start();
    let mut opening_fence = None;
    if let Some(rest) = strip_opening_fence(body, "```") {
        body = rest;
        opening_fence = Some("```");
    } else if let Some(rest) = strip_opening_fence(body, "~~~") {
        body = rest;
        opening_fence = Some("~~~");
    }
    if let Some(fence) = opening_fence {
        body = strip_closing_fence(body, fence);
    }
    let collapsed = body.replace(['\n', '\r'], " ");
    preview_str(&collapsed.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn strip_opening_fence<'a>(text: &'a str, fence: &str) -> Option<&'a str> {
    let rest = text.strip_prefix(fence)?;
    let rest = rest.trim_start_matches(|c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    Some(rest.trim_start_matches(['\n', '\r']))
}

fn strip_closing_fence<'a>(text: &'a str, fence: &str) -> &'a str {
    text.trim_end()
        .strip_suffix(fence)
        .map(str::trim_end)
        .unwrap_or(text)
}

fn preview_str(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.chars().count() <= 80 {
        trimmed.to_string()
    } else {
        let mut out = trimmed.chars().take(77).collect::<String>();
        out.push_str("...");
        out
    }
}

fn preview_value(value: &Value) -> String {
    if value.is_null() {
        return String::new();
    }
    let value = value.to_string();
    if value.chars().count() <= 60 {
        value
    } else {
        let mut out = value.chars().take(57).collect::<String>();
        out.push_str("...");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Finding, Severity, TriageVerdict};
    use crate::run_artifacts::{RunTraceStep, TraceSink};
    use std::sync::{Arc, Mutex};

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
            Ok(TriageOutcome {
                verdict: TriageVerdict::TruePositive,
                confidence: 0.8,
                rationale: "evidence matches".to_string(),
                cost_usd: 0.0,
            })
        }

        fn supports_tools(&self) -> bool {
            true
        }

        fn next_step_blocking(
            &self,
            _request: &AgentToolLoopRequest,
            history: &[LoopHistoryEntry],
        ) -> Result<AgentLoopStep> {
            if history.len() >= 4 {
                return Ok(AgentLoopStep::Final {
                    text: "done".to_string(),
                    structured: None,
                    cost_usd: Some(0.01),
                });
            }
            Ok(AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "read_source".to_string(),
                    input: serde_json::json!({"path": "src/lib.rs"}),
                    call_id: format!("call-{}", history.len()),
                },
            })
        }
    }

    fn fresh_runtime(responses: Vec<Result<AgentQueryResponse>>) -> (Arc<VecSink>, FakeRuntime) {
        (
            Arc::new(VecSink::default()),
            FakeRuntime {
                responses: Mutex::new(responses),
            },
        )
    }

    fn traced<'a>(runtime: &'a FakeRuntime, sink: Arc<VecSink>) -> TracedRuntime<'a> {
        let sink: Arc<dyn TraceSink> = sink;
        TracedRuntime::new(runtime, TraceHandle::new(sink).for_module("triage"))
    }

    #[test]
    fn traced_query_emits_reasoning_step_with_cost_and_latency() {
        let (sink, runtime) = fresh_runtime(vec![Ok(AgentQueryResponse {
            text: "verdict=likely-tp".to_string(),
            cost_usd: 0.0023,
            ..Default::default()
        })]);
        let traced = traced(&runtime, sink.clone());

        let _ = traced
            .query_blocking(AgentQueryRequest::new(
                "openai:gpt-test",
                ".",
                "system",
                "what is X?",
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
    fn traced_query_strips_markdown_fence_in_preview() {
        let (sink, runtime) = fresh_runtime(vec![Ok(AgentQueryResponse {
            text: "```json\n{\"verdict\":\"tp\"}\n```".to_string(),
            ..Default::default()
        })]);
        let traced = traced(&runtime, sink.clone());

        let _ = traced
            .query_blocking(AgentQueryRequest::new("openai:gpt-test", ".", "", "prompt"))
            .unwrap();

        let steps = sink.steps.lock().unwrap();
        assert!(steps[0].label.contains("{\"verdict\":\"tp\"}"));
        assert!(!steps[0].label.contains("```"));
    }

    #[test]
    fn traced_query_failure_emits_refused_with_danger_severity() {
        let (sink, runtime) = fresh_runtime(vec![Err(anyhow::anyhow!("model timeout"))]);
        let traced = traced(&runtime, sink.clone());

        let _ = traced.query_blocking(AgentQueryRequest::new("m", ".", "s", "p"));

        let steps = sink.steps.lock().unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].kind, "refused");
        assert_eq!(steps[0].severity.as_deref(), Some("danger"));
    }

    #[test]
    fn traced_next_step_emits_tool_progress_then_done() {
        let (sink, runtime) = fresh_runtime(vec![]);
        let traced = traced(&runtime, sink.clone());
        let request = AgentToolLoopRequest {
            model: "openai:gpt-test".to_string(),
            cwd: ".".into(),
            system_prompt: "s".to_string(),
            prompt: "p".to_string(),
            tools: vec![],
            max_steps: 5,
            runtime_options: None,
            temperature: None,
        };
        let mut history = Vec::new();

        for _ in 0..3 {
            match traced.next_step_blocking(&request, &history).unwrap() {
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
        }

        let steps = sink.steps.lock().unwrap();
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].kind, "tool-progress");
        assert!(steps[0].label.contains("read_source"));
        assert_eq!(steps[2].kind, "done");
        assert_eq!(steps[2].cost_usd, Some(0.01));
    }

    #[test]
    fn traced_triage_emits_reasoning_step() {
        let (sink, runtime) = fresh_runtime(vec![]);
        let traced = traced(&runtime, sink.clone());

        let _ = traced
            .triage_finding_blocking(TriageRequest {
                model: "openai:gpt-test".to_string(),
                cwd: ".".into(),
                finding: Finding {
                    id: None,
                    scan_id: None,
                    fingerprint: "fp".to_string(),
                    rule_id: "test".to_string(),
                    title: "SQL injection".to_string(),
                    severity: Severity::High,
                    file_path: "src/lib.rs".to_string(),
                    start_line: 1,
                    end_line: None,
                    message: "evidence".to_string(),
                    tool: "test".to_string(),
                    actor_fingerprint: None,
                    static_proof_state: None,
                    triage: None,
                    verification: None,
                    created_at: String::new(),
                    vuln_source: None,
                    dedup_key: None,
                    evidence: Vec::new(),
                },
                prompt_template: None,
            })
            .unwrap();

        let steps = sink.steps.lock().unwrap();
        assert_eq!(steps[0].kind, "reasoning");
        assert!(steps[0].label.contains("SQL injection"));
    }
}
