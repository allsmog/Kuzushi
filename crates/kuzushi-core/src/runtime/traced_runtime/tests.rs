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
    assert_eq!(steps[0].model.as_deref(), Some("openai:gpt-test"));
    assert_eq!(steps[0].provider.as_deref(), Some("openai"));
    assert!(steps[0]
        .prompt_hash
        .as_deref()
        .is_some_and(|hash| hash.starts_with("fnv1a64:")));
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
    assert_eq!(steps[0].model.as_deref(), Some("m"));
    assert_eq!(steps[0].provider.as_deref(), Some(""));
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
    assert_eq!(steps[0].model.as_deref(), Some("openai:gpt-test"));
    assert!(steps[0].prompt_hash.is_some());
    assert_eq!(steps[2].kind, "done");
    assert_eq!(steps[2].cost_usd, Some(0.01));
}

#[test]
fn traced_tool_loop_preflight_emits_model_audit_metadata() {
    let (sink, runtime) = fresh_runtime(vec![]);
    let traced = traced(&runtime, sink.clone());
    let request = AgentToolLoopRequest {
        model: "openai:gpt-test".to_string(),
        cwd: ".".into(),
        system_prompt: "preflight system".to_string(),
        prompt: "preflight prompt".to_string(),
        tools: vec![],
        max_steps: 1,
        runtime_options: None,
        temperature: None,
    };

    traced.preflight_tool_loop_blocking(&request).unwrap();

    let steps = sink.steps.lock().unwrap();
    assert_eq!(steps[0].kind, "tool-progress");
    assert_eq!(steps[0].verb.as_deref(), Some("next-step"));
    assert_eq!(steps[0].model.as_deref(), Some("openai:gpt-test"));
    assert_eq!(steps[0].provider.as_deref(), Some("openai"));
    assert!(steps[0]
        .prompt_hash
        .as_deref()
        .is_some_and(|hash| hash.starts_with("fnv1a64:")));
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
                suppressed: false,
                snoozed_until: None,
                remediation: None,
                references: Vec::new(),
                evidence: Vec::new(),
            },
            prompt_template: None,
        })
        .unwrap();

    let steps = sink.steps.lock().unwrap();
    assert_eq!(steps[0].kind, "reasoning");
    assert!(steps[0].label.contains("SQL injection"));
    assert_eq!(steps[0].model.as_deref(), Some("openai:gpt-test"));
    assert_eq!(steps[0].provider.as_deref(), Some("openai"));
    assert!(steps[0].prompt_hash.is_some());
}
