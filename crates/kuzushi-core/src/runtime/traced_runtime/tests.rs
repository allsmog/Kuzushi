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
    triage_cost_usd_exact: bool,
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
        Ok(TriageOutcome { first_link: None, refute_reason: None,
            verdict: TriageVerdict::TruePositive,
            confidence: 0.8,
            rationale: "evidence matches".to_string(),
            cost_usd: 0.0,
            cost_usd_exact: self.triage_cost_usd_exact,
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
            cost_usd: None,
        })
    }
}

fn fresh_runtime(responses: Vec<Result<AgentQueryResponse>>) -> (Arc<VecSink>, FakeRuntime) {
    (
        Arc::new(VecSink::default()),
        FakeRuntime {
            responses: Mutex::new(responses),
            triage_cost_usd_exact: true,
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
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0].kind, "tool-progress");
    assert_eq!(steps[0].verb.as_deref(), Some("query"));
    assert!(steps[0].label.contains("sending"));
    assert_eq!(steps[1].kind, "reasoning");
    assert_eq!(steps[1].verb.as_deref(), Some("query"));
    assert!(steps[1].label.contains("query completed"));
    assert!(!steps[1].label.contains("verdict=likely-tp"));
    assert!(steps[1].latency_ms.is_some());
    assert_eq!(steps[1].cost_usd, Some(0.0023));
    assert_eq!(steps[0].model.as_deref(), Some("openai:gpt-test"));
    assert_eq!(steps[0].provider.as_deref(), Some("openai"));
    assert!(steps[0]
        .prompt_hash
        .as_deref()
        .is_some_and(|hash| hash.starts_with("fnv1a64:")));
}

#[test]
fn traced_query_never_persists_model_response_preview() {
    let (sink, runtime) = fresh_runtime(vec![Ok(AgentQueryResponse {
        text: "```json\n{\"verdict\":\"tp\"}\n```".to_string(),
        ..Default::default()
    })]);
    let traced = traced(&runtime, sink.clone());

    let _ = traced
        .query_blocking(AgentQueryRequest::new("openai:gpt-test", ".", "", "prompt"))
        .unwrap();

    let steps = sink.steps.lock().unwrap();
    assert!(!steps[1].label.contains("{\"verdict\":\"tp\"}"));
    assert!(!steps[1].label.contains("```"));
}

#[test]
fn partial_aggregate_usage_is_disclosed_as_a_lower_bound() {
    let usage = ModelTokenUsage::reported(12, 3)
        .checked_add(ModelTokenUsage::unavailable_call(), "test aggregate")
        .unwrap();
    let success: Result<()> = Ok(());

    assert_eq!(
        super::model_call_error_class(&success, usage),
        Some("usage_incomplete_lower_bound")
    );
    assert_eq!(
        super::model_call_error_class(&success, ModelTokenUsage::unavailable_call()),
        None
    );
    let failure: Result<()> = Err(anyhow::anyhow!("model timeout"));
    assert_eq!(
        super::model_call_error_class(&failure, usage),
        Some("timeout")
    );
    assert_eq!(super::persisted_model_usage(usage).input_tokens, Some(12));
}

#[test]
fn model_call_failure_classes_are_sanitized() {
    let sentinel = "raw-model-response-sentinel";
    let cases = [
        ("operator canceled request", "canceled"),
        ("request timed out", "timeout"),
        ("provider returned 429", "rate_limited"),
        ("missing authentication credential", "authentication"),
        (
            "could not parse response: raw-model-response-sentinel",
            "invalid_response",
        ),
        ("network connection failed", "transport"),
        ("unexpected adapter failure", "runtime_error"),
    ];

    for (message, expected) in cases {
        let result: Result<()> = Err(anyhow::anyhow!(message));
        let error_class =
            super::model_call_error_class(&result, ModelTokenUsage::unavailable_call());

        assert_eq!(error_class, Some(expected));
        assert!(!error_class.unwrap().contains(sentinel));
    }
}

#[test]
fn observed_query_persists_usage_without_model_response_content() {
    struct ObservedQueryRuntime {
        response: Mutex<Option<Observed<AgentQueryResponse>>>,
    }

    #[async_trait]
    impl AgentRuntime for ObservedQueryRuntime {
        fn query_observed_blocking(
            &self,
            _request: AgentQueryRequest,
        ) -> Result<Observed<AgentQueryResponse>> {
            self.response
                .lock()
                .unwrap()
                .take()
                .context("missing response")
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            unreachable!("not used in this test")
        }
    }

    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("observed-query");
    let observation =
        crate::run_lifecycle::RunObservationHandle::jsonl(target.path(), &run_id).unwrap();
    let response_sentinel = "raw-model-response-sentinel";
    let runtime = ObservedQueryRuntime {
        response: Mutex::new(Some(Observed::new(
            AgentQueryResponse {
                text: response_sentinel.to_string(),
                ..Default::default()
            },
            ModelTokenUsage::reported(77, 11),
        ))),
    };
    let traced = TracedRuntime::new(&runtime, observation.trace_handle());

    traced
        .query_blocking(AgentQueryRequest::new(
            "openai:gpt-test",
            ".",
            "system",
            "prompt",
        ))
        .unwrap();
    observation.flush().unwrap();

    let read = crate::run_lifecycle::read_run_items(target.path(), &run_id)
        .unwrap()
        .unwrap();
    let usage = read.items.iter().find_map(|item| match &item.item {
        crate::run_lifecycle::RunItemV1::ModelCallFinished { usage, .. } => Some(usage),
        _ => None,
    });
    assert_eq!(usage.and_then(|usage| usage.input_tokens), Some(77));
    assert_eq!(usage.and_then(|usage| usage.output_tokens), Some(11));
    let stream = std::fs::read_to_string(crate::run_artifacts::run_artifact_path(
        target.path(),
        &run_id,
        "items.jsonl",
    ))
    .unwrap();
    assert!(!stream.contains(response_sentinel));
}

#[test]
fn failed_query_persists_only_the_sanitized_error_class() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("failed-query");
    let observation =
        crate::run_lifecycle::RunObservationHandle::jsonl(target.path(), &run_id).unwrap();
    let sentinel = "raw-model-response-sentinel";
    let runtime = FakeRuntime {
        responses: Mutex::new(vec![Err(anyhow::anyhow!(
            "could not parse response: {sentinel}"
        ))]),
        triage_cost_usd_exact: true,
    };
    let traced = TracedRuntime::new(&runtime, observation.trace_handle());

    let error = traced
        .query_blocking(AgentQueryRequest::new(
            "openai:gpt-test",
            ".",
            "system",
            "prompt",
        ))
        .unwrap_err();
    assert!(error.to_string().contains(sentinel));
    observation.flush().unwrap();

    let read = crate::run_lifecycle::read_run_items(target.path(), &run_id)
        .unwrap()
        .unwrap();
    let error_class = read.items.iter().find_map(|item| match &item.item {
        crate::run_lifecycle::RunItemV1::ModelCallFinished { error_class, .. } => {
            error_class.as_ref().map(|error_class| error_class.as_str())
        }
        _ => None,
    });
    assert_eq!(error_class, Some("invalid_response"));
    let stream = std::fs::read_to_string(crate::run_artifacts::run_artifact_path(
        target.path(),
        &run_id,
        "items.jsonl",
    ))
    .unwrap();
    assert!(!stream.contains(sentinel));
}

#[test]
fn traced_query_failure_emits_refused_with_danger_severity() {
    let (sink, runtime) = fresh_runtime(vec![Err(anyhow::anyhow!("model timeout"))]);
    let traced = traced(&runtime, sink.clone());

    let _ = traced.query_blocking(AgentQueryRequest::new("m", ".", "s", "p"));

    let steps = sink.steps.lock().unwrap();
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0].kind, "tool-progress");
    assert_eq!(steps[1].kind, "refused");
    assert_eq!(steps[1].severity.as_deref(), Some("danger"));
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
            AgentLoopStep::ToolCall { call, .. } => {
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
    assert_eq!(steps.len(), 6);
    assert_eq!(steps[0].kind, "tool-progress");
    assert!(steps[0].label.contains("waiting on model"));
    assert_eq!(steps[1].kind, "tool-progress");
    assert!(steps[1].label.starts_with("agent-action:"));
    assert!(steps[1].label.contains("read_source"));
    assert!(steps[1].label.contains("options path"));
    assert!(!steps[1].label.contains("src/lib.rs"));
    assert_eq!(steps[0].model.as_deref(), Some("openai:gpt-test"));
    assert!(steps[0].prompt_hash.is_some());
    assert_eq!(steps[5].kind, "done");
    assert_eq!(steps[5].cost_usd, Some(0.01));
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
fn traced_triage_emits_reasoning_without_persisting_the_finding_title() {
    let (sink, runtime) = fresh_runtime(vec![]);
    let traced = traced(&runtime, sink.clone());

    let _ = traced
        .triage_finding_blocking(triage_request("SQL injection"))
        .unwrap();

    let steps = sink.steps.lock().unwrap();
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0].kind, "tool-progress");
    assert_eq!(steps[0].label, "triage · checking finding");
    assert_eq!(steps[1].kind, "reasoning");
    assert_eq!(steps[1].label, "triage completed");
    assert!(!steps
        .iter()
        .any(|step| step.label.contains("SQL injection")));
    assert_eq!(steps[0].model.as_deref(), Some("openai:gpt-test"));
    assert_eq!(steps[0].provider.as_deref(), Some("openai"));
    assert!(steps[0].prompt_hash.is_some());
    assert_eq!(steps[1].cost_usd, Some(0.0));
}

#[test]
fn traced_triage_omits_unreported_zero_cost() {
    let (sink, mut runtime) = fresh_runtime(vec![]);
    runtime.triage_cost_usd_exact = false;
    let traced = traced(&runtime, sink.clone());

    let _ = traced
        .triage_finding_blocking(triage_request("Unpriced triage"))
        .unwrap();

    let steps = sink.steps.lock().unwrap();
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[1].kind, "reasoning");
    assert_eq!(steps[1].cost_usd, None);
}

fn triage_request(title: &str) -> TriageRequest {
    let mut finding = Finding::new_tool(
        "test",
        "test",
        "src/lib.rs",
        1,
        None,
        Severity::High,
        "evidence",
    );
    finding.title = title.to_string();
    TriageRequest {
        model: "openai:gpt-test".to_string(),
        cwd: ".".into(),
        finding,
        prompt_template: None,
    }
}
