use super::*;
use crate::run_lifecycle::{RunItemStatus, RunItemV1, RunObservationHandle};
use std::sync::Mutex;

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
        unreachable!("not used by these tests")
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

fn runtime_with(response: Result<AgentQueryResponse>) -> FakeRuntime {
    FakeRuntime {
        responses: Mutex::new(vec![response]),
    }
}

fn traced<'a>(
    runtime: &'a FakeRuntime,
    target: &std::path::Path,
    run_id: &str,
) -> TracedRuntime<'a> {
    let observation = RunObservationHandle::jsonl(target, run_id).unwrap();
    TracedRuntime::new(runtime, observation.trace_handle().for_module("triage"))
}

#[test]
fn query_emits_correlated_typed_model_lifecycle_and_safe_summary() {
    let target = tempfile::tempdir().unwrap();
    let runtime = runtime_with(Ok(AgentQueryResponse {
        text: "private provider response".to_string(),
        cost_usd: 0.0023,
        ..Default::default()
    }));
    traced(&runtime, target.path(), "typed-query")
        .query_blocking(AgentQueryRequest::new(
            "openai:gpt-test",
            ".",
            "system",
            "question",
        ))
        .unwrap();

    let read = crate::run_lifecycle::read_run_items(target.path(), "typed-query")
        .unwrap()
        .unwrap();
    let started = read.items.iter().find_map(|envelope| match envelope.item {
        RunItemV1::ModelCallStarted { .. } => envelope.call_id,
        _ => None,
    });
    let finished = read.items.iter().find_map(|envelope| match envelope.item {
        RunItemV1::ModelCallFinished {
            status: RunItemStatus::Completed,
            ..
        } => envelope.call_id,
        _ => None,
    });
    assert_eq!(started, finished);
    assert!(read
        .items
        .iter()
        .any(|envelope| matches!(envelope.item, RunItemV1::SafeReasoningSummary { .. })));
    let body = std::fs::read_to_string(crate::run_artifacts::run_artifact_path(
        target.path(),
        "typed-query",
        "items.jsonl",
    ))
    .unwrap();
    assert!(!body.contains("private provider response"));
}

#[test]
fn failed_query_finishes_the_same_model_call_as_failed() {
    let target = tempfile::tempdir().unwrap();
    let runtime = runtime_with(Err(anyhow::anyhow!("model timeout")));
    let result = traced(&runtime, target.path(), "typed-failure")
        .query_blocking(AgentQueryRequest::new("openai:gpt-test", ".", "s", "p"));
    assert!(result.is_err());

    let read = crate::run_lifecycle::read_run_items(target.path(), "typed-failure")
        .unwrap()
        .unwrap();
    assert!(read.items.iter().any(|envelope| matches!(
        envelope.item,
        RunItemV1::ModelCallFinished {
            status: RunItemStatus::Failed,
            ..
        }
    )));
    assert!(read.items.iter().any(|envelope| matches!(
        envelope.item,
        RunItemV1::DiagnosticNotice {
            level: crate::run_lifecycle::DiagnosticLevel::Error,
            ..
        }
    )));
}

#[test]
fn partial_aggregate_usage_is_disclosed_as_a_lower_bound() {
    let usage = ModelTokenUsage::reported(12, 3)
        .checked_add(ModelTokenUsage::unavailable_call(), "test aggregate")
        .unwrap();
    let success: Result<()> = Ok(());
    assert_eq!(
        super::model_call_error_class(&success, usage, None),
        Some("usage_incomplete_lower_bound")
    );
    assert_eq!(
        super::model_call_error_class(&success, ModelTokenUsage::unavailable_call(), None),
        None
    );
    let failure: Result<()> = Err(anyhow::anyhow!("model timeout"));
    let metadata = super::fallback_runtime_failure_metadata(failure.as_ref().unwrap_err());
    assert_eq!(
        super::model_call_error_class(&failure, usage, Some(&metadata)),
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
        let metadata = super::fallback_runtime_failure_metadata(result.as_ref().unwrap_err());
        let error_class = super::model_call_error_class(
            &result,
            ModelTokenUsage::unavailable_call(),
            Some(&metadata),
        );

        let expected = match expected {
            "canceled" => "cancelled",
            "invalid_response" => "provider_response_invalid",
            expected => expected,
        };
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

    traced_runtime(&runtime, target.path(), &run_id)
        .query_blocking(AgentQueryRequest::new(
            "openai:gpt-test",
            ".",
            "system",
            "prompt",
        ))
        .unwrap();

    let read = crate::run_lifecycle::read_run_items(target.path(), &run_id)
        .unwrap()
        .unwrap();
    let usage = read.items.iter().find_map(|item| match &item.item {
        RunItemV1::ModelCallFinished { usage, .. } => Some(usage),
        _ => None,
    });
    assert_eq!(usage.and_then(|usage| usage.input_tokens), Some(77));
    assert_eq!(usage.and_then(|usage| usage.output_tokens), Some(11));
    assert!(!run_item_stream(target.path(), &run_id).contains(response_sentinel));
}

#[test]
fn failed_query_persists_class_without_untyped_failure_detail() {
    let target = tempfile::tempdir().unwrap();
    let sentinel = "raw-model-response-sentinel";
    let runtime = runtime_with(Err(anyhow::anyhow!("could not parse response: {sentinel}")));

    let error = traced(&runtime, target.path(), "failed-query")
        .query_blocking(AgentQueryRequest::new(
            "openai:gpt-test",
            ".",
            "system",
            "prompt",
        ))
        .unwrap_err();

    assert!(error.to_string().contains(sentinel));
    let read = crate::run_lifecycle::read_run_items(target.path(), "failed-query")
        .unwrap()
        .unwrap();
    let error_class = read.items.iter().find_map(|item| match &item.item {
        RunItemV1::ModelCallFinished { error_class, .. } => {
            error_class.as_ref().map(|error_class| error_class.as_str())
        }
        _ => None,
    });
    assert_eq!(error_class, Some("provider_response_invalid"));
    assert!(!run_item_stream(target.path(), "failed-query").contains(sentinel));
}

#[test]
fn typed_runtime_failure_keeps_stage_call_model_class_status_and_safe_detail() {
    use crate::runtime::{RuntimeFailure, RuntimeFailureClass, RuntimeFailureMetadata};
    let target = tempfile::tempdir().unwrap();
    let metadata = RuntimeFailureMetadata::new(
        RuntimeFailureClass::SdkClientValidation,
        Some(400),
        Some("temperature incompatible with adaptive thinking; token=secret-sentinel"),
    );
    let runtime = runtime_with(Err(anyhow::Error::new(RuntimeFailure::new(metadata))));

    let _ = traced(&runtime, target.path(), "typed-failure")
        .query_blocking(
            AgentQueryRequest::new("anthropic:claude-test", ".", "system", "prompt")
                .with_stage("agentic-sast:review"),
        )
        .unwrap_err();

    let read = crate::run_lifecycle::read_run_items(target.path(), "typed-failure")
        .unwrap()
        .unwrap();
    let (call_id, model, failure) = read
        .items
        .iter()
        .find_map(|item| match &item.item {
            RunItemV1::ModelCallFinished {
                model,
                failure: Some(failure),
                ..
            } => Some((item.call_id.unwrap().to_string(), model.as_str(), failure)),
            _ => None,
        })
        .unwrap();
    assert_eq!(model, "anthropic:claude-test");
    assert_eq!(
        failure.error_class,
        RuntimeFailureClass::SdkClientValidation
    );
    assert_eq!(failure.http_status, Some(400));
    assert_eq!(failure.stage.as_deref(), Some("agentic-sast:review"));
    assert_eq!(failure.model_call_id.as_deref(), Some(call_id.as_str()));
    assert_eq!(
        failure.detail.as_deref(),
        Some("temperature is incompatible with adaptive thinking; omit the pinned temperature")
    );
}

#[test]
fn mcp_unavailable_failure_records_exact_zero_provider_cost() {
    use crate::runtime::{RuntimeFailure, RuntimeFailureClass, RuntimeFailureMetadata};
    let target = tempfile::tempdir().unwrap();
    let failure = RuntimeFailure::new(RuntimeFailureMetadata::new(
        RuntimeFailureClass::McpUnavailable,
        None,
        None,
    ));
    let runtime = runtime_with(Err(anyhow::Error::new(failure)));

    let _ = traced(&runtime, target.path(), "mcp-unavailable")
        .query_blocking(AgentQueryRequest::new(
            "openai:gpt-test",
            ".",
            "system",
            "prompt",
        ))
        .unwrap_err();

    let read = crate::run_lifecycle::read_run_items(target.path(), "mcp-unavailable")
        .unwrap()
        .unwrap();
    let (cost, failure) = read
        .items
        .iter()
        .find_map(|item| match &item.item {
            RunItemV1::ModelCallFinished {
                cost,
                failure: Some(failure),
                ..
            } => Some((*cost, failure)),
            _ => None,
        })
        .unwrap();
    assert_eq!(cost.exact_usd(), Some(0.0));
    assert_eq!(failure.error_class, RuntimeFailureClass::McpUnavailable);
}

#[test]
fn next_step_records_typed_model_calls_and_safe_agent_actions() {
    let target = tempfile::tempdir().unwrap();
    let runtime = runtime_with(Ok(AgentQueryResponse::default()));
    let traced = traced(&runtime, target.path(), "typed-tool-loop");
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
    drop(traced);

    let read = crate::run_lifecycle::read_run_items(target.path(), "typed-tool-loop")
        .unwrap()
        .unwrap();
    assert_eq!(
        read.items
            .iter()
            .filter(|item| matches!(item.item, RunItemV1::ModelCallStarted { .. }))
            .count(),
        3
    );
    assert_eq!(
        read.items
            .iter()
            .filter(|item| matches!(item.item, RunItemV1::ModelCallFinished { .. }))
            .count(),
        3
    );
    let notices = read
        .items
        .iter()
        .filter_map(|item| match &item.item {
            RunItemV1::DiagnosticNotice { message, .. } => Some(message.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(notices
        .iter()
        .any(|message| message.contains("agent-action:")));
    assert!(notices
        .iter()
        .any(|message| message.contains("model completed")));
    assert!(notices
        .iter()
        .all(|message| !message.contains("src/lib.rs")));
}

fn traced_runtime<'a>(
    runtime: &'a dyn AgentRuntime,
    target: &std::path::Path,
    run_id: &str,
) -> TracedRuntime<'a> {
    let observation = RunObservationHandle::jsonl(target, run_id).unwrap();
    TracedRuntime::new(runtime, observation.trace_handle().for_module("triage"))
}

fn run_item_stream(target: &std::path::Path, run_id: &str) -> String {
    std::fs::read_to_string(crate::run_artifacts::run_artifact_path(
        target,
        run_id,
        "items.jsonl",
    ))
    .unwrap()
}
