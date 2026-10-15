mod support;
use serde_json::json;
use support::*;

#[test]
fn actor_discovery_is_experimental_and_cannot_publish_a_scan_checkpoint() {
    let registry = crate::ModuleRegistry::with_v2_builtins();
    let tool = registry.resolve_tool("offense-review:threat-hunt").unwrap();
    assert_eq!(
        tool.discovery_maturity,
        Some(crate::modules::ModuleMaturity::Labs)
    );
    assert!(!tool.phase_result);
    assert!(
        !registry
            .resolve_tool("carlini-threat-hunt:run")
            .unwrap()
            .phase_result
    );
    for input in [
        json!({"maxActors":9}),
        json!({"runsPerActor":4}),
        json!({"maxOutputTokens":0}),
        json!({"maxModelTurns":17}),
        json!({"thinkingLevel":"unknown"}),
        json!({"scanContextRef":{}}),
    ] {
        assert!(registry
            .prepare_tool_input(&tool.name, input, None)
            .is_err());
    }
}

#[test]
fn prepared_actor_query_inherits_reasoning_and_keeps_declared_request_bounds() {
    let fixture = Fixture::new(2);
    let output = fixture.dispatch(json!({})).unwrap();
    assert_eq!(output["status"], "partial");
    assert_eq!(output["data"]["coverage"]["complete"], false);
    assert_eq!(output["data"]["observationsVerified"], false);
    assert_eq!(output["data"]["count"], 0);
    let requests = fixture.runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].thinking_level, None);
    assert_eq!(requests[0].max_output_tokens, Some(4096));
    assert_eq!(
        requests[0]
            .runtime_options
            .as_ref()
            .unwrap()
            .max_model_turns,
        Some(4)
    );
}

#[test]
fn truncation_retry_keeps_the_approved_limits_and_uses_another_reservation() {
    let mut fixture = Fixture::new(3);
    fixture.runtime.truncated_first = true;
    assert_eq!(fixture.dispatch(json!({})).unwrap()["status"], "partial");
    let requests = fixture.runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.max_output_tokens == Some(4096)
                && request.thinking_level.is_none())
    );
}

#[test]
fn actor_discovery_cannot_borrow_protected_review() {
    let fixture = Fixture::new(1);
    assert!(fixture.dispatch(json!({})).is_err());
    assert!(fixture.runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn cancellation_after_response_prevents_publication() {
    let mut fixture = Fixture::new(2);
    fixture.runtime.canceled_response = Some(fixture.cancel.clone());
    assert!(fixture.dispatch(json!({})).is_err());
    assert_eq!(fixture.runtime.requests.lock().unwrap().len(), 1);
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}
