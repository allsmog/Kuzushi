mod support;
use serde_json::json;
use support::*;

#[test]
fn advisory_search_is_experimental_auxiliary_scan_with_declared_limits() {
    let registry = crate::ModuleRegistry::with_v2_builtins();
    let tool = registry.resolve_tool("ndiff:hunt-variants").unwrap();
    assert_eq!(tool.phase, crate::modules::ToolPhase::Scan);
    assert_eq!(
        tool.discovery_maturity,
        Some(crate::modules::ModuleMaturity::Labs)
    );
    assert!(!tool.phase_result);
    assert!(!registry.tool_is_discoverable(&tool.name));
    for input in [
        json!({}),
        json!({"pattern":pattern(),"maxFindings":101}),
        json!({"pattern":pattern(),"maxOutputTokens":0}),
        json!({"pattern":pattern(),"maxModelTurns":17}),
        json!({"pattern":pattern(),"thinkingLevel":"unknown"}),
        json!({"pattern":pattern(),"scanContextRef":{}}),
    ] {
        let result = registry.prepare_tool_input(&tool.name, input.clone(), None);
        assert!(result.is_err());
    }
}

#[test]
fn prepared_empty_result_is_partial_source_bound_and_inherits_reasoning() {
    let fixture = Fixture::new(2);
    let result = fixture.dispatch(json!({})).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["coverage"]["complete"], false);
    assert_eq!(result["data"]["observationsVerified"], false);
    assert_eq!(result["data"]["patternAccepted"], false);
    assert!(result["data"]["treeHash"].as_str().unwrap().len() > 20);
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
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}

#[test]
fn declared_aliases_reach_the_actual_request_without_fallback() {
    let fixture = Fixture::new(2);
    fixture.dispatch(json!({"thinking_level":"low","max_output_tokens":512,"max_model_turns":2,"include_vendored":false})).unwrap();
    let requests = fixture.runtime.requests.lock().unwrap();
    let request = &requests[0];
    assert_eq!(request.model, "openai:gpt-5.5");
    assert_eq!(request.thinking_level.as_deref(), Some("low"));
    assert_eq!(request.max_output_tokens, Some(512));
    assert_eq!(
        request.runtime_options.as_ref().unwrap().max_model_turns,
        Some(2)
    );
    assert!(request.prompt.contains("Restrict search to first-party"));
}

#[test]
fn malformed_patterns_fail_before_any_query() {
    let fixture = Fixture::new(2);
    for input in [
        json!({"pattern":{}}),
        json!({"pattern":{"fixShape":"owned","vulnerableShape":" "}}),
    ] {
        assert!(fixture.dispatch(input).is_err());
    }
    assert!(fixture.runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn advisory_search_cannot_spend_protected_review() {
    let fixture = Fixture::new(1);
    assert!(fixture.dispatch(json!({})).is_err());
    assert!(fixture.runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn canceled_response_does_not_publish_observations() {
    let mut fixture = Fixture::new(2);
    fixture.runtime.cancel = Some(fixture.cancel.clone());
    fixture.runtime.response = json!({"variants":[{"filePath":"hello.txt","startLine":1,"severity":"INFO","confidence":"MEDIUM","message":"Labeled greeting observation; no defect claimed"}]});
    assert!(fixture.dispatch(json!({})).is_err());
    assert_eq!(fixture.runtime.requests.lock().unwrap().len(), 1);
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}

#[test]
fn malformed_output_cannot_become_an_empty_clean_result() {
    let mut fixture = Fixture::new(3);
    fixture.runtime.response = json!({});
    assert!(fixture.dispatch(json!({})).is_err());
    let requests = fixture.runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|request| request.max_output_tokens == Some(4096)
            && request.thinking_level.is_none()
            && request.runtime_options.as_ref().unwrap().max_model_turns == Some(4)));
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}

#[test]
fn supplied_pattern_creates_unreviewed_observations_without_accepting_a_lesson() {
    let mut fixture = Fixture::new(2);
    fixture.runtime.response = json!({"variants":[{"filePath":"hello.txt","startLine":1,"severity":"INFO","confidence":"MEDIUM","message":"Labeled owned greeting observation; no defect claimed"}]});
    let result = fixture.dispatch(json!({})).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["findings"].as_array().unwrap().len(), 1);
    let finding = &fixture.store.list_all_findings().unwrap()[0];
    assert!(finding.triage.is_none());
    assert!(finding.static_proof_state.is_none());
    assert_eq!(result["data"]["patternAccepted"], false);
}

#[test]
fn source_changes_keep_the_original_receipt_and_disclose_stale_observations() {
    let mut fixture = Fixture::new(2);
    fixture.runtime.change_source = Some(fixture.workspace.root().join("hello.txt"));
    let result = fixture.dispatch(json!({})).unwrap();
    assert_eq!(result["status"], "partial");
    assert!(result["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning
            .as_str()
            .is_some_and(|text| text.contains("source changed during execution"))));
    assert_eq!(result["data"]["coverage"]["complete"], false);
    assert_eq!(fixture.runtime.requests.lock().unwrap().len(), 1);
}
