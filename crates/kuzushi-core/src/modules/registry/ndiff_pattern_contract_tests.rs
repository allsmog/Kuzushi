mod support;
use serde_json::json;
use support::*;

#[test]
fn advisory_draft_is_auxiliary_learning_and_keeps_external_authorization() {
    let registry = crate::ModuleRegistry::with_v2_builtins();
    let tool = registry.resolve_tool("ndiff:extract-fix-pattern").unwrap();
    assert_eq!(tool.phase, crate::modules::ToolPhase::Map);
    assert_eq!(tool.effect, crate::modules::ToolEffect::ExternalAction);
    assert_eq!(
        tool.discovery_maturity,
        Some(crate::modules::ModuleMaturity::Labs)
    );
    assert_eq!(
        tool.allowance_category,
        Some(crate::modules::AllowanceCategory::Learning)
    );
    assert!(!tool.phase_result);
    assert!(!registry.tool_is_discoverable(&tool.name));
    let module = registry
        .all_modules()
        .find(|module| module.metadata().id == "ndiff")
        .unwrap();
    assert_eq!(module.maturity(), crate::modules::ModuleMaturity::Labs);
    let fixture = Fixture::new(2);
    assert!(fixture
        .dispatch_tool(&tool.name, json!({"patchText":"Owned inert diff"}), false)
        .is_err());
    assert!(fixture.runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn declared_limits_fail_before_a_request_and_scope_is_unsupported() {
    let fixture = Fixture::new(2);
    for input in [
        json!({"maxPatchBytes":0}),
        json!({"maxSourceBytes":255}),
        json!({"maxContextBytes":524289}),
        json!({"maxOutputTokens":0}),
        json!({"maxModelTurns":5}),
        json!({"thinkingLevel":"unknown"}),
        json!({"scanContextRef":{}}),
    ] {
        assert!(fixture.dispatch(input).is_err());
    }
    assert!(fixture.runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn a_supplied_file_is_consumed_with_no_source_tools_and_an_unaccepted_receipt() {
    let fixture = Fixture::new(2);
    let result = fixture
        .dispatch(json!({"patch_path":"owned.diff","offline":true}))
        .unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["sourceReceipt"]["kind"], "supplied-file");
    assert_eq!(result["data"]["sourceReceipt"]["complete"], true);
    assert_eq!(result["data"]["accepted"], false);
    assert_eq!(result["data"]["contextActivated"], false);
    let requests = fixture.runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].prompt.contains("Owned changed greeting"));
    assert_eq!(requests[0].thinking_level, None);
    assert_eq!(requests[0].max_output_tokens, Some(4096));
    assert_eq!(
        requests[0]
            .runtime_options
            .as_ref()
            .unwrap()
            .max_model_turns,
        Some(1)
    );
    let policy = &requests[0].tool_policy;
    assert!(policy.tools.is_empty());
    assert!(!policy.mcps);
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}

#[test]
fn unicode_excerpting_discloses_exact_omissions_and_hashes_the_full_input() {
    let fixture = Fixture::new(2);
    let text = format!("{}界owned tail", "x".repeat(17999));
    let result = fixture.dispatch(json!({"patchText":text})).unwrap();
    let receipt = &result["data"]["sourceReceipt"];
    assert_eq!(result["status"], "partial");
    assert_eq!(receipt["includedBytes"], 17999);
    assert_eq!(receipt["omittedBytes"], text.len() - 17999);
    assert_eq!(
        receipt["digest"],
        "sha256:b45a7d80ce230f38c90df812ec81072a711acd959e8d360ed4d3bb48222c8128"
    );
    assert!(!fixture.runtime.requests.lock().unwrap()[0]
        .prompt
        .contains("owned tail"));
}

#[test]
fn source_and_metadata_bounds_reject_before_any_model_work() {
    let fixture = Fixture::new(2);
    let result = fixture
        .dispatch(json!({"patchText":"too many bytes","maxPatchBytes":2}))
        .unwrap();
    assert_eq!(result["status"], "failed");
    let result=fixture.dispatch(json!({"patchText":"Owned diff","record":{"id":"OWNED","source":"supplied","description":"x".repeat(1000),"cwes":[],"affected":[],"patches":[],"raw":{}},"maxMetadataBytes":64})).unwrap();
    assert_eq!(result["status"], "failed");
    assert!(fixture
        .dispatch(json!({"patchText":"x".repeat(1800),"maxContextBytes":1024}))
        .is_err());
    assert!(fixture.runtime.requests.lock().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn supplied_files_cannot_escape_the_target_or_follow_a_symlink() {
    let fixture = Fixture::new(2);
    let outside = tempfile::tempdir().unwrap();
    let file = outside.path().join("owned.diff");
    std::fs::write(&file, "Owned outside text").unwrap();
    std::os::unix::fs::symlink(&file, fixture.workspace.root().join("alias.diff")).unwrap();
    for path in [file.to_string_lossy().into_owned(), "alias.diff".into()] {
        assert!(fixture
            .dispatch(json!({"patchPath":path,"offline":true}))
            .is_err());
    }
    assert!(fixture.runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn learning_cannot_spend_protected_review_or_start_without_an_allowance() {
    let fixture = Fixture::new(1);
    assert!(fixture.dispatch(json!({"patchText":"Owned diff"})).is_err());
    assert!(fixture.runtime.requests.lock().unwrap().is_empty());
    let fixture = Fixture::new(2);
    let registry = crate::ModuleRegistry::with_v2_builtins();
    let ctx = fixture.context();
    let prepared = registry
        .prepare_dispatch_input(
            "ndiff:extract-fix-pattern",
            json!({"patchText":"Owned diff"}),
            &ctx,
            None,
        )
        .unwrap()
        .authorize_explicit_headless();
    assert!(registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&fixture.runtime))
        .is_err());
    assert!(fixture.runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn malformed_output_repair_keeps_the_model_reasoning_and_limits() {
    let mut fixture = Fixture::new(3);
    fixture.runtime.response = json!({});
    assert!(fixture.dispatch(json!({"patchText":"Owned diff","thinking_level":"low","max_output_tokens":512,"max_model_turns":1})).is_err());
    let requests = fixture.runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|r| r.model == "openai:gpt-5.5"
        && r.thinking_level.as_deref() == Some("low")
        && r.max_output_tokens == Some(512)
        && r.runtime_options.as_ref().unwrap().max_model_turns == Some(1)
        && r.tool_policy.tools.is_empty()));
}

#[test]
fn cancellation_after_response_prevents_draft_publication() {
    let mut fixture = Fixture::new(2);
    fixture.runtime.cancel = Some(fixture.cancel.clone());
    assert!(fixture.dispatch(json!({"patchText":"Owned diff"})).is_err());
    assert_eq!(fixture.runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn an_explicit_follow_up_consumes_the_draft_without_automatic_jobs() {
    let fixture = Fixture::new(3);
    let draft = fixture.dispatch(json!({"patchText":"Owned diff"})).unwrap();
    assert_eq!(fixture.runtime.requests.lock().unwrap().len(), 1);
    let result=fixture.dispatch_tool("ndiff:hunt-variants",json!({"pattern":draft["data"]["pattern"],"advisoryId":"OWNED","allowanceRef":{"schemaVersion":1,"investigationId":"owned-advisory-pattern","revision":1,"workId":"explicit-follow-up"}}),true).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(fixture.runtime.requests.lock().unwrap().len(), 2);
    assert_eq!(result["data"]["patternAccepted"], false);
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}
