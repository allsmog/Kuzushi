mod support;
use serde_json::json;
use support::*;

#[test]
fn advisory_research_and_harvest_are_experimental_auxiliary_learning() {
    let registry = crate::ModuleRegistry::with_v2_builtins();
    for name in ["threat-intel:research", "threat-intel:harvest"] {
        let tool = registry.resolve_tool(name).unwrap();
        assert_eq!(
            tool.discovery_maturity,
            Some(crate::modules::ModuleMaturity::Labs)
        );
        assert_eq!(
            tool.allowance_category,
            Some(crate::modules::AllowanceCategory::Learning)
        );
        assert!(!tool.phase_result);
        assert!(!registry.tool_is_discoverable(name));
        for extra in [
            json!({"maxCves":33}),
            json!({"maxOutputTokens":0}),
            json!({"maxModelTurns":5}),
            json!({"thinkingLevel":"unknown"}),
            json!({"scanContextRef":{}}),
        ] {
            assert!(registry.prepare_tool_input(name, extra, None).is_err());
        }
    }
}

#[test]
fn a_real_nested_extraction_shares_the_parent_allowance_and_retains_its_receipt() {
    let fixture = Fixture::new(2);
    let result = fixture
        .dispatch(
            "threat-intel:harvest",
            json!({"thinking_level":"low","max_output_tokens":512}),
        )
        .unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["summary"]["harvested"], 1);
    assert_eq!(result["data"]["accepted"], false);
    let row = &result["data"]["perCve"][0];
    assert_eq!(row["extractionReceipt"]["data"]["accepted"], false);
    assert_eq!(
        row["extractionReceipt"]["data"]["sourceReceipt"]["complete"],
        true
    );
    let requests = fixture.runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].thinking_level.as_deref(), Some("low"));
    assert_eq!(requests[0].max_output_tokens, Some(512));
    assert!(requests[0].tool_policy.tools.is_empty());
    let catalog = std::fs::read_to_string(result["data"]["outputPath"].as_str().unwrap()).unwrap();
    assert!(catalog.contains("Unaccepted catalog draft"));
    assert!(catalog.contains("source claims unverified"));
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}

#[test]
fn budget_exhaustion_defers_remaining_advisories_before_another_model_request() {
    let fixture = Fixture::new(2);
    let result = fixture
        .dispatch(
            "threat-intel:harvest",
            json!({"cves":["OWNED-ONE","OWNED-TWO"]}),
        )
        .unwrap();
    assert_eq!(result["data"]["summary"]["harvested"], 1);
    assert_eq!(result["data"]["summary"]["deferred"], 1);
    assert_eq!(result["data"]["perCve"][1]["status"], "deferred");
    assert_eq!(fixture.runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn exact_duplicate_ids_do_not_duplicate_model_work() {
    let fixture = Fixture::new(2);
    let result = fixture
        .dispatch(
            "threat-intel:harvest",
            json!({"cves":["OWNED-ONE","owned-one"]}),
        )
        .unwrap();
    assert_eq!(result["data"]["summary"]["totalCves"], 1);
    assert_eq!(fixture.runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn missing_parent_allowance_and_protected_review_stop_before_model_work() {
    let fixture = Fixture::new(1);
    assert!(fixture.dispatch("threat-intel:harvest", json!({})).is_err());
    assert!(fixture.runtime.requests.lock().unwrap().is_empty());
    let fixture = Fixture::new(2);
    let registry = crate::ModuleRegistry::with_v2_builtins();
    let ctx = fixture.context();
    let mut input = fixture.input();
    input.as_object_mut().unwrap().remove("allowanceRef");
    let prepared = registry
        .prepare_dispatch_input("threat-intel:harvest", input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    assert!(registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&fixture.runtime))
        .is_err());
    assert!(fixture.runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn malformed_patterns_produce_failed_rows_and_no_complete_catalog_claim() {
    let mut fixture = Fixture::new(3);
    fixture.runtime.response = json!({});
    let result = fixture.dispatch("threat-intel:harvest", json!({})).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["summary"]["harvested"], 0);
    assert_eq!(result["data"]["summary"]["failed"], 1);
    assert_eq!(fixture.runtime.requests.lock().unwrap().len(), 2);
}

#[test]
fn offline_research_consumes_supplied_metadata_without_live_fallback() {
    let fixture = Fixture::new(2);
    let result=fixture.dispatch("threat-intel:research",json!({"osvFixtures":{"owned-lib":[{"id":"OWNED-ONE","summary":"Labeled owned advisory"}]}})).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["cveCount"], 1);
    assert_eq!(result["data"]["harvest"]["data"]["summary"]["harvested"], 1);
    assert_eq!(result["data"]["sourceVerified"], false);
    assert_eq!(fixture.runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn missing_offline_responses_remain_failed_lookups_with_no_model_call() {
    let fixture = Fixture::new(2);
    let result = fixture
        .dispatch("threat-intel:research", json!({"osvFixtures":{}}))
        .unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["failedPackages"], json!(["owned-lib"]));
    assert_eq!(result["data"]["cveCount"], 0);
    assert!(fixture.runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn cancellation_retains_completed_drafts_and_defers_future_work() {
    let mut fixture = Fixture::new(3);
    fixture.runtime.cancellation = Some((fixture.cancel.clone(), 2));
    let result = fixture
        .dispatch(
            "threat-intel:harvest",
            json!({"cves":["OWNED-ONE","OWNED-TWO","OWNED-THREE"]}),
        )
        .unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["summary"]["harvested"], 1);
    assert_eq!(result["data"]["summary"]["failed"], 1);
    assert_eq!(result["data"]["summary"]["deferred"], 1);
    assert_eq!(fixture.runtime.requests.lock().unwrap().len(), 2);
    assert!(std::path::Path::new(result["data"]["outputPath"].as_str().unwrap()).exists());
}

#[test]
fn supplied_metadata_and_invalid_id_lists_fail_before_a_request() {
    let fixture = Fixture::new(2);
    for extra in [
        json!({"cves":vec!["OWNED-ONE";33]}),
        json!({"cves":["../outside"]}),
        json!({"maxMetadataBytes":1}),
    ] {
        assert!(fixture.dispatch("threat-intel:harvest", extra).is_err());
    }
    assert!(fixture.runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn explicit_parent_model_selection_reaches_each_nested_extraction() {
    let mut fixture = Fixture::new(2);
    fixture.config.model = Some("openai:other-config-model".into());
    let result = fixture
        .dispatch("threat-intel:harvest", json!({"model":"openai:gpt-5.5"}))
        .unwrap();
    assert_eq!(result["data"]["summary"]["harvested"], 1);
    assert_eq!(
        fixture.runtime.requests.lock().unwrap()[0].model,
        "openai:gpt-5.5"
    );
}
