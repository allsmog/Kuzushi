use super::*;

#[test]
fn canceled_evidence_selection_cannot_use_the_saved_inventory() {
    let fixture = Fixture::new();
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    let mut ctx = fixture.context();
    ctx.cancellation = Some(&cancellation);
    let error =
        selection::files::require_inventory_membership(&["app/one.rs".into()], &ctx).unwrap_err();
    assert!(error.to_string().contains("canceled"));
    assert!(!fixture.root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn evidence_inventory_metadata_must_match_before_allowance_approval() {
    let fixture = Fixture::new();
    let original = plan(&fixture, json!(["app/one.rs"])).unwrap();
    let path = fixture
        .root
        .path()
        .join(".kuzushi/v3/campaigns/evidence-context/plan.json");
    let mut stored: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    stored["sourceInventory"]["enumeratedFiles"] = json!(0);
    std::fs::write(&path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();
    let edited =
        crate::capabilities::campaign::load_context_study(fixture.root.path(), "evidence-context")
            .unwrap();
    assert_ne!(edited.plan_sha256, original.plan_sha256);
    let result = fixture.dispatch("campaign:approve-allowance", json!({
        "investigationId":"group-test","expectedRevision":0,"model":edited.model,
        "maxProviderCalls":3,"protectedReviewCalls":1,"reason":"Owned inventory binding regression",
        "campaignId":edited.campaign_id,"campaignPlanSha256":edited.plan_sha256,
        "campaignJobs":1,"maxJobAttempts":1
    }), None, true);
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("inventory changed"));
    assert!(edited
        .load_allowance(fixture.root.path())
        .unwrap()
        .is_none());
}

fn create(fixture: &Fixture) -> Value {
    let receipt = plan(fixture, json!(["app/one.rs"])).unwrap();
    fixture
        .dispatch(
            "threat-model:build",
            fixture.approve(&receipt),
            Some(&OfflineRuntime::new(document())),
            true,
        )
        .unwrap()
}

#[test]
fn evidence_context_cannot_widen_its_parent_file_membership() {
    let fixture = Fixture::new();
    let result = create(&fixture);
    let input = json!({"campaignId":"wider","investigationId":"group-test","contextInput":{
        "sourcePaths":["other/other.rs"],"inheritedContextRef":result["data"]["modelRef"]}});
    assert!(fixture
        .dispatch("campaign:context-study", input, None, false)
        .is_err());
}

#[test]
fn later_text_regeneration_reuses_exact_evidence_files_without_widening() {
    let mut fixture = Fixture::new();
    let created = create(&fixture);
    let planned=fixture.dispatch("campaign:context-study",json!({"campaignId":"evidence-text","investigationId":"group-test",
        "generationTool":"threat-model:regenerate","contextInput":{"threatModelRef":created["data"]["modelRef"],"fields":["/dfd/nodes/0/purpose"]}}),None,false).unwrap();
    let receipt: crate::capabilities::campaign::ContextStudyReceipt =
        serde_json::from_value(planned["data"].clone()).unwrap();
    fixture.dispatch("campaign:approve-allowance",json!({"investigationId":"group-test","expectedRevision":1,"model":receipt.model,
        "maxProviderCalls":3,"protectedReviewCalls":1,"reason":"Additional offline text request","campaignId":receipt.campaign_id,
        "campaignPlanSha256":receipt.plan_sha256,"campaignJobs":1,"maxJobAttempts":1}),None,true).unwrap();
    let input = receipt
        .bound_input(
            &receipt
                .load_allowance(fixture.root.path())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    let runtime = OfflineRuntime::new(
        json!({"schemaVersion":1,"edits":[{"pointer":"/dfd/nodes/0/purpose","text":"Reviewed exact-file explanation"}]}),
    );
    fixture.trace =
        crate::run_artifacts::TraceHandle::jsonl(fixture.root.path(), "evidence-text-run");
    let revised = fixture
        .dispatch("threat-model:regenerate", input, Some(&runtime), false)
        .unwrap();
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let prompt: Value = serde_json::from_str(&requests[0].prompt).unwrap();
    let source = serde_json::to_string(&prompt["source"]).unwrap();
    assert!(source.contains("OWNED_APP"));
    for marker in [
        "OWNED_ADAPTER",
        "OWNED_SHARED",
        "UNSELECTED_SIBLING",
        "UNSELECTED_ROOT",
    ] {
        assert!(!source.contains(marker));
    }
    assert_eq!(
        revised["data"]["document"]["dfd"],
        json!({"nodes":[{"id":"app","name":"Owned component","purpose":"Reviewed exact-file explanation","type":"process","trustZone":"internal","sourceRefs":["app/one.rs:1"]}],"flows":[],"trustBoundaries":[]})
    );
    assert_eq!(
        revised["data"]["document"]["provenance"]["fileContext"],
        created["data"]["document"]["provenance"]["fileContext"]
    );
    assert_eq!(
        revised["data"]["regeneration"]["sourceInventory"],
        created["data"]["fileContext"]["inventory"]
    );
}

fn plan(
    fixture: &Fixture,
    paths: Value,
) -> Result<crate::capabilities::campaign::ContextStudyReceipt> {
    let output = fixture.dispatch("campaign:context-study", json!({"campaignId":"evidence-context","investigationId":"group-test",
        "contextInput":{"sourcePaths":paths,"inheritedContextRef":fixture.active,"maxSourceBytes":8192}}),None,false)?;
    Ok(serde_json::from_value(output["data"].clone())?)
}

#[test]
fn exact_evidence_context_uses_one_approved_call_and_stays_inactive() {
    let fixture = Fixture::new();
    let receipt = plan(&fixture, json!(["app/one.rs"])).unwrap();
    let inventory = receipt.source_inventory.as_ref().unwrap();
    assert_eq!(inventory["enumerationComplete"], true);
    let original =
        crate::workspace::load_scan_scope_proposal(&fixture.workspace, &fixture.scope.proposal)
            .unwrap();
    assert_eq!(inventory["inventoryHash"], original.record.inventory_hash);
    assert_eq!(
        crate::capabilities::campaign::load_context_study(
            fixture.root.path(),
            &receipt.campaign_id
        )
        .unwrap()
        .source_inventory,
        receipt.source_inventory
    );
    assert_eq!(receipt.job_count(), 1);
    assert!(receipt.preparation_jobs.is_empty());
    assert!(receipt
        .load_allowance(fixture.root.path())
        .unwrap()
        .is_none());
    let input = fixture.approve(&receipt);
    let runtime = OfflineRuntime::new(document());
    let result = fixture
        .dispatch("threat-model:build", input, Some(&runtime), true)
        .unwrap();
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let prompt: Value = serde_json::from_str(&requests[0].prompt).unwrap();
    let source = serde_json::to_string(&prompt["source"]).unwrap();
    assert_eq!(prompt["sourceInventory"]["selectedMembershipKnown"], true);
    assert!(source.contains("OWNED_APP"));
    for marker in [
        "OWNED_ADAPTER",
        "OWNED_SHARED",
        "UNSELECTED_ROOT",
        "UNSELECTED_SIBLING",
    ] {
        assert!(!source.contains(marker));
    }
    assert!(requests[0].tool_policy.tools.is_empty());
    assert_eq!(
        requests[0]
            .runtime_options
            .as_ref()
            .unwrap()
            .max_model_turns,
        Some(1)
    );
    let origin = &result["data"]["document"]["provenance"]["fileContext"]["receipt"];
    assert_eq!(origin["sourcePaths"], json!(["app/one.rs"]));
    assert_eq!(origin["completeRepositoryCoverage"], false);
    assert_eq!(origin["inheritedContextRef"], json!(fixture.active));
    assert_eq!(origin["inventory"]["selectedMembershipKnown"], true);
    assert!(result["data"]["scopeContext"].is_null());
    assert_eq!(result["data"]["activated"], false);
    assert_eq!(
        load_active_threat_model(fixture.root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        fixture.active
    );
    let saved: ThreatModelRef = serde_json::from_value(result["data"]["modelRef"].clone()).unwrap();
    assert_eq!(
        load_exact_threat_model(fixture.root.path(), &saved).unwrap(),
        result["data"]["document"]
    );
}

#[test]
fn evidence_selection_refuses_invalid_missing_directory_and_duplicate_paths() {
    for paths in [
        json!([]),
        json!(["app"]),
        json!(["../app/one.rs"]),
        json!(["/app/one.rs"]),
        json!(["app/one.rs", "app/one.rs"]),
        json!(["missing.rs"]),
        json!(["./app/one.rs"]),
        json!(["app/one.rs/"]),
    ] {
        assert!(
            plan(&Fixture::new(), paths.clone()).is_err(),
            "accepted {paths}"
        );
    }
}

#[test]
fn literal_spaced_paths_are_kept_separate_from_unspaced_paths() {
    let fixture = Fixture::new();
    std::fs::create_dir(fixture.root.path().join(" app ")).unwrap();
    std::fs::write(fixture.root.path().join(" app /one.rs"), "// SPACED_ONLY\n").unwrap();
    // Refresh the source-bound context after adding this file.
    let imported = fixture
        .dispatch(
            "threat-model:import",
            json!({"document":document(),"activate":false}),
            None,
            false,
        )
        .unwrap();
    let result=fixture.dispatch("campaign:context-study",json!({"campaignId":"spaced-evidence","investigationId":"group-test",
        "contextInput":{"sourcePaths":[" app /one.rs"],"inheritedContextRef":imported["data"]["modelRef"],"maxSourceBytes":8192}}),None,false).unwrap();
    let receipt = serde_json::from_value(result["data"].clone()).unwrap();
    let mut reply = document();
    reply["dfd"]["nodes"][0]["sourceRefs"] = json!([" app /one.rs:1"]);
    let runtime = OfflineRuntime::new(reply);
    fixture
        .dispatch(
            "threat-model:build",
            fixture.approve(&receipt),
            Some(&runtime),
            true,
        )
        .unwrap();
    let requests = runtime.requests.lock().unwrap();
    assert!(requests[0].prompt.contains("SPACED_ONLY"));
    assert!(!requests[0].prompt.contains("OWNED_APP"));
}

#[test]
fn stale_inherited_source_and_conflicting_scope_fail_before_a_request() {
    let fixture = Fixture::new();
    let both=fixture.dispatch("campaign:context-study",json!({"campaignId":"both","investigationId":"group-test",
        "contextInput":{"sourcePaths":["app/one.rs"],"scanScopeRef":fixture.scope,"inheritedContextRef":fixture.active}}),None,false);
    assert!(both.is_err());
    std::fs::write(
        fixture.root.path().join("app/one.rs"),
        "// changed source\n",
    )
    .unwrap();
    assert!(plan(&fixture, json!(["app/one.rs"])).is_err());
}

#[cfg(unix)]
#[test]
fn symlink_evidence_is_not_inventory_membership() {
    let fixture = Fixture::new();
    std::os::unix::fs::symlink(
        fixture.root.path().join("app/one.rs"),
        fixture.root.path().join("alias.rs"),
    )
    .unwrap();
    assert!(plan(&fixture, json!(["alias.rs"])).is_err());
}

#[test]
fn evidence_context_disallows_extra_preparation_jobs() {
    let fixture = Fixture::new();
    assert!(fixture.dispatch("campaign:context-study",json!({"campaignId":"extra-evidence","investigationId":"group-test",
        "contextInput":{"sourcePaths":["app/one.rs"],"inheritedContextRef":fixture.active},"preparationJobs":[{"tool":"context:build","input":{}}]}),None,false).is_err());
}
