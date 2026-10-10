use super::*;
use crate::capabilities::campaign::load_context_study;
use crate::run_artifacts::*;

fn plan(fixture: &Fixture) -> crate::capabilities::campaign::ContextStudyReceipt {
    let mut input = fixture.input();
    input.as_object_mut().unwrap().remove("allowanceRef");
    fixture
        .dispatch(
            "campaign:context-study",
            json!({
                "campaignId":"regeneration-draft","investigationId":"regeneration",
                "generationTool":"threat-model:regenerate","contextInput":input
            }),
            None,
            false,
        )
        .unwrap();
    load_context_study(fixture.root.path(), "regeneration-draft").unwrap()
}

fn approve(fixture: &Fixture, receipt: &crate::capabilities::campaign::ContextStudyReceipt) {
    fixture.dispatch("campaign:approve-allowance", json!({
        "investigationId":"regeneration","expectedRevision":1,"model":"openai-codex:gpt-5.5",
        "maxProviderCalls":2,"protectedReviewCalls":1,"reason":"Approve one offline context edit job",
        "campaignId":receipt.campaign_id,"campaignPlanSha256":receipt.plan_sha256,
        "campaignJobs":1,"maxJobAttempts":1
    }), None, true).unwrap();
}

fn execute(
    fixture: &Fixture,
    tool: &str,
    run: &str,
    input: Value,
    runtime: Option<&dyn AgentRuntime>,
) -> Value {
    let record = ToolRunRecord::new(fixture.root.path(), run, "tool", tool);
    try_record_tool_run_started_with_reproducibility(
        record.clone(),
        &input,
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    let trace = TraceHandle::jsonl(fixture.root.path(), run);
    let mut ctx = fixture.context();
    ctx.trace = Some(&trace);
    let prepared = fixture
        .registry
        .prepare_dispatch_input(tool, input, &ctx, None)
        .unwrap();
    let observed = fixture
        .registry
        .dispatch_prepared_input_observed_with_runtime(prepared, &ctx, runtime)
        .unwrap();
    let output = observed.execution.unwrap();
    try_record_tool_run_complete_settled(
        record,
        &output,
        &trace.run_observation().unwrap(),
        observed.completion,
    )
    .unwrap();
    output
}

#[test]
fn fixed_regeneration_recovers_a_draft_and_requires_a_recorded_check_before_map() {
    let fixture = Fixture::new();
    let receipt = plan(&fixture);
    assert_eq!(receipt.job_count(), 1);
    assert!(receipt.preparation_jobs.is_empty());
    assert_eq!(receipt.input["threatModelRef"], json!(fixture.selected));
    assert_eq!(
        receipt.generated_context(fixture.root.path()).unwrap(),
        None
    );
    assert_eq!(
        receipt
            .load_allowance(fixture.root.path())
            .unwrap()
            .unwrap()
            .committed_calls,
        0
    );
    approve(&fixture, &receipt);
    let allowance = receipt
        .load_allowance(fixture.root.path())
        .unwrap()
        .unwrap();
    let input = receipt.bound_input(&allowance).unwrap();
    let runtime = OfflineRegenerationRuntime::new(response());
    let result = execute(
        &fixture,
        "threat-model:regenerate",
        "regeneration-completed",
        input,
        Some(&runtime),
    );
    assert_eq!(result["data"]["sourceCurrent"], true);
    let reference: ThreatModelRef =
        serde_json::from_value(result["data"]["modelRef"].clone()).unwrap();
    let path = fixture
        .root
        .path()
        .join(".kuzushi/v3/campaigns/regeneration-draft/queue.json");
    fs::write(
        path,
        serde_json::to_vec(
            &json!({"jobs":{"context-001":{"state":"completed","runId":"regeneration-completed"}}}),
        )
        .unwrap(),
    )
    .unwrap();
    let recovered = load_context_study(fixture.root.path(), "regeneration-draft").unwrap();
    assert_eq!(
        recovered.generated_context(fixture.root.path()).unwrap(),
        Some(reference.clone())
    );
    let error = fixture
        .dispatch(
            "campaign:context-map",
            json!({"campaignId":receipt.campaign_id,"expectedPlanSha256":receipt.plan_sha256}),
            None,
            false,
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("Check the exact revision"),
        "{error:#}"
    );
    assert_eq!(
        crate::workflow_attempts::load_phase_attempt_ledger(fixture.root.path())
            .unwrap()
            .attempts()
            .count(),
        0
    );
    let checked = execute(
        &fixture,
        "threat-model:verify",
        "regeneration-checked",
        json!({"threatModelRef":reference}),
        None,
    );
    let checked_reference: ThreatModelRef =
        serde_json::from_value(checked["data"]["modelRef"].clone()).unwrap();
    assert_ne!(checked_reference, reference);
    let map = fixture
        .dispatch(
            "campaign:context-map",
            json!({"threatModelRef":checked_reference}),
            None,
            false,
        )
        .unwrap();
    assert_eq!(map["ok"], true);
    let ledger = crate::workflow_attempts::load_phase_attempt_ledger(fixture.root.path()).unwrap();
    let attempt = ledger.attempts().next().unwrap();
    assert!(attempt.disposition.is_none());
    let context = crate::workflow_attempts::load_map_run_context(
        fixture.root.path(),
        &attempt.completed.run_refs,
    )
    .unwrap()
    .unwrap();
    assert_eq!(context.model_ref, Some(checked_reference.clone()));
    crate::workflow_attempts::append_phase_attempt_disposition(
        fixture.root.path(),
        crate::workflow_attempts::PhaseAttemptDispositionRecorded::new(
            map["data"]["attemptId"].as_str().unwrap(),
            crate::workflow_attempts::PhaseAttemptDisposition::Selected {
                acknowledged_partial: false,
            },
        ),
    )
    .unwrap();
    let accepted = crate::capabilities::campaign::load_accepted_map_allowance(fixture.root.path())
        .unwrap()
        .expect("Checked regeneration must retain its investigation accounting");
    assert_eq!(accepted.investigation_id, "regeneration");
    assert_eq!(accepted.committed_calls, 1);
    assert_eq!(accepted.limits.protected_review_calls, 1);
    let next = fixture.dispatch("campaign:study", json!({"campaignId":"after-regeneration", "scanInput":{"taskMode":"manual","tasks":["secret-scan"]}}), None, false).unwrap();
    assert_eq!(next["data"]["investigationId"], "regeneration");
    assert_eq!(
        next["data"]["scanInput"]["threatModelRef"],
        json!(checked_reference)
    );
    assert_eq!(
        load_threat_model_manifest(fixture.root.path())
            .unwrap()
            .unwrap()
            .active,
        Some(fixture.active)
    );
    let remaining = recovered
        .load_allowance(fixture.root.path())
        .unwrap()
        .unwrap();
    assert_eq!(remaining.committed_calls, 1);
    assert_eq!(remaining.unresolved_calls, 0);
    assert_eq!(remaining.limits.protected_review_calls, 1);
    assert!(!remaining.cost.is_complete());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn protected_review_and_cancellation_prevent_an_additional_provider_attempt() {
    let fixture = Fixture::new();
    let runtime = OfflineRegenerationRuntime::new(response());
    fixture
        .dispatch(
            "threat-model:regenerate",
            fixture.input(),
            Some(&runtime),
            false,
        )
        .unwrap();
    let before = fs::read(threat_model_manifest_path(fixture.root.path())).unwrap();
    let mut input = fixture.input();
    input["allowanceRef"]["workId"] = json!("unapproved-follow-up");
    assert!(fixture
        .dispatch("threat-model:regenerate", input, Some(&runtime), false)
        .is_err());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(
        fs::read(threat_model_manifest_path(fixture.root.path())).unwrap(),
        before
    );
    let cancellation = crate::ScanCancellation::default();
    cancellation.cancel();
    let mut ctx = fixture.context();
    ctx.cancellation = Some(&cancellation);
    let prepared = fixture
        .registry
        .prepare_dispatch_input("threat-model:regenerate", fixture.input(), &ctx, None)
        .unwrap();
    assert!(fixture
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
        .is_err());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
}
