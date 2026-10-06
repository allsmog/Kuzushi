use super::*;
use crate::capabilities::threat_model::{
    commit_threat_model_revision, load_active_threat_model, ScopeRef, ThreatModelCommit,
    ThreatModelRevisionSource,
};
use crate::run_artifacts::*;
use crate::workflow_attempts::*;

struct Fixture {
    config: V2Config,
    registry: ModuleRegistry,
    receipt: ContextStudyReceipt,
    generated: crate::ThreatModelRef,
}

fn generate(root: &Path) -> Fixture {
    std::fs::write(root.join("main.rs"), "fn main() { println!(\"hello\"); }\n").unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let workspace = WorkspaceTarget::new(root).unwrap();
    let ctx = context(&workspace, &config);
    draft(&registry, &ctx, json!({})).unwrap();
    let receipt = load_context_study(root, "context-draft").unwrap();
    approve(&registry, &ctx, approval(&receipt)).unwrap();
    let bound = receipt
        .bound_input(&receipt.load_allowance(root).unwrap().unwrap())
        .unwrap();
    let output = recorded_generation(root, &config, &registry, bound);
    let generated = serde_json::from_value(output["data"]["modelRef"].clone()).unwrap();
    write_json_atomic(
        &campaign_queue_path(root, &receipt.campaign_id),
        &json!({"jobs":{
            "context-001":{"state":"completed","runId":"context-result","attempts":1}
        }}),
    )
    .unwrap();
    Fixture {
        config,
        registry,
        receipt,
        generated,
    }
}

fn recorded_generation(
    root: &Path,
    config: &V2Config,
    registry: &ModuleRegistry,
    input: Value,
) -> Value {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let record = ToolRunRecord::new(root, "context-result", "tool", TOOL);
    try_record_tool_run_started_with_reproducibility(record, &input, None, None, Vec::new())
        .unwrap();
    let trace = TraceHandle::jsonl(root, "context-result");
    let mut ctx = context(&workspace, config);
    ctx.trace = Some(&trace);
    let prepared = registry
        .prepare_dispatch_input(TOOL, input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let runtime = super::execution::OfflineContextRuntime::default();
    let observed = registry
        .dispatch_prepared_input_observed_with_runtime(prepared, &ctx, Some(&runtime))
        .unwrap();
    let result = observed.execution.unwrap();
    try_record_tool_run_complete_settled(
        record,
        &result,
        &trace.run_observation().unwrap(),
        observed.completion,
    )
    .unwrap();
    result
}

impl Fixture {
    fn review(&self, root: &Path) -> Result<Value> {
        let workspace = WorkspaceTarget::new(root)?;
        self.registry.execute_tool(
            "campaign:context-map",
            json!({"campaignId":self.receipt.campaign_id,
            "expectedPlanSha256":self.receipt.plan_sha256}),
            &context(&workspace, &self.config),
        )
    }
}

#[test]
fn generated_map_reopens_without_duplicate_attempt_or_active_context_change() {
    let root = tempfile::tempdir().unwrap();
    let fixture = generate(root.path());
    let active = active_context(root.path());
    let first = fixture.review(root.path()).unwrap();
    let again = fixture.review(root.path()).unwrap();
    assert_eq!(first["data"], again["data"]);
    let ledger = load_phase_attempt_ledger(root.path()).unwrap();
    assert_eq!(ledger.attempts().count(), 1);
    let attempt = ledger.attempts().next().unwrap();
    assert!(attempt.disposition.is_none());
    assert_eq!(
        load_map_run_context(root.path(), &attempt.completed.run_refs)
            .unwrap()
            .unwrap()
            .model_ref,
        Some(fixture.generated)
    );
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        active
    );
    assert_eq!(
        fixture
            .receipt
            .load_allowance(root.path())
            .unwrap()
            .unwrap()
            .committed_calls,
        1
    );
}

fn accept(fixture: &Fixture, root: &Path) {
    let result = fixture.review(root).unwrap();
    append_phase_attempt_disposition(
        root,
        PhaseAttemptDispositionRecorded::new(
            result["data"]["attemptId"].as_str().unwrap(),
            PhaseAttemptDisposition::Selected {
                acknowledged_partial: false,
            },
        ),
    )
    .unwrap();
}

fn scan_draft(fixture: &Fixture, root: &Path, extra: Value) -> Result<Value> {
    let workspace = WorkspaceTarget::new(root)?;
    let mut input = json!({"campaignId":"scan-draft","scanInput":{"taskMode":"manual","tasks":["secret-scan"]}});
    input
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    fixture.registry.execute_tool(
        "campaign:study",
        input,
        &context(&workspace, &fixture.config),
    )
}

#[test]
fn accepted_generated_map_keeps_accounting_when_new_scan_work_is_approved_and_reopened() {
    let root = tempfile::tempdir().unwrap();
    let fixture = generate(root.path());
    let active = active_context(root.path());
    accept(&fixture, root.path());
    let before = crate::capabilities::campaign::load_accepted_map_allowance(root.path())
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            before.committed_calls,
            before.remaining_discovery_calls(),
            before.protected_review_remaining()
        ),
        (1, 2, 2)
    );
    let draft = scan_draft(&fixture, root.path(), json!({})).unwrap();
    let receipt: StudyPlanReceipt = serde_json::from_value(draft["data"].clone()).unwrap();
    assert_eq!(receipt.investigation_id.as_deref(), Some("investigation"));
    assert_eq!(receipt.job_count, 3);
    assert_eq!(
        receipt.scan_input["threatModelRef"],
        serde_json::to_value(&fixture.generated).unwrap()
    );
    assert_eq!(
        load_study_allowance(root.path(), &receipt)
            .unwrap()
            .unwrap(),
        before
    );
    assert_ne!(
        before.work_plan.as_ref().unwrap().campaign_id,
        receipt.campaign_id
    );
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut revised = approval(&fixture.receipt);
    revised["expectedRevision"] = json!(1);
    revised["campaignId"] = json!(receipt.campaign_id);
    revised["campaignPlanSha256"] = json!(receipt.plan_sha256);
    revised["campaignJobs"] = json!(receipt.job_count);
    let result = approve(
        &fixture.registry,
        &context(&workspace, &fixture.config),
        revised,
    )
    .unwrap();
    assert_eq!(result["data"]["allowance"]["committedCalls"], 1);
    assert_eq!(result["data"]["allowance"]["revision"], 2);
    let reopened = crate::capabilities::campaign::load_accepted_map_allowance(root.path())
        .unwrap()
        .unwrap();
    assert_eq!((reopened.committed_calls, reopened.revision), (1, 2));
    assert_eq!(reopened.work_plan.unwrap().campaign_id, "scan-draft");
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        active
    );
}

#[test]
fn explicit_scan_context_omission_keeps_accounting_and_explicit_investigation_is_respected() {
    let root = tempfile::tempdir().unwrap();
    let fixture = generate(root.path());
    accept(&fixture, root.path());
    let omitted = scan_draft(
        &fixture,
        root.path(),
        json!({"scanInput":{"taskMode":"manual","tasks":["secret-scan"],"threatModelRef":null}}),
    )
    .unwrap();
    assert_eq!(omitted["data"]["investigationId"], "investigation");
    assert!(omitted["data"]["scanInput"]["threatModelRef"].is_null());
    let explicit = scan_draft(
        &fixture,
        root.path(),
        json!({"campaignId":"separate-draft","investigationId":"separate"}),
    )
    .unwrap();
    assert_eq!(explicit["data"]["investigationId"], "separate");
    assert_eq!(
        fixture
            .receipt
            .load_allowance(root.path())
            .unwrap()
            .unwrap()
            .committed_calls,
        1
    );
}

#[test]
fn missing_accounting_and_source_drift_cannot_start_fresh_implicit_investigations() {
    let root = tempfile::tempdir().unwrap();
    let fixture = generate(root.path());
    accept(&fixture, root.path());
    let source = root.path().join("main.rs");
    let original = std::fs::read(&source).unwrap();
    std::fs::write(&source, "fn changed() {}\n").unwrap();
    let historical =
        crate::capabilities::campaign::load_selected_map_history_allowance(root.path())
            .unwrap()
            .unwrap();
    assert_eq!(
        (
            historical.investigation_id.as_str(),
            historical.committed_calls
        ),
        ("investigation", 1)
    );
    let changed = scan_draft(
        &fixture,
        root.path(),
        json!({"scanInput":{"taskMode":"manual","tasks":["secret-scan"],"threatModelRef":null}}),
    )
    .unwrap();
    assert_eq!(changed["data"]["investigationId"], "investigation");
    assert!(changed["data"]["scanInput"]["threatModelRef"].is_null());
    assert_eq!(historical.committed_calls, 1);
    std::fs::write(source, original).unwrap();
    let db = WorkspaceTarget::new(root.path())
        .unwrap()
        .findings_db_path();
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    connection
        .execute("delete from investigation_allowance_revisions", [])
        .unwrap();
    let error = scan_draft(
        &fixture,
        root.path(),
        json!({"campaignId":"missing-accounting-draft"}),
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("accounting is missing"),
        "{error:#}"
    );
    assert_eq!(
        connection
            .query_row(
                "select count(*) from investigation_allowance_revisions",
                [],
                |row| row.get::<_, u32>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "select count(*) from investigation_call_reservations",
                [],
                |row| row.get::<_, u32>(0)
            )
            .unwrap(),
        1
    );
    assert!(!campaign_plan_path(root.path(), "missing-accounting-draft").exists());
}

#[test]
fn generated_map_options_are_shared_required_and_do_not_create_an_extra_phase_result() {
    let root = tempfile::tempdir().unwrap();
    let fixture = generate(root.path());
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let ctx = context(&workspace, &fixture.config);
    for input in [
        json!({"campaignId":"context-draft"}),
        json!({"expectedPlanSha256":fixture.receipt.plan_sha256}),
        json!({"campaignId":"context-draft","expectedPlanSha256":fixture.receipt.plan_sha256,"recurse":true}),
    ] {
        assert!(fixture
            .registry
            .execute_tool("campaign:context-map", input, &ctx)
            .is_err());
    }
    let descriptor = fixture
        .registry
        .resolve_tool("campaign:context-map")
        .unwrap();
    assert!(crate::modules::phase_result_phase(descriptor).is_none());
    let error = fixture
        .registry
        .execute_tool(
            "campaign:context-map",
            json!({
                "campaignId":"context-draft","expectedPlanSha256":"changed"
            }),
            &ctx,
        )
        .unwrap_err();
    assert!(error.to_string().contains("plan changed"));
    assert_eq!(
        load_phase_attempt_ledger(root.path())
            .unwrap()
            .attempts()
            .count(),
        0
    );
}

#[test]
fn generated_map_recovers_an_interrupted_compatibility_append() {
    let root = tempfile::tempdir().unwrap();
    let fixture = generate(root.path());
    let first = fixture.review(root.path()).unwrap();
    std::fs::write(phase_attempt_ledger_path(root.path()), "").unwrap();
    let resumed = fixture.review(root.path()).unwrap();
    assert_eq!(first["data"]["attemptId"], resumed["data"]["attemptId"]);
    assert_eq!(
        load_phase_attempt_ledger(root.path())
            .unwrap()
            .attempts()
            .count(),
        1
    );
    assert_eq!(
        load_phase_attempt_ledger_v2(root.path())
            .unwrap()
            .attempts
            .len(),
        1
    );
}

#[test]
fn generated_map_rejects_changed_source_failed_job_and_tampered_result() {
    let root = tempfile::tempdir().unwrap();
    let fixture = generate(root.path());
    std::fs::write(root.path().join("later.rs"), "fn changed() {}\n").unwrap();
    assert!(fixture
        .review(root.path())
        .unwrap_err()
        .to_string()
        .contains("earlier source content"));
    std::fs::remove_file(root.path().join("later.rs")).unwrap();
    let path = campaign_queue_path(root.path(), "context-draft");
    let original = std::fs::read(&path).unwrap();
    write_json_atomic(
        &path,
        &json!({"jobs":{"context-001":{"state":"failed","runId":"context-result"}}}),
    )
    .unwrap();
    assert!(fixture
        .review(root.path())
        .unwrap_err()
        .to_string()
        .contains("is failed"));
    std::fs::write(path, original).unwrap();
    std::fs::write(
        crate::run_artifact_path(root.path(), "context-result", "result.json"),
        "{}",
    )
    .unwrap();
    assert!(format!("{:#}", fixture.review(root.path()).unwrap_err())
        .contains("cannot be authenticated"));
    assert_eq!(
        load_phase_attempt_ledger(root.path())
            .unwrap()
            .attempts()
            .count(),
        0
    );
}

#[test]
fn discarded_generated_map_is_not_recreated_by_review() {
    let root = tempfile::tempdir().unwrap();
    let fixture = generate(root.path());
    let result = fixture.review(root.path()).unwrap();
    append_phase_attempt_disposition(
        root.path(),
        PhaseAttemptDispositionRecorded::new(
            result["data"]["attemptId"].as_str().unwrap(),
            PhaseAttemptDisposition::Discarded,
        ),
    )
    .unwrap();
    assert!(fixture
        .review(root.path())
        .unwrap_err()
        .to_string()
        .contains("discarded"));
    assert_eq!(
        load_phase_attempt_ledger(root.path())
            .unwrap()
            .attempts()
            .count(),
        1
    );
}

fn active_context(root: &Path) -> crate::ThreatModelRef {
    commit_threat_model_revision(root, &json!({"version":"1","methodology":"stride","title":"Labeled other active context",
        "dfd":{"nodes":[{"id":"other","type":"process","name":"Other active context","trustZone":"internal"}],"flows":[],"trustBoundaries":[]},"summary":{},"threats":[]}),
        ThreatModelCommit { model_id:None,new_model:true,label:"Other active context".into(),
            scope:ScopeRef::legacy_root(root, &format!("sha256:{}", "1".repeat(64))),methodology:"stride".into(),
            source:ThreatModelRevisionSource::Import,source_revision_id:None,run_id:None,activate:Some(true),actor:"test".into() }).unwrap().model_ref
}

#[test]
#[ignore = "Explicit offline tmux fixture export, requires a target path"]
fn export_generated_map_tui_fixture() {
    let root = PathBuf::from(
        std::env::var_os("KUZUSHI_TEST_CONTEXT_MAP_TARGET").expect("explicit fixture target"),
    );
    assert!(
        root.join(".git").is_dir(),
        "fixture export requires the harness repository"
    );
    let fixture = generate(&root);
    let active = active_context(&root);
    write_json_atomic(&root.join(".kuzushi/v3/context-map-fixture.json"), &json!({
        "fixtureKind":"real source-only context generator with mocked provider; injected completed queue",
        "campaignId":fixture.receipt.campaign_id,"investigationId":fixture.receipt.investigation_id,
        "generated":fixture.generated,"active":active,"mockProviderCalls":1,"liveProviderCalls":0,
    })).unwrap();
}
