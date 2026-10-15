use super::*;
use crate::{ModuleRegistry, V2Config, WorkspaceTarget};

struct Fixture {
    root: tempfile::TempDir,
    config: V2Config,
    workspace: WorkspaceTarget,
    registry: ModuleRegistry,
    references: Vec<Value>,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("main.rs"),
            "// Owned fixture, never executed\nfn main() {}\n",
        )
        .unwrap();
        let config = V2Config {
            model: Some("openai-codex:gpt-5.5".into()),
            ..V2Config::default()
        };
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut fixture = Self {
            root,
            config,
            workspace,
            registry,
            references: Vec::new(),
        };
        for label in ["Alpha", "Beta", "Gamma"] {
            let output = fixture
                .registry
                .execute_tool(
                    "threat-model:import",
                    json!({
                "activate":true,"label":label,"document":{"version":"1","methodology":"stride",
                "title":label,"systemContext":label,"dfd":{"nodes":[{"id":"app","name":label,
                "type":"process","trustZone":"internal"}],"flows":[],"trustBoundaries":[]},
                "threats":[],"summary":{}}}),
                    &fixture.ctx(),
                )
                .unwrap();
            fixture.references.push(output["data"]["modelRef"].clone());
        }
        fixture
    }

    fn ctx(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }

    fn input(&self) -> Value {
        json!({"campaignId":"matrix-test","investigationId":"matrix-accounting","baselineCaseId":"alpha",
            "scanInput":{"taskMode":"manual","tasks":["secret-scan"]},"contextCases":[
            {"id":"alpha","label":"Baseline","threatModelRef":self.references[0]},
            {"id":"beta","label":"Candidate","threatModelRef":self.references[1]},
            {"id":"gamma","label":"Other context","threatModelRef":self.references[2]}]})
    }
}

#[test]
fn matrix_freezes_nine_case_bound_jobs_without_combining_condition_keys_or_starting_work() {
    let fixture = Fixture::new();
    let active = std::fs::read(fixture.root.path().join(".kuzushi/threat-model.json")).unwrap();
    let mut input = fixture.input();
    input["scanInput"]["tasks"] = json!(["agentic"]);
    let output = fixture
        .registry
        .execute_tool("campaign:study", input, &fixture.ctx())
        .unwrap();
    let receipt: ContextMatrixReceipt = serde_json::from_value(output["data"].clone()).unwrap();
    assert_eq!(receipt.job_count, 9);
    assert_eq!(receipt.workers, 1);
    assert_eq!(receipt.matrix.baseline().unwrap().id, "alpha");
    let plan = approved_work::read_bounded_plan(fixture.root.path(), "matrix-test").unwrap();
    assert_eq!(plan["kind"], CONTEXT_MATRIX_KIND);
    assert!(plan.get("equivalenceKey").is_none());
    for (index, case) in receipt.matrix.cases.iter().enumerate() {
        assert_eq!(
            case.base_input["scanContextRef"],
            receipt.matrix.baseline().unwrap().base_input["scanContextRef"]
        );
        assert!(case
            .equivalence
            .components
            .supporting_context_sha256
            .is_some());
        assert_eq!(case.base_input["threatModelRef"], fixture.references[index]);
        let reference = serde_json::from_value(fixture.references[index].clone()).unwrap();
        let frozen = crate::scan::inspect_threat_model_digest(
            fixture.root.path(),
            &case.base_input["threatModelDigestRef"],
            &reference,
        )
        .unwrap();
        assert!(frozen.preview["text"]
            .as_str()
            .unwrap()
            .contains(["Alpha", "Beta", "Gamma"][index]));
        assert_eq!(
            plan["jobs"][index * 3]["input"]["threatModelDigestRef"],
            case.base_input["threatModelDigestRef"]
        );
        assert_eq!(plan["jobs"][index * 3]["caseId"], case.id);
        assert_eq!(
            plan["jobs"][index * 3]["input"]["batchEquivalenceKey"],
            case.equivalence.sha256
        );
        assert_eq!(plan["jobs"][index * 3 + 2]["input"]["trial"], 3);
    }
    assert_ne!(
        receipt.matrix.cases[0].equivalence.sha256,
        receipt.matrix.cases[1].equivalence.sha256
    );
    assert!(load_study_plan_receipt(fixture.root.path(), "matrix-test").is_err());
    assert_eq!(
        active,
        std::fs::read(fixture.root.path().join(".kuzushi/threat-model.json")).unwrap()
    );
    assert!(!fixture
        .root
        .path()
        .join(".kuzushi/v3/campaigns/matrix-test/queue.json")
        .exists());
    let restored = load_context_matrix_receipt(fixture.root.path(), "matrix-test").unwrap();
    // Shared result normalization presents artifact paths relative to the target.
    assert_eq!(restored.matrix, receipt.matrix);
    assert_eq!(restored.plan_sha256, receipt.plan_sha256);
    assert_eq!(restored.job_count, receipt.job_count);
}

#[test]
fn root_context_omission_compares_without_changing_legacy_condition_keys() {
    let fixture = Fixture::new();
    let mut input = fixture.input();
    input["contextCases"] = json!([
        {"id":"alpha","label":"Root context","threatModelRef":fixture.references[0]},
        {"id":"none","label":"Omit context","threatModelRef":null}
    ]);
    let result = fixture
        .registry
        .execute_tool("campaign:study", input, &fixture.ctx())
        .unwrap();
    let receipt: ContextMatrixReceipt = serde_json::from_value(result["data"].clone()).unwrap();
    assert_eq!(receipt.job_count, 6);
    let root_case = &receipt.matrix.cases[0];
    let omitted = &receipt.matrix.cases[1];
    assert_eq!(
        root_case.omission_scope_sha256.as_deref(),
        Some(omitted.equivalence.components.scope_sha256.as_str())
    );
    assert!(omitted.omission_scope_sha256.is_none());
    let captured = capture_batch_equivalence(
        fixture.root.path(),
        &root_case.base_input,
        &fixture.config,
        &fixture.registry,
    )
    .unwrap();
    assert_eq!(captured, root_case.equivalence);
    let plan = approved_work::read_bounded_plan(fixture.root.path(), "matrix-test").unwrap();
    let mut legacy = plan.clone();
    legacy["contextMatrix"]["cases"][0]
        .as_object_mut()
        .unwrap()
        .remove("omissionScopeSha256");
    assert!(validate_context_matrix_plan("matrix-test", &legacy)
        .unwrap_err()
        .to_string()
        .contains("new fixed matrix"));
    assert_eq!(
        approved_work::read_bounded_plan(fixture.root.path(), "matrix-test").unwrap(),
        plan
    );
}

#[test]
fn tampered_root_comparison_is_rejected_at_approval_and_omitted_case_cannot_claim_one() {
    let fixture = Fixture::new();
    fixture
        .registry
        .execute_tool("campaign:study", fixture.input(), &fixture.ctx())
        .unwrap();
    let mut plan = approved_work::read_bounded_plan(fixture.root.path(), "matrix-test").unwrap();
    plan["contextMatrix"]["cases"][0]["omissionScopeSha256"] =
        json!(format!("sha256:{}", "0".repeat(64)));
    let error = approval::review_for_approval(
        fixture.root.path(),
        "matrix-test",
        &plan,
        &json!({"campaignJobs":9}),
        &fixture.ctx(),
        &fixture.registry,
    )
    .unwrap_err();
    assert!(error.to_string().contains("Root-scope comparison differs"));
    let mut case: FrozenContextCase =
        serde_json::from_value(plan["contextMatrix"]["cases"][0].clone()).unwrap();
    case.equivalence.components.threat_model = None;
    assert!(scope_comparison::require_case_conditions(&case, &case)
        .unwrap_err()
        .to_string()
        .contains("omitted context cannot carry"));
}

#[test]
fn matrix_rejects_changed_jobs_context_binding_and_rehashed_other_conditions() {
    let fixture = Fixture::new();
    fixture
        .registry
        .execute_tool("campaign:study", fixture.input(), &fixture.ctx())
        .unwrap();
    let original = approved_work::read_bounded_plan(fixture.root.path(), "matrix-test").unwrap();
    for change in [
        "extra-job",
        "context",
        "source",
        "scope",
        "model",
        "runtime",
        "prompt",
        "engine",
    ] {
        let mut plan = original.clone();
        if change == "extra-job" {
            let extra = plan["jobs"][0].clone();
            plan["jobs"].as_array_mut().unwrap().push(extra);
        } else if change == "context" {
            plan["jobs"][3]["input"]["threatModelRef"] = fixture.references[0].clone();
        } else {
            change_condition(&mut plan, change);
        }
        assert!(
            validate_context_matrix_plan("matrix-test", &plan).is_err(),
            "{change}"
        );
    }
}

fn change_condition(plan: &mut Value, change: &str) {
    let key = &mut plan["contextMatrix"]["cases"][1]["equivalence"];
    match change {
        "source" => key["components"]["workspaceIdentity"] = json!("different-source"),
        "scope" => key["components"]["scopeSha256"] = json!("different-scope"),
        "model" => key["components"]["model"] = json!("other-model"),
        "runtime" => key["components"]["runtimeIdentity"]["backend"] = json!("other-runtime"),
        "prompt" => key["components"]["promptOverridesSha256"] = json!("other-prompts"),
        _ => key["components"]["engineIdentity"]["kuzushiVersion"] = json!("other-engine"),
    }
    key["sha256"] = json!(batch::equivalence::digest_serializable(&key["components"]).unwrap());
}

#[test]
fn invalid_case_definition_publishes_no_partial_plan() {
    let fixture = Fixture::new();
    let mut input = fixture.input();
    input["contextCases"][1]["threatModelRef"] = fixture.references[0].clone();
    assert!(fixture
        .registry
        .execute_tool("campaign:study", input, &fixture.ctx())
        .is_err());
    assert!(!campaign_plan_path(fixture.root.path(), "matrix-test").exists());
}

fn approve(fixture: &Fixture, receipt: &ContextMatrixReceipt) -> Result<Value> {
    let input = json!({"investigationId":"matrix-accounting","expectedRevision":0,
        "model":"openai-codex:gpt-5.5","maxProviderCalls":11,"protectedReviewCalls":2,
        "reason":"Owned deterministic matrix test, no live requests","campaignId":receipt.campaign_id,
        "campaignPlanSha256":receipt.plan_sha256,"campaignJobs":receipt.job_count,"maxJobAttempts":1});
    let prepared = fixture
        .registry
        .prepare_dispatch_input("campaign:approve-allowance", input, &fixture.ctx(), None)?
        .authorize_explicit_headless();
    fixture
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &fixture.ctx(), None)
}

#[test]
fn matrix_approval_binds_all_jobs_and_shared_dispatch_refuses_an_extra_attempt() {
    let fixture = Fixture::new();
    fixture
        .registry
        .execute_tool("campaign:study", fixture.input(), &fixture.ctx())
        .unwrap();
    let receipt = load_context_matrix_receipt(fixture.root.path(), "matrix-test").unwrap();
    let plan = approved_work::read_bounded_plan(fixture.root.path(), "matrix-test").unwrap();
    let mut job = plan["jobs"][0]["input"].clone();
    assert!(fixture
        .registry
        .execute_tool("sast:scan", job.clone(), &fixture.ctx())
        .is_err());
    let approval = approve(&fixture, &receipt).unwrap();
    assert_eq!(
        approval["data"]["allowance"]["workPlan"]["jobs"]
            .as_array()
            .unwrap()
            .len(),
        9
    );
    job["allowanceRef"] = json!({"schemaVersion":1,"investigationId":"matrix-accounting","revision":1,
        "workId":"matrix-test:alpha-trial-001"});
    let store = crate::FindingStore::open(fixture.workspace.findings_db_path()).unwrap();
    let trace =
        crate::run_lifecycle::RunObservationHandle::jsonl(fixture.root.path(), "owned-alpha-pass")
            .unwrap()
            .start_root_task("sast:scan")
            .unwrap()
            .trace_handle();
    let mut child_ctx = fixture.ctx();
    child_ctx.findings_store = Some(&store);
    child_ctx.trace = Some(&trace);
    let prepared = fixture
        .registry
        .prepare_dispatch_input("sast:scan", job.clone(), &child_ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let output = fixture
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &child_ctx, None)
        .unwrap();
    assert_eq!(output["status"], "completed");
    let extra_trace =
        crate::run_artifacts::TraceHandle::jsonl(fixture.root.path(), "extra-alpha-attempt");
    child_ctx.trace = Some(&extra_trace);
    let prepared = fixture
        .registry
        .prepare_dispatch_input("sast:scan", job, &child_ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    assert!(fixture
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &child_ctx, None)
        .is_err());
    let allowance = crate::SpendLimiter::read_allowance_snapshot(
        &fixture.workspace.findings_db_path(),
        "matrix-accounting",
    )
    .unwrap();
    assert_eq!(allowance.committed_calls, 0);
    assert_eq!(allowance.protected_review_remaining(), 2);
}

#[test]
fn source_drift_prevents_matrix_approval_without_creating_an_allowance() {
    let fixture = Fixture::new();
    fixture
        .registry
        .execute_tool("campaign:study", fixture.input(), &fixture.ctx())
        .unwrap();
    let receipt = load_context_matrix_receipt(fixture.root.path(), "matrix-test").unwrap();
    std::fs::write(fixture.root.path().join("main.rs"), "// Changed source\n").unwrap();
    assert!(approve(&fixture, &receipt).is_err());
    assert!(crate::SpendLimiter::read_allowance_snapshot(
        &fixture.workspace.findings_db_path(),
        "matrix-accounting"
    )
    .is_err());
}

#[test]
fn occurrence_report_keeps_each_contexts_planned_denominator_separate() {
    let fixture = Fixture::new();
    fixture
        .registry
        .execute_tool("campaign:study", fixture.input(), &fixture.ctx())
        .unwrap();
    let store = crate::FindingStore::open(fixture.workspace.findings_db_path()).unwrap();
    let report = crate::findings::derive_context_matrix_occurrence_report(
        fixture.root.path(),
        "matrix-test",
        &store,
    )
    .unwrap();
    assert_eq!(report.cases.len(), 3);
    assert_eq!(report.baseline_case_id, "alpha");
    for case in &report.cases {
        assert_eq!(case.occurrence.planned, 3);
        assert_eq!(case.occurrence.completed, 0);
        assert_eq!(case.occurrence.pending, 3);
        assert!(case.occurrence.rows.is_empty());
    }
    assert_ne!(
        report.cases[0].occurrence.equivalence_key,
        report.cases[1].occurrence.equivalence_key
    );
}
