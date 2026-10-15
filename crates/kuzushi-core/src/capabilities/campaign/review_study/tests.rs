use super::*;
use crate::{
    allowance::AllowanceBinding, AgentRuntime, FindingStore, Severity, TriageOutcome,
    TriageRequest, TriageVerdict, V2Config, WorkspaceTarget,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

const MODEL: &str = "openai:gpt-5.5";
mod source_evidence;

#[test]
fn review_approval_accepts_broad_selection_with_multiple_observation_generations() {
    let fixture = Fixture::new();
    let finding = Finding::new_tool(
        "audit",
        "owned",
        "note.md",
        1,
        None,
        Severity::Low,
        "Labeled inert observation",
    );
    fixture
        .store
        .record_run_started("second", fixture.root.path(), "running")
        .unwrap();
    fixture.store.insert_finding("second", &finding).unwrap();
    fixture
        .store
        .record_run_finished("second", "completed", 1)
        .unwrap();
    let receipt = fixture.draft(json!({"strategy":"standard"}));
    assert_eq!(receipt.findings.len(), 1);
    let approved = fixture.approve(fixture.approval(&receipt, 2)).unwrap();
    assert_eq!(approved["data"]["allowance"]["committedCalls"], 0);
    assert_eq!(receipt.input["fingerprints"].as_array().unwrap().len(), 1);
}

fn recorded_commit(fixture: &Fixture, sha: &str) {
    let summary = crate::run_artifacts::RunSummary::running(
        "observed",
        "scan",
        None,
        fixture.root.path().display().to_string(),
    )
    .with_target_git(Some(crate::run_artifacts::RunTargetGitMetadata {
        sha: sha.into(),
        branch: Some("main".into()),
        dirty: false,
    }))
    .complete();
    crate::run_artifacts::write_run_summary(fixture.root.path(), &summary).unwrap();
}

#[test]
fn review_freezes_recorded_observation_commit_without_substituting_current_source() {
    let fixture = Fixture::new();
    recorded_commit(&fixture, &"a".repeat(40));
    let receipt = fixture.draft(json!({"strategy":"standard"}));
    assert!(receipt.source_identity.starts_with("tree:"));
    assert_eq!(receipt.observation_sources.len(), 1);
    let source = &receipt.observation_sources[0];
    assert_eq!(source.generation_id, receipt.findings[0].id.unwrap());
    assert_eq!(source.recorded_git.as_ref().unwrap().sha, "a".repeat(40));
    assert!(!source.metadata_unavailable);
}

#[test]
fn unreadable_observation_metadata_does_not_invent_a_commit() {
    let fixture = Fixture::new();
    let receipt = fixture.draft(json!({"strategy":"standard"}));
    assert!(receipt.observation_sources[0].metadata_unavailable);
    assert!(receipt.observation_sources[0].recorded_git.is_none());
}

#[test]
fn invalid_recorded_commit_is_disclosed_as_unavailable() {
    let fixture = Fixture::new();
    recorded_commit(&fixture, "invalid");
    let receipt = fixture.draft(json!({"strategy":"standard"}));
    assert!(receipt.observation_sources[0].metadata_unavailable);
    assert!(receipt.observation_sources[0].recorded_git.is_none());
}

#[test]
fn invalid_branch_metadata_is_not_copied_into_the_review_draft() {
    for branch in ["invalid\u{1b}branch".to_string(), "x".repeat(257)] {
        let fixture = Fixture::new();
        let summary = crate::run_artifacts::RunSummary::running(
            "observed",
            "scan",
            None,
            fixture.root.path().display().to_string(),
        )
        .with_target_git(Some(crate::run_artifacts::RunTargetGitMetadata {
            sha: "a".repeat(40),
            branch: Some(branch),
            dirty: false,
        }))
        .complete();
        crate::run_artifacts::write_run_summary(fixture.root.path(), &summary).unwrap();
        let receipt = fixture.draft(json!({"strategy":"standard"}));
        assert!(receipt.observation_sources[0].metadata_unavailable);
        assert!(receipt.observation_sources[0].recorded_git.is_none());
    }
}

#[test]
fn legacy_review_plans_load_without_sources_and_foreign_sources_are_rejected() {
    let fixture = Fixture::new();
    fixture.draft(json!({"strategy":"standard"}));
    let path = campaign_plan_path(fixture.root.path(), "review");
    let mut plan: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let sources = plan
        .as_object_mut()
        .unwrap()
        .remove("observationSources")
        .unwrap();
    std::fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
    assert!(load_review_study(fixture.root.path(), "review")
        .unwrap()
        .observation_sources
        .is_empty());
    plan["observationSources"] = sources;
    plan["observationSources"][0]["generationId"] = json!(1);
    std::fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
    assert!(load_review_study(fixture.root.path(), "review")
        .unwrap_err()
        .to_string()
        .contains("source identity changed"));
}

struct Fixture {
    root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    store: FindingStore,
    config: V2Config,
    registry: ModuleRegistry,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("note.md"),
            "Owned review fixture. Never executed.\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("observed", root.path(), "running")
            .unwrap();
        store
            .insert_finding(
                "observed",
                &Finding::new_tool(
                    "audit",
                    "owned",
                    "note.md",
                    1,
                    None,
                    Severity::Low,
                    "Labeled inert observation",
                ),
            )
            .unwrap();
        store
            .record_run_finished("observed", "completed", 1)
            .unwrap();
        Self {
            root,
            workspace,
            store,
            config: V2Config {
                model: Some(MODEL.into()),
                ..Default::default()
            },
            registry: ModuleRegistry::with_v2_builtins(),
        }
    }
    fn ctx(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: Some(&self.store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }
    fn draft(&self, mut review: Value) -> ReviewStudyReceipt {
        review
            .as_object_mut()
            .unwrap()
            .entry("threatModelRef")
            .or_insert(Value::Null);
        let result = self.registry.execute_tool("campaign:review-study", json!({"campaignId":"review","investigationId":"investigation","reviewInput":review}), &self.ctx()).unwrap();
        serde_json::from_value(result["data"].clone()).unwrap()
    }
    fn approval(&self, receipt: &ReviewStudyReceipt, calls: usize) -> Value {
        json!({"investigationId":"investigation","expectedRevision":0,"model":MODEL,"maxProviderCalls":calls,"protectedReviewCalls":calls,"reason":"Owned synthetic review test; no live provider","campaignId":"review","campaignPlanSha256":receipt.plan_sha256,"campaignJobs":1,"maxJobAttempts":1})
    }
    fn approve(&self, input: Value) -> Result<Value> {
        let prepared = self
            .registry
            .prepare_dispatch_input("campaign:approve-allowance", input, &self.ctx(), None)?
            .authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &self.ctx(), None)
    }
    fn ledger(&self) -> crate::SpendLimiter {
        crate::SpendLimiter::open(self.workspace.findings_db_path()).unwrap()
    }
    fn run(&self, input: Value, runtime: &dyn AgentRuntime, run: &str) -> Result<Value> {
        let observation = crate::run_lifecycle::RunObservationHandle::jsonl(self.root.path(), run)
            .unwrap()
            .start_root_task(TOOL)
            .unwrap();
        let trace = observation.trace_handle();
        let mut ctx = self.ctx();
        ctx.trace = Some(&trace);
        let prepared = self
            .registry
            .prepare_dispatch_input(TOOL, input, &ctx, None)?
            .authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(runtime))
    }
}

#[derive(Clone, Default)]
struct MeteredReview {
    binding: Option<AllowanceBinding>,
    attempts: Arc<AtomicUsize>,
}
impl AgentRuntime for MeteredReview {
    fn with_allowance_binding(
        &self,
        binding: AllowanceBinding,
    ) -> Result<Box<dyn AgentRuntime + '_>> {
        Ok(Box::new(Self {
            binding: Some(binding),
            ..self.clone()
        }))
    }
    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        let binding = self
            .binding
            .as_ref()
            .context("fixture requires an allowance")?;
        for _ in 0..2 {
            let reservation = binding.reserve(&request.model)?;
            self.attempts.fetch_add(1, Ordering::SeqCst);
            binding.settle(reservation, crate::runtime::RuntimeCostReport::UNAVAILABLE)?;
        }
        Ok(TriageOutcome {
            verdict: TriageVerdict::NeedsReview,
            confidence: 0.5,
            rationale: "Labeled synthetic review. No vulnerability claim.".into(),
            ..Default::default()
        })
    }
}

#[test]
fn planning_freezes_exact_observations_without_reducing_review_quality_or_starting_work() {
    let fixture = Fixture::new();
    let receipt = fixture.draft(json!({}));
    assert_eq!(receipt.input["strategy"], "deep");
    assert_eq!(receipt.input["concurrency"], 1);
    assert_eq!(receipt.findings.len(), 1);
    assert_eq!(
        receipt.input["fingerprints"],
        json!([format!("generation:{}", receipt.findings[0].id.unwrap())])
    );
    assert!(receipt.input.get("allowanceRef").is_none());
    assert!(fixture
        .ledger()
        .allowance_snapshot("investigation")
        .is_err());
    assert!(!fixture.root.path().join(".kuzushi/v3/runs").exists());
    assert_eq!(
        load_review_study(fixture.root.path(), "review").unwrap(),
        receipt
    );
}

#[test]
fn review_approval_preserves_fixed_work_and_charges_internal_attempts_to_protected_review() {
    let fixture = Fixture::new();
    let reference = crate::capabilities::threat_model::commit_test_model(
        fixture.root.path(),
        "Owned review context",
    );
    let receipt = fixture
        .draft(json!({"strategy":"standard","prefilterThreshold":0,"identityReconcile":"off","threatModelRef":reference}));
    let frozen = crate::scan::inspect_threat_model_digest(
        fixture.root.path(),
        &receipt.input["threatModelDigestRef"],
        &reference,
    )
    .unwrap();
    assert!(frozen.preview["text"]
        .as_str()
        .unwrap()
        .contains("Owned review context"));
    fixture.approve(fixture.approval(&receipt, 2)).unwrap();
    let allowance = fixture
        .ledger()
        .allowance_snapshot("investigation")
        .unwrap();
    assert_eq!(allowance.committed_calls, 0);
    let runtime = MeteredReview::default();
    let input = receipt.bound_input(&allowance).unwrap();
    let result = fixture
        .run(input.clone(), &runtime, "approved-review")
        .unwrap();
    assert_eq!(result["data"]["triaged"], 1);
    assert_eq!(runtime.attempts.load(Ordering::SeqCst), 2);
    let recovered = fixture
        .ledger()
        .allowance_snapshot("investigation")
        .unwrap();
    assert_eq!(recovered.committed_calls, 2);
    assert_eq!(recovered.protected_review_remaining(), 0);
    assert!(fixture
        .run(input, &runtime, "unapproved-review-repeat")
        .is_err());
    assert_eq!(runtime.attempts.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture
            .store
            .list_review_decisions(receipt.findings[0].id.unwrap())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn internal_attempt_cannot_cross_the_allowance_limit() {
    let fixture = Fixture::new();
    let receipt = fixture.draft(json!({"strategy":"standard","prefilterThreshold":0}));
    fixture.approve(fixture.approval(&receipt, 1)).unwrap();
    let allowance = fixture
        .ledger()
        .allowance_snapshot("investigation")
        .unwrap();
    let runtime = MeteredReview::default();
    let result = fixture
        .run(
            receipt.bound_input(&allowance).unwrap(),
            &runtime,
            "limited-review",
        )
        .unwrap();
    assert_eq!(result["status"], "failed");
    assert_eq!(runtime.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .ledger()
            .allowance_snapshot("investigation")
            .unwrap()
            .committed_calls,
        1
    );
}

#[test]
fn review_refuses_changed_source_attempt_expansion_and_input_governance() {
    let fixture = Fixture::new();
    let receipt = fixture.draft(json!({}));
    let mut approval = fixture.approval(&receipt, 3);
    approval["maxJobAttempts"] = json!(2);
    assert!(fixture.approve(approval).is_err());
    std::fs::write(
        fixture.root.path().join("note.md"),
        "Changed owned source\n",
    )
    .unwrap();
    assert!(fixture.approve(fixture.approval(&receipt, 3)).is_err());
    for review in [
        json!({"concurrency":2}),
        json!({"allowanceRef":{}}),
        json!({"fingerprints":["missing"]}),
    ] {
        assert!(fixture.registry.execute_tool("campaign:review-study",json!({"campaignId":"other","investigationId":"investigation","reviewInput":review}),&fixture.ctx()).is_err());
    }
}

#[test]
fn missing_accepted_context_is_not_replaced_with_globally_active_context() {
    let fixture = Fixture::new();
    let error = fixture
        .registry
        .execute_tool(
            "campaign:review-study",
            json!({"campaignId":"no-context","investigationId":"investigation","reviewInput":{}}),
            &fixture.ctx(),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("No accepted Map context"));
    let receipt = fixture.draft(json!({"threatModelRef":null}));
    assert!(receipt.input["threatModelRef"].is_null());
}

#[test]
fn review_approval_reads_workspace_findings_when_the_optional_handle_is_absent() {
    let fixture = Fixture::new();
    let receipt = fixture.draft(json!({"threatModelRef":null}));
    let mut ctx = fixture.ctx();
    ctx.findings_store = None;
    let prepared = fixture
        .registry
        .prepare_dispatch_input(
            "campaign:approve-allowance",
            fixture.approval(&receipt, 2),
            &ctx,
            None,
        )
        .unwrap()
        .authorize_explicit_headless();
    let output = fixture
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(output["data"]["allowance"]["committedCalls"], 0);
    assert_eq!(
        output["data"]["allowance"]["workPlan"]["jobs"][0]["tool"],
        TOOL
    );
}

#[test]
fn prepare_native_review_study_fixture() {
    let Some(root) = std::env::var_os("KUZUSHI_REVIEW_STUDY_FIXTURE_OUT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    assert!(root.is_absolute() && !root.join(".kuzushi/review-study-fixture.json").exists());
    for file in ["app.py", "config.env"] {
        let _ = std::fs::remove_file(root.join(file));
    }
    std::fs::write(
        root.join("note.md"),
        "Owned review observation. No vulnerability claim. Never executed.\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(&root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("observed", &root, "running")
        .unwrap();
    store
        .insert_finding(
            "observed",
            &Finding::new_tool(
                "fixture",
                "owned",
                "note.md",
                1,
                None,
                Severity::Low,
                "Labeled pending observation for review",
            ),
        )
        .unwrap();
    store
        .record_run_finished("observed", "completed", 1)
        .unwrap();
    let snapshot = crate::incremental_index::register_workspace_tree_identity(&workspace).unwrap();
    let record =
        crate::run_artifacts::ToolRunRecord::new(&root, "observed", "scan", "fixture:observe");
    crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        &json!({"syntheticObservation":true}),
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    crate::run_artifacts::try_record_tool_run_complete(record,&json!({"status":"completed","data":{"syntheticObservation":true,"snapshotHash":snapshot.snapshot_hash,"treeHash":snapshot.tree_hash}})).unwrap();
    std::fs::write(
        root.join(".kuzushi/review-study-fixture.json"),
        serde_json::to_vec_pretty(
            &json!({"syntheticObservation":true,"providerRequests":0,"sourceExecuted":false}),
        )
        .unwrap(),
    )
    .unwrap();
}
