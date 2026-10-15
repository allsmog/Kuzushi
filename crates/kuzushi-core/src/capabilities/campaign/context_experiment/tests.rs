use super::*;
use crate::run_artifacts::*;
use crate::{
    modules::{ModuleRegistry, ToolExecutionContext},
    V2Config, WorkspaceTarget,
};
use serde_json::json;

#[test]
fn controlled_conditions_exclude_only_the_selected_context_and_its_saved_projection() {
    let first = json!({"tasks":["agentic"],"threatModelRef":{"synthetic":"alpha"},"threatModelDigestRef":{"synthetic":"alpha-bytes"}});
    let mut second = first.clone();
    second["threatModelRef"] = json!({"synthetic":"beta"});
    second["threatModelDigestRef"] = json!({"synthetic":"beta-bytes"});
    assert_eq!(
        conditions::controlled_input_digest(&first).unwrap(),
        conditions::controlled_input_digest(&second).unwrap()
    );
    second["tasks"] = json!(["secret-scan"]);
    assert_ne!(
        conditions::controlled_input_digest(&first).unwrap(),
        conditions::controlled_input_digest(&second).unwrap()
    );
}

struct Fixture {
    root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    config: V2Config,
    registry: ModuleRegistry,
    baseline: StudyPlanReceipt,
    candidate_ref: Value,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("main.rs"),
            "// Owned source fixture, never executed.\nfn main() {}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let config = V2Config {
            model: Some("openai-codex:gpt-5.5".into()),
            ..Default::default()
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = context(&workspace, &config);
        let alpha = import(&registry, &ctx, "Alpha");
        let beta = import(&registry, &ctx, "Beta");
        registry
            .execute_tool(
                "campaign:study",
                json!({"campaignId":"baseline-study","investigationId":"investigation",
            "scanInput":{"taskMode":"manual","tasks":["secret-scan"],"threatModelRef":alpha}}),
                &ctx,
            )
            .unwrap();
        let baseline = load_study_plan_receipt(root.path(), "baseline-study").unwrap();
        admit_labeled_baseline(&registry, &ctx, &baseline);
        write_labeled_baseline(root.path(), &baseline);
        Self {
            root,
            workspace,
            config,
            registry,
            baseline,
            candidate_ref: beta,
        }
    }
    fn input(&self) -> Value {
        let mut scan = self.baseline.scan_input.clone();
        scan["threatModelRef"] = self.candidate_ref.clone();
        json!({"campaignId":"candidate-study","investigationId":"investigation","contextBaselineRunId":"baseline-run","scanInput":scan})
    }
    fn plan(&self, input: Value) -> Result<Value> {
        self.registry.execute_tool(
            "campaign:study",
            input,
            &context(&self.workspace, &self.config),
        )
    }
}

fn context<'a>(workspace: &'a WorkspaceTarget, config: &'a V2Config) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

fn import(registry: &ModuleRegistry, ctx: &ToolExecutionContext<'_>, label: &str) -> Value {
    let output = registry.execute_tool("threat-model:import", json!({"activate":true,"label":label,
        "document":{"version":"1","methodology":"stride","title":label,"systemContext":label,
        "dfd":{"nodes":[{"id":"app","type":"process","name":label,"trustZone":"internal"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{}}}),ctx).unwrap();
    output["data"]["modelRef"].clone()
}

fn write_labeled_baseline(root: &Path, receipt: &StudyPlanReceipt) {
    let summary = RunSummary::running(
        "baseline-run",
        "tool",
        Some("sast:scan".into()),
        root.display().to_string(),
    )
    .complete();
    write_run_summary(root, &summary).unwrap();
    write_run_artifact_json(
        root,
        "baseline-run",
        "scan-input.json",
        "Labeled baseline input",
        &receipt.scan_input,
    )
    .unwrap();
    let condition = ScanBatchChildEquivalenceReceipt {
        schema_version: 1,
        batch_id: receipt.campaign_id.clone(),
        trial: 1,
        expected_key: receipt.equivalence.sha256.clone(),
        consumed: receipt.equivalence.clone(),
    };
    write_run_artifact_json(
        root,
        "baseline-run",
        SCAN_BATCH_EQUIVALENCE_RECEIPT_FILE,
        "Labeled condition receipt",
        &serde_json::to_value(condition).unwrap(),
    )
    .unwrap();
    let stage = PhaseStageReceipt {
        phase: crate::WorkflowPhase::Scan,
        outcome: PhaseStageOutcome::Completed,
        run_refs: vec!["baseline-run".into()],
        scan: Some(ScanStageData {
            scope: ScanStageScope {
                target: root.display().to_string(),
                paths: Vec::new(),
            },
            plan: ScanStagePlan {
                selection: "manual".into(),
                engines: vec!["secret-scan".into()],
            },
            engines: vec![ScanStageEngine {
                engine: "secret-scan".into(),
                outcome: ScanEngineStageOutcome::Complete,
                run_ref: Some("baseline-run".into()),
                detail: Some("Labeled offline receipt, no source execution".into()),
            }],
            finding_delta: ScanFindingDelta {
                added: 0,
                updated: 0,
            },
            severity_counts: Vec::new(),
            artifact_delta: Vec::new(),
            duration_ms: 0,
            cost: None,
            target_snapshot: crate::workflow_attempts::PhaseTargetSnapshot::capture(root),
        }),
    };
    std::fs::write(
        root.join(".kuzushi/v3/runs/baseline-run/phase-stages.jsonl"),
        format!("{}\n", serde_json::to_string(&stage).unwrap()),
    )
    .unwrap();
}

fn admit_labeled_baseline(
    registry: &ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
    baseline: &StudyPlanReceipt,
) {
    let input = json!({"investigationId":"investigation","expectedRevision":0,"model":"openai-codex:gpt-5.5","maxProviderCalls":8,"protectedReviewCalls":2,"reason":"Owned labeled baseline admission",
        "campaignId":baseline.campaign_id,"campaignPlanSha256":baseline.plan_sha256,"campaignJobs":3,"maxJobAttempts":1});
    let prepared = registry
        .prepare_dispatch_input("campaign:approve-allowance", input, ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, ctx, None)
        .unwrap();
    let snapshot = load_study_allowance(ctx.workspace.unwrap().root(), baseline)
        .unwrap()
        .unwrap();
    let plan = snapshot.work_plan.as_ref().unwrap();
    let job = &plan.jobs[0];
    let reference = crate::allowance::AllowanceReferenceV1 {
        schema_version: 1,
        investigation_id: snapshot.investigation_id.clone(),
        revision: snapshot.revision,
        work_id: job.work_id.clone(),
    };
    let ledger = crate::SpendLimiter::open(ctx.workspace.unwrap().findings_db_path()).unwrap();
    ledger
        .claim_work_attempt(&crate::allowance::WorkAttempt {
            reference: &reference,
            run_id: "baseline-run",
            tool: "sast:scan",
            input_sha256: &job.input_sha256,
            source_identity: &plan.source_identity,
            config_sha256: &plan.config_sha256,
        })
        .unwrap();
}

#[test]
fn context_candidate_freezes_three_identical_jobs_and_authenticates_baseline_on_recovery() {
    let fixture = Fixture::new();
    let output = fixture.plan(fixture.input()).unwrap();
    let receipt = load_study_plan_receipt(fixture.root.path(), "candidate-study").unwrap();
    assert_eq!(output["data"]["jobCount"], 3);
    let experiment = load_study_context_experiment(fixture.root.path(), &receipt)
        .unwrap()
        .unwrap();
    assert_eq!(experiment.baseline_run_id, "baseline-run");
    assert_eq!(experiment.baseline, fixture.baseline.equivalence);
    assert_ne!(experiment.baseline, experiment.candidate);
    assert_eq!(experiment.candidate, receipt.equivalence);
    assert_eq!(receipt.scan_input["threatModelRef"], fixture.candidate_ref);
    let plan = approved_work::read_bounded_plan(fixture.root.path(), "candidate-study").unwrap();
    assert_eq!(plan["jobs"].as_array().unwrap().len(), 3);
    assert!(plan["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|job| job["input"]["threatModelRef"] == fixture.candidate_ref));
    assert!(!campaign_queue_path(fixture.root.path(), "candidate-study").exists());
    let active = crate::capabilities::threat_model::load_threat_model_manifest(fixture.root.path())
        .unwrap()
        .unwrap()
        .active;
    assert_eq!(serde_json::to_value(active).unwrap(), fixture.candidate_ref);
}

#[test]
fn same_context_source_options_and_unverifiable_baselines_cannot_be_context_only_experiments() {
    for change in [
        "same-context",
        "source",
        "options",
        "missing-input",
        "tampered-input",
        "legacy",
        "missing-stage",
        "partial-engine",
        "missing-accounting",
        "unsafe-run",
        "account-reset",
    ] {
        let fixture = Fixture::new();
        let mut input = fixture.input();
        match change {
            "same-context" => {
                input["scanInput"]["threatModelRef"] =
                    fixture.baseline.scan_input["threatModelRef"].clone()
            }
            "source" => {
                std::fs::write(fixture.root.path().join("main.rs"), "// Changed source\n").unwrap()
            }
            "options" => input["scanInput"]["maxFindings"] = json!(7),
            "missing-input" => std::fs::remove_file(
                fixture
                    .root
                    .path()
                    .join(".kuzushi/v3/runs/baseline-run/scan-input.json"),
            )
            .unwrap(),
            "tampered-input" => std::fs::write(
                fixture
                    .root
                    .path()
                    .join(".kuzushi/v3/runs/baseline-run/scan-input.json"),
                "{}",
            )
            .unwrap(),
            "legacy" => std::fs::remove_file(
                fixture
                    .root
                    .path()
                    .join(".kuzushi/v3/runs/baseline-run/batch-equivalence.json"),
            )
            .unwrap(),
            "unsafe-run" => input["contextBaselineRunId"] = json!("../outside"),
            "missing-stage" => std::fs::remove_file(
                fixture
                    .root
                    .path()
                    .join(".kuzushi/v3/runs/baseline-run/phase-stages.jsonl"),
            )
            .unwrap(),
            "partial-engine" => {
                let path = fixture
                    .root
                    .path()
                    .join(".kuzushi/v3/runs/baseline-run/phase-stages.jsonl");
                let mut stage: Value =
                    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
                stage["scan"]["engines"][0]["outcome"] = json!("partial");
                std::fs::write(path, format!("{}\n", stage)).unwrap();
            }
            "missing-accounting" => {
                let db = rusqlite::Connection::open(fixture.workspace.findings_db_path()).unwrap();
                db.execute("delete from investigation_work_attempts", [])
                    .unwrap();
            }
            "account-reset" => input["investigationId"] = json!("new-empty-account"),
            _ => unreachable!(),
        }
        assert!(fixture.plan(input).is_err(), "{change}");
        assert!(
            !campaign_plan_path(fixture.root.path(), "candidate-study").exists(),
            "{change}"
        );
    }
}

#[test]
fn baseline_tampering_after_plan_is_refused_at_approval_without_resetting_accounting() {
    let fixture = Fixture::new();
    fixture.plan(fixture.input()).unwrap();
    let receipt = load_study_plan_receipt(fixture.root.path(), "candidate-study").unwrap();
    std::fs::write(
        fixture
            .root
            .path()
            .join(".kuzushi/v3/runs/baseline-run/scan-input.json"),
        "{}",
    )
    .unwrap();
    let ctx = context(&fixture.workspace, &fixture.config);
    let before = load_study_allowance(fixture.root.path(), &receipt).unwrap();
    let input = json!({"investigationId":"investigation","expectedRevision":1,"model":"openai-codex:gpt-5.5","maxProviderCalls":8,"protectedReviewCalls":2,"reason":"One candidate study",
        "campaignId":"candidate-study","campaignPlanSha256":receipt.plan_sha256,"campaignJobs":3,"maxJobAttempts":1});
    let prepared = fixture
        .registry
        .prepare_dispatch_input("campaign:approve-allowance", input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    assert!(fixture
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .is_err());
    assert_eq!(
        load_study_allowance(fixture.root.path(), &receipt).unwrap(),
        before
    );
}

#[test]
fn frozen_receipt_rejects_other_condition_changes_even_with_a_rehashed_key() {
    let fixture = Fixture::new();
    fixture.plan(fixture.input()).unwrap();
    let receipt = load_study_plan_receipt(fixture.root.path(), "candidate-study").unwrap();
    let experiment = load_study_context_experiment(fixture.root.path(), &receipt)
        .unwrap()
        .unwrap();
    for field in [
        "model",
        "runtime",
        "scope",
        "prompts",
        "engine",
        "source",
        "descriptors",
    ] {
        let mut changed = experiment.clone();
        let before = &mut changed.baseline.components;
        match field {
            "model" => before.model = Some("operator:changed".into()),
            "runtime" => before.runtime_identity.backend = "changed".into(),
            "scope" => before.scope_sha256 = "changed".into(),
            "prompts" => before.prompt_overrides_sha256 = "changed".into(),
            "engine" => before.engine_identity.kuzushi_version = "changed".into(),
            "source" => before.workspace_identity = "changed".into(),
            _ => before.descriptor_set_sha256 = "changed".into(),
        }
        changed.baseline.sha256 = batch::equivalence::digest_serializable(before).unwrap();
        assert!(
            conditions::validate(&changed, &receipt.scan_input, &receipt.equivalence).is_err(),
            "{field}"
        );
    }
}
