use super::*;
use kuzushi_core::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::json;

struct Fixture {
    root: tempfile::TempDir,
    config: V2Config,
    workspace: WorkspaceTarget,
    registry: ModuleRegistry,
    receipt: kuzushi_core::capabilities::campaign::ContextMatrixReceipt,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("main.rs"),
            "// Owned source, never executed\nfn main() {}\n",
        )
        .unwrap();
        let config = V2Config {
            model: Some("openai-codex:gpt-5.5".into()),
            ..V2Config::default()
        };
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let cases = labeled_context_cases(&registry, &ctx);
        registry.execute_tool("campaign:study",json!({"campaignId":"matrix","investigationId":"accounting",
            "baselineCaseId":"baseline","contextCases":cases,"scanInput":{"taskMode":"manual","tasks":["secret-scan"]}}),&ctx).unwrap();
        let receipt = kuzushi_core::capabilities::campaign::load_context_matrix_receipt(
            root.path(),
            "matrix",
        )
        .unwrap();
        Self {
            root,
            config,
            workspace,
            registry,
            receipt,
        }
    }

    fn approve(&self) {
        let ctx = ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let input = json!({"investigationId":"accounting","expectedRevision":0,"model":"openai-codex:gpt-5.5",
            "maxProviderCalls":8,"protectedReviewCalls":2,"reason":"Owned matrix dispatcher fixture",
            "campaignId":"matrix","campaignPlanSha256":self.receipt.plan_sha256,"campaignJobs":6,"maxJobAttempts":1});
        let prepared = self
            .registry
            .prepare_dispatch_input("campaign:approve-allowance", input, &ctx, None)
            .unwrap()
            .authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
            .unwrap();
    }
}

fn labeled_context_cases(registry: &ModuleRegistry, ctx: &ToolExecutionContext<'_>) -> Vec<Value> {
    let mut cases = Vec::new();
    for id in ["baseline", "candidate"] {
        let imported = registry
            .execute_tool(
                "threat-model:import",
                json!({"label":id,"activate":true,
            "document":{"version":"1","methodology":"stride","title":id,"systemContext":id,
                "dfd":{"nodes":[{"id":"app","name":id,"type":"process","trustZone":"internal"}],
                    "flows":[],"trustBoundaries":[]},"threats":[],"summary":{}}}),
                ctx,
            )
            .unwrap();
        cases.push(json!({"id":id,"label":id,"threatModelRef":imported["data"]["modelRef"]}));
    }
    cases
}

#[test]
fn dispatcher_keeps_matrix_jobs_workers_source_and_shared_approval_frozen() {
    let fixture = Fixture::new();
    assert!(load_plan_jobs(fixture.root.path(), "matrix", &[]).is_err());
    fixture.approve();
    let loaded = load_plan_jobs(fixture.root.path(), "matrix", &[]).unwrap();
    assert!(loaded.case_study);
    assert_eq!(loaded.jobs.len(), 6);
    assert_eq!(loaded.batch_guard.as_ref().unwrap().effective_workers, 1);
    assert!(authorize_loaded_plan(&loaded, DispatchAuthority::PublicCampaign, "matrix").is_ok());
    let settings = standard_batch_dispatch_settings(1).unwrap();
    assert!(enforce_scan_batch_worker_boundary(&loaded, &settings).is_ok());
    let other = standard_batch_dispatch_settings(2).unwrap();
    assert!(enforce_scan_batch_worker_boundary(&loaded, &other).is_err());
    assert!(load_plan_jobs(
        fixture.root.path(),
        "matrix",
        &["baseline-trial-001".into()]
    )
    .is_err());
    for job in &loaded.jobs {
        assert_eq!(job.approved_attempts, Some(1));
        let input: Value = serde_json::from_str(&job.input_json).unwrap();
        assert_eq!(input["allowanceRef"]["investigationId"], "accounting");
        assert_eq!(
            input["allowanceRef"]["workId"],
            format!("matrix:{}", job.job_id)
        );
    }
    assert!(!fixture
        .root
        .path()
        .join(".kuzushi/v3/campaigns/matrix/queue.json")
        .exists());
}

#[test]
fn invalid_matrix_and_changed_approval_are_rejected_before_queue_creation() {
    let fixture = Fixture::new();
    fixture.approve();
    let path = fixture.receipt.plan_path.clone();
    let mut plan = kuzushi_core::capabilities::campaign::read_campaign_plan_document(
        fixture.root.path(),
        "matrix",
    )
    .unwrap();
    plan["contextMatrix"]["cases"][1]["label"] = json!("Changed after approval");
    std::fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
    assert!(load_plan_jobs(fixture.root.path(), "matrix", &[]).is_err());
    plan["jobs"].as_array_mut().unwrap().pop();
    std::fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
    assert!(load_plan_jobs(fixture.root.path(), "matrix", &[]).is_err());
    assert!(!fixture
        .root
        .path()
        .join(".kuzushi/v3/campaigns/matrix/queue.json")
        .exists());
}

#[tokio::test]
async fn finishing_an_unstarted_matrix_does_not_publish_scan_coverage() {
    let fixture = Fixture::new();
    fixture.approve();
    let loaded = load_plan_jobs(fixture.root.path(), "matrix", &[]).unwrap();
    let dispatcher = Dispatcher::open(
        fixture.root.path().to_path_buf(),
        "matrix".into(),
        loaded,
        standard_batch_dispatch_settings(1).unwrap(),
    )
    .unwrap();
    assert!(dispatcher.finish().is_err());
    assert!(
        kuzushi_core::workflow_attempts::load_phase_attempt_events(fixture.root.path())
            .unwrap()
            .is_empty()
    );
    let queue: Value = serde_json::from_slice(
        &std::fs::read(campaign_dir(fixture.root.path(), "matrix").join("queue.json")).unwrap(),
    )
    .unwrap();
    assert!(queue["jobs"]
        .as_object()
        .unwrap()
        .values()
        .all(|job| job["state"] == "planned" && job["attempts"] == 0));
}
