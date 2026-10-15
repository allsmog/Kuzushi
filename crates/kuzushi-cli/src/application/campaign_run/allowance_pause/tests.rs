use super::*;
use kuzushi_core::allowance::{
    AllowanceApprovalV1, AllowanceCall, AllowanceLimits, ApprovedWorkItem, ApprovedWorkPlanV1,
    InvestigationWork, WorkAttempt,
};
use serde_json::json;

struct Fixture {
    root: tempfile::TempDir,
    ledger: SpendLimiter,
    approval: AllowanceApprovalV1,
    job: PlanJob,
}

impl Fixture {
    fn new(enrichment: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let input = json!({"enrichment":enrichment,"model":"openai-codex:gpt-5.5"});
        let work = ApprovedWorkItem {
            work_id: "pause:context-one".into(),
            tool: "context:build".into(),
            input_sha256: kuzushi_core::capabilities::campaign::work_input_digest(&input).unwrap(),
            max_attempts: 2,
        };
        let approval = AllowanceApprovalV1 {
            schema_version: 1,
            investigation_id: "bounded".into(),
            expected_revision: 0,
            model: "openai-codex:gpt-5.5".into(),
            reason: "Owned pause test; no provider requests".into(),
            limits: AllowanceLimits {
                max_provider_calls: 2,
                protected_review_calls: 1,
            },
            work_plan: Some(ApprovedWorkPlanV1 {
                schema_version: 1,
                campaign_id: "pause".into(),
                plan_sha256: format!("sha256:{}", "0".repeat(64)),
                source_identity: "owned-fixture".into(),
                config_sha256: format!("sha256:{}", "0".repeat(64)),
                jobs: vec![work],
            }),
        };
        let ledger = SpendLimiter::open(workspace.findings_db_path()).unwrap();
        ledger.approve_allowance(&approval).unwrap();
        let reference = AllowanceReferenceV1 {
            schema_version: 1,
            investigation_id: "bounded".into(),
            revision: 1,
            work_id: "pause:context-one".into(),
        };
        let plan = approval.work_plan.as_ref().unwrap();
        ledger
            .claim_work_attempt(&WorkAttempt {
                reference: &reference,
                run_id: "earlier-run",
                tool: "context:build",
                input_sha256: &plan.jobs[0].input_sha256,
                source_identity: &plan.source_identity,
                config_sha256: &plan.config_sha256,
            })
            .unwrap();
        ledger
            .reserve_provider_call(&AllowanceCall {
                investigation_id: "bounded".into(),
                expected_revision: 1,
                request_id: "unresolved-earlier-request".into(),
                run_id: "earlier-run".into(),
                work_id: reference.work_id.clone(),
                model: approval.model.clone(),
                work: InvestigationWork::Context,
            })
            .unwrap();
        let mut bound = input;
        bound["allowanceRef"] = serde_json::to_value(reference).unwrap();
        let job = PlanJob {
            job_id: "context-one".into(),
            tool: "context:build".into(),
            input_json: bound.to_string(),
            job_budget_usd: None,
            approved_attempts: Some(2),
        };
        Self {
            root,
            ledger,
            approval,
            job,
        }
    }

    fn dispatcher(&self) -> Dispatcher {
        let loaded = LoadedPlan {
            context_study: false,
            case_study: false,
            jobs: vec![self.job.clone()],
            batch_guard: None,
        };
        Dispatcher::open(
            self.root.path().to_path_buf(),
            "pause".into(),
            loaded,
            standard_batch_dispatch_settings(1).unwrap(),
        )
        .unwrap()
    }
}

#[tokio::test]
async fn exhausted_calls_park_work_before_any_new_job_attempt() {
    let fixture = Fixture::new(true);
    let mut dispatcher = fixture.dispatcher();
    assert!(dispatcher.next_job_for_dispatch().unwrap().is_none());
    let job = dispatcher.store.job("context-one").unwrap();
    assert_eq!(job.state, "parked");
    assert_eq!(job.reason.as_deref(), Some("allowance-exhausted"));
    assert_eq!((job.attempts, job.dispatches), (0, 0));
    let snapshot = fixture.ledger.allowance_snapshot("bounded").unwrap();
    assert_eq!(
        (
            snapshot.committed_calls,
            snapshot.unresolved_calls,
            snapshot.protected_review_remaining()
        ),
        (1, 1, 1)
    );
}

#[tokio::test]
async fn deterministic_work_can_continue_without_provider_capacity() {
    let fixture = Fixture::new(false);
    assert!(fixture
        .dispatcher()
        .next_job_for_dispatch()
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn a_stop_after_waiting_cannot_launch_or_consume_another_attempt() {
    let fixture = Fixture::new(false);
    let mut dispatcher = fixture.dispatcher();
    kuzushi_core::capabilities::campaign::request_campaign_dispatcher_stop(
        fixture.root.path(),
        "pause",
        std::process::id(),
    )
    .unwrap();
    assert!(dispatcher.next_job_for_dispatch().unwrap().is_none());
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        dispatcher.shutdown_rx.changed(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(dispatcher.next_job_for_dispatch().unwrap().is_none());
    let job = dispatcher.store.job("context-one").unwrap();
    assert_eq!((job.attempts, job.dispatches), (0, 0));
}

#[tokio::test]
async fn revised_allowance_waits_for_review_instead_of_spending_old_job_authority() {
    let mut fixture = Fixture::new(true);
    fixture.approval.expected_revision = 1;
    fixture.approval.limits.max_provider_calls = 3;
    fixture.ledger.approve_allowance(&fixture.approval).unwrap();
    let mut dispatcher = fixture.dispatcher();
    assert!(dispatcher.next_job_for_dispatch().unwrap().is_none());
    assert_eq!(
        dispatcher
            .store
            .job("context-one")
            .unwrap()
            .reason
            .as_deref(),
        Some("allowance-revised")
    );
}

#[tokio::test]
async fn missing_accounting_cannot_become_permission_to_start_a_job() {
    let fixture = Fixture::new(true);
    let mut dispatcher = fixture.dispatcher();
    let workspace = WorkspaceTarget::new(fixture.root.path()).unwrap();
    std::fs::rename(
        workspace.findings_db_path(),
        fixture.root.path().join("retained-ledger.sqlite3"),
    )
    .unwrap();
    assert!(dispatcher.next_job_for_dispatch().is_err());
    assert_eq!(dispatcher.store.job("context-one").unwrap().dispatches, 0);
}

#[tokio::test]
async fn specific_revision_releases_parked_work_with_its_original_attempt_limit() {
    let mut fixture = Fixture::new(true);
    assert!(fixture
        .dispatcher()
        .next_job_for_dispatch()
        .unwrap()
        .is_none());
    fixture.approval.expected_revision = 1;
    fixture.approval.limits.max_provider_calls = 3;
    fixture.ledger.approve_allowance(&fixture.approval).unwrap();
    let mut input: Value = serde_json::from_str(&fixture.job.input_json).unwrap();
    input["allowanceRef"]["revision"] = json!(2);
    fixture.job.input_json = input.to_string();
    let mut resumed = fixture.dispatcher();
    let job = resumed.next_job_for_dispatch().unwrap().unwrap();
    assert_eq!(job.approved_attempts, Some(2));
    assert_eq!(resumed.store.job("context-one").unwrap().dispatches, 0);
    let snapshot = fixture.ledger.allowance_snapshot("bounded").unwrap();
    assert_eq!(
        (snapshot.committed_calls, snapshot.unresolved_calls),
        (1, 1)
    );
}

#[tokio::test]
async fn approved_review_can_dispatch_using_its_protected_capacity() {
    let mut fixture = Fixture::new(true);
    let input = json!({"model":"openai-codex:gpt-5.5", "strategy":"standard"});
    fixture.approval.expected_revision = 1;
    let work = &mut fixture.approval.work_plan.as_mut().unwrap().jobs[0];
    work.work_id = "pause:review-one".into();
    work.tool = "triage:run".into();
    work.input_sha256 = kuzushi_core::capabilities::campaign::work_input_digest(&input).unwrap();
    fixture.ledger.approve_allowance(&fixture.approval).unwrap();
    let mut bound = input;
    bound["allowanceRef"] = json!({"schemaVersion":1,"investigationId":"bounded","revision":2,"workId":"pause:review-one"});
    fixture.job.job_id = "review-one".into();
    fixture.job.tool = "triage:run".into();
    fixture.job.input_json = bound.to_string();
    assert!(fixture
        .dispatcher()
        .next_job_for_dispatch()
        .unwrap()
        .is_some());
    let snapshot = fixture.ledger.allowance_snapshot("bounded").unwrap();
    assert_eq!(
        (
            snapshot.committed_calls,
            snapshot.protected_review_remaining()
        ),
        (1, 1)
    );
    fixture.job.tool = "threat-model:build".into();
    assert!(stop_reason(fixture.root.path(), "pause", &fixture.job).is_err());
}
