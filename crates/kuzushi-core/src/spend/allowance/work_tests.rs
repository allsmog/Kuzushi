use super::*;
use crate::SpendLimiter;

pub(super) fn approval() -> AllowanceApprovalV1 {
    AllowanceApprovalV1 {
        schema_version: 1,
        investigation_id: "study".into(),
        expected_revision: 0,
        model: "openai-codex:gpt-5.5".into(),
        limits: AllowanceLimits {
            max_provider_calls: 9,
            protected_review_calls: 3,
        },
        reason: "Offline finite work test".into(),
        work_plan: Some(ApprovedWorkPlanV1 {
            schema_version: 1,
            campaign_id: "batch".into(),
            plan_sha256: "a".repeat(64),
            source_identity: "git:commit;tree:dirty-content".into(),
            config_sha256: "b".repeat(64),
            jobs: (1..=3)
                .map(|n| ApprovedWorkItem {
                    work_id: format!("batch:trial-{n:03}"),
                    tool: "sast:scan".into(),
                    input_sha256: "c".repeat(64),
                    max_attempts: 1,
                })
                .collect(),
        }),
    }
}

pub(super) fn reference() -> AllowanceReferenceV1 {
    AllowanceReferenceV1 {
        schema_version: 1,
        investigation_id: "study".into(),
        revision: 1,
        work_id: "batch:trial-001".into(),
    }
}

pub(super) fn claim(
    ledger: &SpendLimiter,
    reference: &AllowanceReferenceV1,
    run: &str,
) -> anyhow::Result<()> {
    ledger.claim_work_attempt(&WorkAttempt {
        reference,
        run_id: run,
        tool: "sast:scan",
        input_sha256: &"c".repeat(64),
        source_identity: "git:commit;tree:dirty-content",
        config_sha256: &"b".repeat(64),
    })
}

#[test]
fn finite_jobs_refuse_unknown_work_and_unadmitted_provider_requests() {
    let ledger = SpendLimiter::open_in_memory().unwrap();
    ledger.approve_allowance(&approval()).unwrap();
    let mut reference = reference();
    reference.work_id = "batch:trial-004".into();
    assert!(claim(&ledger, &reference, "run-4").is_err());
    let call = AllowanceCall {
        investigation_id: "study".into(),
        expected_revision: 1,
        request_id: "request".into(),
        run_id: "run-1".into(),
        work_id: "batch:trial-001".into(),
        model: approval().model,
        work: InvestigationWork::Discovery,
    };
    assert!(ledger.reserve_provider_call(&call).is_err());
    claim(&ledger, &self::reference(), "run-1").unwrap();
    ledger.reserve_provider_call(&call).unwrap();
    assert!(ledger
        .reserve_provider_call(&AllowanceCall {
            request_id: "review".into(),
            work: InvestigationWork::Review,
            ..call
        })
        .is_err());
}

#[test]
fn attempts_remain_consumed_after_cancellation_and_restart() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ledger.db");
    let ledger = SpendLimiter::open(&path).unwrap();
    ledger.approve_allowance(&approval()).unwrap();
    claim(&ledger, &reference(), "started-then-canceled").unwrap();
    drop(ledger);
    let resumed = SpendLimiter::open(&path).unwrap();
    assert!(claim(&resumed, &reference(), "new-run").is_err());
    assert!(claim(&resumed, &reference(), "started-then-canceled").is_err());
    let snapshot = SpendLimiter::read_campaign_allowance(&path, "batch")
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.work_plan.unwrap().jobs.len(), 3);
    assert_eq!(snapshot.committed_calls, 0);
}

#[test]
fn independent_workers_cannot_start_the_same_last_attempt() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ledger.db");
    SpendLimiter::open(&path)
        .unwrap()
        .approve_allowance(&approval())
        .unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|n| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let ledger = SpendLimiter::open(path).unwrap();
                barrier.wait();
                claim(&ledger, &reference(), &format!("run-{n}")).is_ok()
            })
        })
        .collect();
    let admitted = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .filter(|value| *value)
        .count();
    assert_eq!(admitted, 1);
}

#[test]
fn explicit_revision_can_add_attempts_but_cannot_reset_or_repurpose_work() {
    let ledger = SpendLimiter::open_in_memory().unwrap();
    ledger.approve_allowance(&approval()).unwrap();
    claim(&ledger, &reference(), "run-1").unwrap();
    let mut changed = approval();
    changed.expected_revision = 1;
    changed.work_plan = None;
    assert!(ledger.approve_allowance(&changed).is_err());
    changed.work_plan = approval().work_plan;
    changed.work_plan.as_mut().unwrap().jobs[0].max_attempts = 2;
    ledger.approve_allowance(&changed).unwrap();
    let mut reference = reference();
    assert!(claim(&ledger, &reference, "stale-revision").is_err());
    reference.revision = 2;
    claim(&ledger, &reference, "run-2").unwrap();
    assert!(claim(&ledger, &reference, "run-3").is_err());
    changed.expected_revision = 2;
    changed.work_plan.as_mut().unwrap().jobs[0].max_attempts = 1;
    assert!(ledger.approve_allowance(&changed).is_err());
    changed.work_plan.as_mut().unwrap().jobs[0].max_attempts = 2;
    changed.work_plan.as_mut().unwrap().source_identity = "git:another;tree:new".into();
    assert!(ledger.approve_allowance(&changed).is_err());
}

#[test]
fn campaign_ownership_and_finite_plan_shape_are_validated_before_approval() {
    let ledger = SpendLimiter::open_in_memory().unwrap();
    ledger.approve_allowance(&approval()).unwrap();
    let mut changed = approval();
    changed.investigation_id = "another-study".into();
    assert!(ledger.approve_allowance(&changed).is_err());
    for size in [0, 101] {
        let mut invalid = approval();
        let plan = invalid.work_plan.as_mut().unwrap();
        plan.jobs = vec![plan.jobs[0].clone(); size];
        assert!(SpendLimiter::open_in_memory()
            .unwrap()
            .approve_allowance(&invalid)
            .is_err());
    }
    let mut duplicate = approval();
    let plan = duplicate.work_plan.as_mut().unwrap();
    plan.jobs[1] = plan.jobs[0].clone();
    assert!(SpendLimiter::open_in_memory()
        .unwrap()
        .approve_allowance(&duplicate)
        .is_err());
}

#[test]
fn changed_input_configuration_or_dirty_source_does_not_consume_an_attempt() {
    let ledger = SpendLimiter::open_in_memory().unwrap();
    ledger.approve_allowance(&approval()).unwrap();
    let reference = reference();
    let digest = "c".repeat(64);
    let mut attempt = WorkAttempt {
        reference: &reference,
        run_id: "run",
        tool: "sast:scan",
        input_sha256: &"c".repeat(64),
        source_identity: "git:commit;tree:changed",
        config_sha256: &"b".repeat(64),
    };
    assert!(ledger.claim_work_attempt(&attempt).is_err());
    attempt.source_identity = "git:commit;tree:dirty-content";
    attempt.tool = "report:build";
    assert!(ledger.claim_work_attempt(&attempt).is_err());
    attempt.tool = "sast:scan";
    attempt.input_sha256 = "changed";
    assert!(ledger.claim_work_attempt(&attempt).is_err());
    attempt.input_sha256 = &digest;
    attempt.config_sha256 = "changed";
    assert!(ledger.claim_work_attempt(&attempt).is_err());
    claim(&ledger, &reference, "run").unwrap();
}

#[test]
fn fixed_work_preflight_uses_approved_categories_without_reserving_calls() {
    let ledger = SpendLimiter::open_in_memory().unwrap();
    ledger.approve_allowance(&approval()).unwrap();
    let mut snapshot = ledger.allowance_snapshot("study").unwrap();
    snapshot.committed_calls = 6;
    for tool in [
        "sast:scan",
        "context:build",
        "threat-model:build",
        "findings:lesson-generate",
        "triage:run",
    ] {
        snapshot.work_plan.as_mut().unwrap().jobs[0].tool = tool.into();
        assert_eq!(
            snapshot
                .require_work_call_capacity("batch:trial-001", tool)
                .is_ok(),
            tool == "triage:run",
            "{tool}"
        );
    }
    assert!(snapshot
        .require_work_call_capacity("unknown", "triage:run")
        .is_err());
    assert!(snapshot
        .require_work_call_capacity("batch:trial-001", "sast:scan")
        .is_err());
    snapshot.work_plan = None;
    assert!(snapshot
        .require_work_call_capacity("batch:trial-001", "triage:run")
        .is_err());
    assert_eq!(
        ledger.allowance_snapshot("study").unwrap().committed_calls,
        0
    );
}
