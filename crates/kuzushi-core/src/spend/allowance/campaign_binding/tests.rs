use super::*;
use crate::allowance::{
    AllowanceCall, AllowanceLimits, ApprovedWorkItem, ApprovedWorkPlanV1, InvestigationWork,
};

const MODEL: &str = "openai-codex:gpt-5.5";

fn approval(revision: u32, campaign: Option<&str>) -> AllowanceApprovalV1 {
    AllowanceApprovalV1 {
        schema_version: 1,
        investigation_id: "investigation".into(),
        expected_revision: revision,
        model: MODEL.into(),
        reason: "Offline report history test".into(),
        limits: AllowanceLimits {
            max_provider_calls: 5,
            protected_review_calls: 2,
        },
        work_plan: campaign.map(|id| ApprovedWorkPlanV1 {
            schema_version: 1,
            campaign_id: id.into(),
            plan_sha256: "a".repeat(64),
            source_identity: "recorded-source".into(),
            config_sha256: "b".repeat(64),
            jobs: vec![ApprovedWorkItem {
                work_id: format!("{id}:job"),
                tool: "sast:scan".into(),
                input_sha256: "c".repeat(64),
                max_attempts: 1,
            }],
        }),
    }
}

#[test]
fn historical_reporting_keeps_current_consumption_without_reauthorizing_old_work() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ledger.db");
    let ledger = SpendLimiter::open(&path).unwrap();
    ledger.approve_allowance(&approval(0, None)).unwrap();
    ledger
        .reserve_provider_call(&AllowanceCall {
            investigation_id: "investigation".into(),
            expected_revision: 1,
            request_id: "context-call".into(),
            run_id: "context-run".into(),
            work_id: "context".into(),
            model: MODEL.into(),
            work: InvestigationWork::Context,
        })
        .unwrap();
    ledger
        .approve_allowance(&approval(1, Some("old-study")))
        .unwrap();
    let reference = crate::allowance::AllowanceReferenceV1 {
        schema_version: 1,
        investigation_id: "investigation".into(),
        revision: 2,
        work_id: "old-study:job".into(),
    };
    ledger
        .claim_work_attempt(&crate::allowance::WorkAttempt {
            reference: &reference,
            run_id: "scan-run",
            tool: "sast:scan",
            input_sha256: &"c".repeat(64),
            source_identity: "recorded-source",
            config_sha256: &"b".repeat(64),
        })
        .unwrap();
    ledger
        .approve_allowance(&approval(2, Some("new-study")))
        .unwrap();
    let report = SpendLimiter::read_campaign_allowance_report(&path, "old-study")
        .unwrap()
        .unwrap();
    let serialized = serde_json::to_value(&report).unwrap();
    assert!(serialized["currentInvestigation"]["cost"]["observedUsd"].is_null());
    assert_eq!(report.approved_revision, 2);
    assert_eq!(report.approval.work_plan.unwrap().campaign_id, "old-study");
    assert_eq!(report.current_investigation.revision, 3);
    assert_eq!(
        (
            report.current_investigation.committed_calls,
            report.current_investigation.unresolved_calls
        ),
        (1, 1)
    );
    assert!(report.current_investigation.cost.is_unavailable());
    let value = serde_json::to_value(&report.current_investigation).unwrap();
    assert_eq!(value["cost"]["completeness"], "unavailable");
    assert!(SpendLimiter::read_campaign_allowance(&path, "old-study").is_err());
    assert_eq!(
        SpendLimiter::read_run_campaign_report(&path, "scan-run")
            .unwrap()
            .as_deref(),
        Some("old-study")
    );
    assert!(
        SpendLimiter::read_campaign_allowance_report(&path, "missing")
            .unwrap()
            .is_none()
    );
}
