use super::*;
use crate::allowance::{AllowanceCall, AllowanceReferenceV1, InvestigationWork, WorkAttempt};
use crate::{runtime::RuntimeCostReport, SpendLimiter};

fn admitted_source(fixture: &ReviewedFindingFixture, run: &str) -> SpendLimiter {
    let ledger = SpendLimiter::open(fixture.workspace.findings_db_path()).unwrap();
    let approval = serde_json::from_value(json!({
        "schemaVersion": 1, "investigationId": "lesson-investigation", "expectedRevision": 0,
        "model": "openai-codex:gpt-5.5", "reason": "Owned accounting test, no model requests",
        "limits": {"maxProviderCalls": 6, "protectedReviewCalls": 1},
        "workPlan": {"schemaVersion": 1, "campaignId": "owned-plan", "planSha256": "a".repeat(64),
            "sourceIdentity": "owned-source", "configSha256": "b".repeat(64),
            "jobs": [{"workId": "owned:scan", "tool": "sast:scan", "inputSha256": "c".repeat(64), "maxAttempts": 1}]}
    })).unwrap();
    ledger.approve_allowance(&approval).unwrap();
    ledger
        .claim_work_attempt(&WorkAttempt {
            reference: &AllowanceReferenceV1 {
                schema_version: 1,
                investigation_id: "lesson-investigation".into(),
                revision: 1,
                work_id: "owned:scan".into(),
            },
            run_id: run,
            tool: "sast:scan",
            input_sha256: &"c".repeat(64),
            source_identity: "owned-source",
            config_sha256: &"b".repeat(64),
        })
        .unwrap();
    ledger
}

fn reserve(
    ledger: &SpendLimiter,
    run: &str,
    request: &str,
) -> crate::allowance::AllowanceReservation {
    ledger
        .reserve_provider_call(&AllowanceCall {
            investigation_id: "lesson-investigation".into(),
            expected_revision: 1,
            request_id: request.into(),
            run_id: run.into(),
            work_id: "owned:scan".into(),
            model: "openai-codex:gpt-5.5".into(),
            work: InvestigationWork::Discovery,
        })
        .unwrap()
}

#[test]
fn followup_preserves_spending_protected_calls_and_unresolved_reservations() {
    let fixture = ReviewedFindingFixture::new();
    let (reference, lesson) = context(&fixture);
    let run = lesson.origin.finding.run_id.unwrap();
    let ledger = admitted_source(&fixture, &run);
    ledger
        .settle_provider_call(
            reserve(&ledger, &run, "settled"),
            RuntimeCostReport::UNAVAILABLE,
        )
        .unwrap();
    let _unresolved = reserve(&ledger, &run, "canceled");
    let before = ledger.allowance_snapshot("lesson-investigation").unwrap();
    assert_eq!((before.committed_calls, before.unresolved_calls), (2, 1));
    let result = load_lesson_followup_context(fixture.workspace.root(), &reference, None).unwrap();
    assert_eq!(result.unaccounted_source_runs, 0);
    assert_eq!(result.allowance, Some(before.clone()));
    assert_eq!(
        ledger.allowance_snapshot("lesson-investigation").unwrap(),
        before
    );
}

#[test]
fn lost_recorded_approval_is_an_error_without_a_fresh_budget() {
    let fixture = ReviewedFindingFixture::new();
    let (reference, lesson) = context(&fixture);
    let ledger = admitted_source(&fixture, lesson.origin.finding.run_id.as_deref().unwrap());
    drop(ledger);
    let db = rusqlite::Connection::open(fixture.workspace.findings_db_path()).unwrap();
    db.pragma_update(None, "foreign_keys", false).unwrap();
    db.execute("delete from investigation_allowance_revisions", [])
        .unwrap();
    let error =
        load_lesson_followup_context(fixture.workspace.root(), &reference, None).unwrap_err();
    assert!(format!("{error:#}").contains("approval is missing"));
    assert_eq!(
        db.query_row(
            "select count(*) from investigation_allowance_revisions",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}
