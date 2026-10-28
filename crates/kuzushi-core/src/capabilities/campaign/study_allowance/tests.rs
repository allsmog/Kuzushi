use super::*;
use crate::allowance::{
    AllowanceApprovalV1, AllowanceCall, AllowanceLimits, ApprovedWorkItem, ApprovedWorkPlanV1,
    InvestigationWork,
};
use crate::SpendLimiter;
use serde_json::json;

fn plan(root: &Path, id: &str, kind: &str) -> String {
    let value = json!({"schemaVersion":1,"campaignId":id,"kind":kind,"requiresWorkApproval":true,
        "investigationId":"shared","jobs":[{"jobId":"job","tool":"sast:scan","input":{}}]});
    let path = campaign_plan_path(root, id);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    batch::equivalence::digest_serializable(&value).unwrap()
}

fn approval(revision: u32, work: Option<ApprovedWorkPlanV1>) -> AllowanceApprovalV1 {
    AllowanceApprovalV1 {
        schema_version: 1,
        investigation_id: "shared".into(),
        expected_revision: revision,
        model: "operator:model".into(),
        limits: AllowanceLimits {
            max_provider_calls: 8,
            protected_review_calls: 2,
        },
        reason: "Offline accounting projection; no jobs executed".into(),
        work_plan: work,
    }
}

fn work(id: &str, digest: &str) -> ApprovedWorkPlanV1 {
    ApprovedWorkPlanV1 {
        schema_version: 1,
        campaign_id: id.into(),
        plan_sha256: digest.into(),
        source_identity: "owned-static-source".into(),
        config_sha256: "a".repeat(64),
        jobs: vec![ApprovedWorkItem {
            work_id: format!("{id}:job"),
            tool: "sast:scan".into(),
            input_sha256: "b".repeat(64),
            max_attempts: 1,
        }],
    }
}

fn ledger(root: &Path) -> SpendLimiter {
    let path = crate::WorkspaceTarget::new(root)
        .unwrap()
        .findings_db_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let ledger = SpendLimiter::open(path).unwrap();
    ledger.approve_allowance(&approval(0, None)).unwrap();
    drop(
        ledger
            .reserve_provider_call(&AllowanceCall {
                investigation_id: "shared".into(),
                expected_revision: 1,
                request_id: "interrupted-context".into(),
                run_id: "owned-run".into(),
                work_id: "context".into(),
                model: "operator:model".into(),
                work: InvestigationWork::Context,
            })
            .unwrap(),
    );
    ledger
}

#[test]
fn every_fixed_kind_keeps_shared_spending_after_later_work_replaces_the_current_plan() {
    let root = tempfile::tempdir().unwrap();
    let ledger = ledger(root.path());
    let mut saved = Vec::new();
    for (index, kind) in FIXED_KINDS.iter().enumerate() {
        let id = format!("study-{index}");
        let digest = plan(root.path(), &id, kind);
        ledger
            .approve_allowance(&approval(index as u32 + 1, Some(work(&id, &digest))))
            .unwrap();
        saved.push((id, digest));
    }
    for (id, digest) in saved {
        let snapshot = load_fixed_study_allowance(root.path(), &id, &digest)
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                snapshot.committed_calls,
                snapshot.unresolved_calls,
                snapshot.revision
            ),
            (1, 1, 6)
        );
        assert_eq!(snapshot.protected_review_remaining(), 2);
        assert!(snapshot.cost.is_unavailable());
        assert_eq!(snapshot.work_plan.unwrap().campaign_id, "study-4");
    }
}

#[test]
fn unapproved_draft_can_display_its_declared_shared_budget_without_approving_the_draft() {
    let root = tempfile::tempdir().unwrap();
    let ledger = ledger(root.path());
    let digest = plan(root.path(), "draft", SCAN_BATCH_KIND);
    let snapshot = load_fixed_study_allowance(root.path(), "draft", &digest)
        .unwrap()
        .unwrap();
    assert_eq!(
        (snapshot.committed_calls, snapshot.unresolved_calls),
        (1, 1)
    );
    assert!(snapshot.work_plan.is_none());
    assert!(SpendLimiter::read_campaign_allowance_report(
        &crate::WorkspaceTarget::new(root.path())
            .unwrap()
            .findings_db_path(),
        "draft"
    )
    .unwrap()
    .is_none());
    assert_eq!(ledger.allowance_snapshot("shared").unwrap(), snapshot);
}

#[test]
fn refreshed_changed_plan_never_borrows_its_old_approval_or_another_investigation() {
    let root = tempfile::tempdir().unwrap();
    let ledger = ledger(root.path());
    let original = plan(root.path(), "owned", SCAN_BATCH_KIND);
    ledger
        .approve_allowance(&approval(1, Some(work("owned", &original))))
        .unwrap();
    let path = campaign_plan_path(root.path(), "owned");
    let mut changed: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    changed["investigationId"] = json!("foreign");
    std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(load_fixed_study_allowance(root.path(), "owned", &original)
        .unwrap_err()
        .to_string()
        .contains("Study plan changed"));
    let digest = batch::equivalence::digest_serializable(&changed).unwrap();
    assert!(load_fixed_study_allowance(root.path(), "owned", &digest)
        .unwrap_err()
        .to_string()
        .contains("recorded work approval"));
    assert_eq!(
        ledger.allowance_snapshot("shared").unwrap().committed_calls,
        1
    );
}

#[test]
fn missing_malformed_oversized_and_unsupported_plans_fail_without_creating_a_ledger() {
    let root = tempfile::tempdir().unwrap();
    assert!(load_fixed_study_allowance(root.path(), "../outside", "a").is_err());
    assert!(load_fixed_study_allowance(root.path(), "missing", "a").is_err());
    let digest = plan(root.path(), "legacy", "campaign");
    assert!(load_fixed_study_allowance(root.path(), "legacy", &digest).is_err());
    let path = campaign_plan_path(root.path(), "legacy");
    std::fs::write(&path, b"{not valid JSON").unwrap();
    assert!(load_fixed_study_allowance(root.path(), "legacy", &digest).is_err());
    std::fs::write(&path, vec![b' '; 4 * 1024 * 1024 + 1]).unwrap();
    assert!(load_fixed_study_allowance(root.path(), "legacy", &digest).is_err());
    assert!(!crate::WorkspaceTarget::new(root.path())
        .unwrap()
        .findings_db_path()
        .exists());
    assert!(!is_fixed_study_kind(None));
}

#[cfg(unix)]
#[test]
fn symlinked_plan_or_campaign_directory_is_rejected_even_with_matching_content() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let digest = plan(root.path(), "owned", SCAN_BATCH_KIND);
    let path = campaign_plan_path(root.path(), "owned");
    let copy = outside.path().join("plan.json");
    std::fs::copy(&path, &copy).unwrap();
    std::fs::remove_file(&path).unwrap();
    symlink(&copy, &path).unwrap();
    assert!(load_fixed_study_allowance(root.path(), "owned", &digest).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(path.parent().unwrap()).unwrap();
    symlink(outside.path(), path.parent().unwrap()).unwrap();
    assert!(load_fixed_study_allowance(root.path(), "owned", &digest).is_err());
}
