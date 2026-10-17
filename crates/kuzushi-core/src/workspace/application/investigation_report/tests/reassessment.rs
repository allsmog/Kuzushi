use super::*;
use crate::findings::{ReviewDecision, ReviewDecisionVerdict, TriageAuthor};

fn observation(rule: &str) -> Finding {
    Finding::new_tool(
        "owned-policy",
        rule,
        "hello.txt",
        1,
        None,
        crate::Severity::Info,
        rule,
    )
}

#[test]
fn reobserved_unversioned_decision_is_counted_separately_from_unreviewed_findings() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("before", target.path(), "scan")
        .unwrap();
    let finding = observation("reviewed-marker");
    let id = store.insert_finding("before", &finding).unwrap();
    store
        .insert_finding("before", &observation("unreviewed-marker"))
        .unwrap();
    store
        .append_user_review_decision(
            id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "Confirmed only the owned literal marker".into(),
                dismiss_reason: None,
                actor: Some("operator".into()),
            },
        )
        .unwrap();
    let before = collect_evidence(&workspace, &store, &["before".into()]).unwrap();
    assert_eq!(
        (
            before.finding_count,
            before.reviewed_count,
            before.confirmed_count,
            before.reassessment_required_count
        ),
        (2, 1, 1, 0)
    );
    assert_eq!(before.review_decision_counts.confirmed, 1);
    store
        .record_run_started("after", target.path(), "scan")
        .unwrap();
    store.insert_finding("after", &finding).unwrap();
    let after = collect_evidence(&workspace, &store, &["before".into(), "after".into()]).unwrap();
    assert_eq!(
        (
            after.finding_count,
            after.reviewed_count,
            after.confirmed_count,
            after.reassessment_required_count
        ),
        (2, 0, 0, 1)
    );
    assert_eq!(after.review_decision_counts.total(), 0);
    assert_eq!(
        serde_json::to_value(after).unwrap()["reassessmentRequiredCount"],
        1
    );
    assert_eq!(store.list_all_review_decisions().unwrap().len(), 1);
}
