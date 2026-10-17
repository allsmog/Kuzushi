use super::*;
use crate::findings::{ReviewDecision, ReviewDecisionVerdict, TriageAuthor};

#[test]
fn report_evidence_counts_source_applicable_decisions_without_rewriting_severity() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("owned", target.path(), "scan")
        .unwrap();
    for (index, verdict) in [
        ReviewDecisionVerdict::Confirmed,
        ReviewDecisionVerdict::ToFix,
        ReviewDecisionVerdict::RejectedFalsePositive,
        ReviewDecisionVerdict::Deferred,
        ReviewDecisionVerdict::AcceptedRisk,
        ReviewDecisionVerdict::Suppressed,
        ReviewDecisionVerdict::NeedsReview,
    ]
    .into_iter()
    .enumerate()
    {
        let finding = Finding::new_tool(
            "owned",
            &format!("rule-{index}"),
            "note.txt",
            1,
            None,
            crate::Severity::High,
            "Owned policy observation",
        );
        let id = store.insert_finding("owned", &finding).unwrap();
        store
            .append_user_review_decision(
                id,
                &ReviewDecision {
                    verdict,
                    author: TriageAuthor::Human,
                    confidence: 1.0,
                    rationale: "Owned report decision".into(),
                    dismiss_reason: None,
                    actor: Some("operator".into()),
                },
            )
            .unwrap();
    }
    let report = collect_evidence(&workspace, &store, &["owned".into()]).unwrap();
    assert_eq!(
        (
            report.finding_count,
            report.reviewed_count,
            report.confirmed_count
        ),
        (7, 6, 2)
    );
    assert_eq!(report.review_decision_counts.total(), 6);
    let history = crate::workspace::load_workspace_review_summary(&workspace, None).unwrap();
    assert_eq!(history.finding_count, 7);
    assert_eq!(history.decisions, report.review_decision_counts);
    let wire = serde_json::to_value(report).unwrap();
    assert_eq!(
        wire["reviewDecisionCounts"],
        json!({"confirmed":1,"toFix":1,
        "rejectedFalsePositive":1,"deferred":1,"acceptedRisk":1,"suppressed":1})
    );
    let findings = store
        .list_distinct_findings_for_scan_ids_with_identity_policy(
            &["owned"],
            crate::findings::IdentityFoldPolicy::UNRESOLVED_RUN_SCOPE,
        )
        .unwrap();
    assert!(findings
        .iter()
        .all(|finding| finding.severity == crate::Severity::High));
    store
        .record_run_started("later", target.path(), "scan")
        .unwrap();
    let reobserved = Finding::new_tool(
        "owned",
        "rule-2",
        "note.txt",
        1,
        None,
        crate::Severity::High,
        "Owned policy observation",
    );
    store.insert_finding("later", &reobserved).unwrap();
    let later = collect_evidence(&workspace, &store, &["owned".into(), "later".into()]).unwrap();
    assert_eq!(later.finding_count, 7);
    assert_eq!(later.review_decision_counts.rejected_false_positive, 0);
    assert_eq!(later.review_decision_counts.total(), 5);
    assert_eq!(store.list_all_review_decisions().unwrap().len(), 7);
}
