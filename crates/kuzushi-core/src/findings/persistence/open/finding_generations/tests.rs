use super::*;
use crate::findings::{EffectiveReviewStateIndex, IdentityFoldPolicy, ReviewDecisionVerdict};

#[test]
fn operator_projection_uses_current_observation_and_keeps_local_review_and_sources() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("lib.rs"), "fn candidate() {}\n").unwrap();
    let store = FindingStore::open(&temp.path().join(".kuzushi/v3/index.sqlite3")).unwrap();
    let mut finding = Finding::new_tool(
        "audit",
        "rule",
        "lib.rs",
        1,
        None,
        Severity::High,
        "older high candidate",
    );
    store
        .record_run_started("older", temp.path(), "running")
        .unwrap();
    let older_id = store.insert_finding("older", &finding).unwrap();
    finding.severity = Severity::Medium;
    finding.message = "current medium candidate".to_string();
    store
        .record_run_started("current", temp.path(), "running")
        .unwrap();
    let current_id = store.insert_finding("current", &finding).unwrap();
    assert_ne!(older_id, current_id);
    assert!(store
        .record_auto_triage_locally(
            current_id,
            &TriageOutcome {
                verdict: TriageVerdict::FalsePositive,
                confidence: 0.8,
                rationale: "no reachable sink in this source".to_string(),
                ..TriageOutcome::default()
            }
        )
        .unwrap());
    let headless = store.list_all_findings().unwrap();
    assert_eq!(headless.len(), 1);
    assert_eq!(headless[0].id, Some(current_id));
    for policy in [
        IdentityFoldPolicy::Safe,
        IdentityFoldPolicy::Legacy,
        IdentityFoldPolicy::Aggressive,
    ] {
        let projected = store
            .list_relevant_findings_with_identity_policy(policy)
            .unwrap();
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].id, Some(current_id), "{policy:?}");
        assert_eq!(projected[0].severity, Severity::Medium);
        assert_eq!(projected[0].message, "current medium candidate");
        assert_eq!(projected[0].sources.len(), 2);
        let records = store
            .list_review_decisions_for_findings(&projected)
            .unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].identity_id.is_none());
        let index = EffectiveReviewStateIndex::from_findings_and_decisions(&projected, &records);
        assert_eq!(
            index
                .effective_decision_for(&projected[0])
                .unwrap()
                .verdict(),
            ReviewDecisionVerdict::RejectedFalsePositive
        );
        let generations = store.list_emitted_finding_generations().unwrap();
        assert_eq!(generations.len(), 2);
        assert_eq!(
            generations[0].id,
            Some(older_id),
            "audit reader retains severity order"
        );
        assert!(index.effective_decision_for(&generations[0]).is_none());
    }
}
