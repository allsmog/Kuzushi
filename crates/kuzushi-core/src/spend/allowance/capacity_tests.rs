use super::*;
use crate::runtime::RuntimeCostReport;

#[test]
fn available_capacity_keeps_review_protected_as_calls_are_consumed() {
    for (committed, review, expected) in [
        (0, 0, 3),
        (2, 0, 1),
        (3, 0, 0),
        (4, 1, 0),
        (3, 2, 2),
        (4, 3, 1),
        (5, 2, 0),
        (7, 3, 0),
    ] {
        let snapshot = AllowanceSnapshot {
            schema_version: 1,
            investigation_id: "owned".into(),
            revision: 1,
            model: "openai-codex:gpt-5.5".into(),
            limits: AllowanceLimits {
                max_provider_calls: 5,
                protected_review_calls: 2,
            },
            committed_calls: committed,
            review_calls: review,
            unresolved_calls: committed,
            cost: RuntimeCostReport::UNAVAILABLE,
            work_plan: None,
        };
        assert_eq!(snapshot.non_review_remaining(), expected);
    }
}
