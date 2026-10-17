use super::*;
use kuzushi_core::{allowance::AllowanceLimits, runtime::RuntimeCostReport};

#[test]
fn shared_usage_discloses_protected_capacity_unsettled_calls_and_unknown_dollars() {
    let snapshot = AllowanceSnapshot {
        schema_version: 1,
        investigation_id: "owned".into(),
        revision: 3,
        model: "operator:model".into(),
        limits: AllowanceLimits {
            max_provider_calls: 6,
            protected_review_calls: 2,
        },
        committed_calls: 4,
        review_calls: 0,
        unresolved_calls: 1,
        cost: RuntimeCostReport::UNAVAILABLE,
        work_plan: None,
    };
    let model = present(&snapshot);
    assert_eq!(model.calls, "calls 4/6");
    assert!(model.rows.contains(&"2 Review protected".into()));
    assert!(model.rows.contains(&"0 other calls left".into()));
    assert!(model.rows.contains(&"1 unsettled".into()));
    assert!(model.rows.contains(&"Ledger at last read".into()));
    assert!(model
        .rows
        .iter()
        .any(|row| row.contains("cost not recorded")));
    assert!(!model.rows.iter().any(|row| row.contains("$0")));
}
