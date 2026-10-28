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

#[test]
fn maximum_review_reserve_keeps_a_complete_cost_state_in_a_40_column_summary() {
    use kuzushi_core::runtime::RuntimeCost;
    let cost = RuntimeCost::from_usd(100_000_000.25, "owned test cost").unwrap();
    for report in [
        RuntimeCostReport::UNAVAILABLE,
        RuntimeCostReport::known(cost),
        RuntimeCostReport::incomplete(cost),
        RuntimeCostReport::incomplete(cost).with_unmetered_estimate(Some(cost)),
    ] {
        let snapshot = AllowanceSnapshot {
            schema_version: 1,
            investigation_id: "owned".into(),
            revision: 1,
            model: "operator:model".into(),
            limits: AllowanceLimits {
                max_provider_calls: 1_000_000,
                protected_review_calls: 1_000_000,
            },
            committed_calls: 0,
            review_calls: 0,
            unresolved_calls: 0,
            cost: report,
            work_plan: None,
        };
        let model = present(&snapshot);
        assert!(model.summary.starts_with("1000000 Review protected"));
        assert!(
            unicode_width::UnicodeWidthStr::width(model.summary.as_str()) <= 40,
            "{}",
            model.summary
        );
    }
}
