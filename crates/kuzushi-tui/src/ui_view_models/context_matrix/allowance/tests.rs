use super::*;
use kuzushi_core::allowance::AllowanceLimits;
use kuzushi_core::runtime::RuntimeCost;

fn snapshot() -> AllowanceSnapshot {
    AllowanceSnapshot {
        schema_version: 1,
        investigation_id: "owned".into(),
        revision: 2,
        model: "operator:model".into(),
        limits: AllowanceLimits {
            max_provider_calls: 7,
            protected_review_calls: 2,
        },
        committed_calls: 5,
        review_calls: 0,
        unresolved_calls: 1,
        cost: RuntimeCostReport::UNAVAILABLE,
        work_plan: None,
    }
}

#[test]
fn compact_spending_keeps_capacity_and_unknown_cost_without_inventing_zero() {
    for width in [36, 56, 76, 92, 116, 156] {
        let rows = present(&snapshot(), width);
        assert_eq!(rows.len(), if width < 72 { 3 } else { 2 });
        assert!(rows.join(" · ").contains("Calls 5/7 · Review 2 protected"));
        assert!(rows.last().unwrap().contains("1 unsettled"));
        assert!(!rows.join(" ").contains("$0"));
        assert!(rows
            .iter()
            .all(|row| unicode_width::UnicodeWidthStr::width(row.as_str()) <= width));
    }
}

#[test]
fn narrow_cost_labels_preserve_exact_estimated_partial_and_unknown_distinctions() {
    let cost = RuntimeCost::from_usd(0.25, "owned test cost").unwrap();
    for (value, label) in [
        (RuntimeCostReport::UNAVAILABLE, "cost unknown"),
        (RuntimeCostReport::known(cost), "$0.2500 exact"),
        (RuntimeCostReport::incomplete(cost), "cost incomplete"),
        (
            RuntimeCostReport::incomplete(cost).with_unmetered_estimate(Some(cost)),
            "cost estimated",
        ),
    ] {
        assert_eq!(compact_cost(value), label);
        let mut snapshot = snapshot();
        snapshot.cost = value;
        assert!(present(&snapshot, 36).last().unwrap().contains(label));
    }
}

#[test]
fn maximum_valid_allowances_keep_exact_counts_at_40_columns() {
    let mut snapshot = snapshot();
    snapshot.limits.max_provider_calls = 1_000_000;
    snapshot.limits.protected_review_calls = 500_000;
    snapshot.committed_calls = 500_000;
    snapshot.unresolved_calls = 500_000;
    let rows = present(&snapshot, 36);
    assert_eq!(
        rows,
        [
            "Calls 500000/1000000",
            "Review 500000 protected",
            "500000 unsettled · cost unknown"
        ]
    );
    assert!(rows
        .iter()
        .all(|row| unicode_width::UnicodeWidthStr::width(row.as_str()) <= 36));
}
