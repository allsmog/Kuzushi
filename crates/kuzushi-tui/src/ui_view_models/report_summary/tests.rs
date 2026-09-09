use super::*;
use kuzushi_core::runtime::{RuntimeCost, RuntimeCostReport};
use kuzushi_core::{RunSummary, RunSummaryIssue};

fn entry(id: &str, cost: RuntimeCostReport) -> RunSummaryEntry {
    RunSummaryEntry {
        run_id: id.to_string(),
        path: format!("/unused/{id}").into(),
        state: RunSummaryEntryState::Ready(
            RunSummary::running(id, "module", None, "target").with_cost_report(cost),
        ),
    }
}

#[test]
fn report_cost_coverage_keeps_unknown_cost_distinct_from_exact_zero() {
    let entries = vec![
        entry("exact-zero", RuntimeCostReport::known(RuntimeCost::ZERO)),
        entry("observed-zero", RuntimeCostReport::INCOMPLETE_ZERO),
        entry("unknown", RuntimeCostReport::UNAVAILABLE),
        RunSummaryEntry {
            run_id: "missing".into(),
            path: "/unused/missing".into(),
            state: RunSummaryEntryState::Issue(RunSummaryIssue::MissingMetadata),
        },
    ];
    assert_eq!(
        cost_coverage(&entries),
        CostCoverage {
            complete: 1,
            incomplete: 1,
            unavailable: 1,
            invalid: 1,
        }
    );
    assert!(!cost_coverage(&entries).label().contains('$'));
}

#[test]
fn report_cost_coverage_does_not_sum_overlapping_parent_and_child_costs() {
    let cost = RuntimeCostReport::known(RuntimeCost::from_usd(8.0, "test").unwrap());
    let entries = [entry("scan-parent", cost), entry("scan-child", cost)];
    assert_eq!(cost_coverage(&entries).complete, 2);
    assert!(!cost_coverage(&entries).label().contains("16"));
}

#[test]
fn report_cost_coverage_rejects_contradictory_and_negative_money() {
    let mut entries = [
        entry("both", RuntimeCostReport::known(RuntimeCost::ZERO)),
        entry("negative", RuntimeCostReport::known(RuntimeCost::ZERO)),
    ];
    if let RunSummaryEntryState::Ready(summary) = &mut entries[0].state {
        summary.observed_cost_usd = Some(2.0);
        summary.provider_spend_unresolved = true;
    }
    if let RunSummaryEntryState::Ready(summary) = &mut entries[1].state {
        summary.cost_usd = Some(-1.0);
    }
    assert_eq!(cost_coverage(&entries).invalid, 2);
    assert_eq!(cost_coverage(&entries).complete, 0);
}
