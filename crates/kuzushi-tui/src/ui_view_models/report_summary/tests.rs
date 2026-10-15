use super::*;
use kuzushi_core::runtime::{RuntimeCost, RuntimeCostReport};
use kuzushi_core::{RunSummary, RunSummaryIssue};

#[test]
fn source_history_format_disclosure_uses_the_shared_omission_contract() {
    use kuzushi_core::WorkspaceExportFormat;
    for format in [
        WorkspaceExportFormat::Json,
        WorkspaceExportFormat::Jsonl,
        WorkspaceExportFormat::Sarif,
        WorkspaceExportFormat::MarkdownBundle,
    ] {
        assert!(report_source_history_coverage(format).contains("included"));
    }
    for format in [
        WorkspaceExportFormat::Csv,
        WorkspaceExportFormat::VulnFindings,
    ] {
        assert!(report_source_history_coverage(format).contains("omitted"));
    }
}

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
            missing_metadata: 1,
            invalid: 0,
        }
    );
    assert!(!cost_coverage(&entries).label().contains('$'));
    assert!(cost_coverage(&entries)
        .label()
        .contains("1 missing metadata"));
    assert!(!cost_coverage(&entries)
        .label()
        .contains("unreadable/invalid"));
}

#[test]
fn report_cost_coverage_does_not_sum_overlapping_parent_and_child_costs() {
    let cost = RuntimeCostReport::known(RuntimeCost::from_usd(8.0, "test").unwrap());
    let entries = [entry("scan-parent", cost), entry("scan-child", cost)];
    assert_eq!(cost_coverage(&entries).complete, 2);
    assert!(!cost_coverage(&entries).label().contains("16"));
    assert!(!cost_coverage(&entries).label().contains("metadata"));
    assert!(!cost_coverage(&entries)
        .label()
        .contains("unreadable/invalid"));
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

#[test]
fn report_cost_coverage_distinguishes_missing_metadata_from_unreadable_records() {
    let entries = [
        RunSummaryIssue::MissingMetadata,
        RunSummaryIssue::UnreadableMetadata("owned unreadable fixture".into()),
        RunSummaryIssue::InvalidMetadata("owned invalid fixture".into()),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, issue)| RunSummaryEntry {
        run_id: format!("owned-{index}"),
        path: format!("/unused/{index}").into(),
        state: RunSummaryEntryState::Issue(issue),
    })
    .collect::<Vec<_>>();
    let coverage = cost_coverage(&entries);
    assert_eq!(coverage.missing_metadata, 1);
    assert_eq!(coverage.invalid, 2);
    assert_eq!(coverage.unavailable, 0);
    assert!(coverage
        .label()
        .contains("1 missing metadata · 2 unreadable/invalid"));
}
