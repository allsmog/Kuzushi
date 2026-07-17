use super::fixture::{outstanding_decision_records, terminal_status_records};
use super::*;
use kuzushi_core::run_lifecycle::{RunCellRoleV1, RunItemStatus, RunProgressFidelity};
use std::collections::BTreeSet;

#[test]
fn terminal_status_matrix_keeps_typed_truth_across_surfaces() {
    for status in terminal_statuses() {
        let target = tempfile::tempdir().unwrap();
        let run_id = format!("semantic-equivalence-{}", status.label());
        let fixture = persist_records(
            target.path(),
            &run_id,
            terminal_status_records(&run_id, status),
        );

        assert_eq!(
            fixture.read.projection.terminal.as_ref().unwrap().status,
            status
        );
        assert_eq!(
            kuzushi_core::run_lifecycle::present_run(&fixture.read).terminal_status,
            Some(status)
        );
        assert_surface_equivalence(target.path(), &run_id, fixture);
    }
}

#[test]
fn outstanding_decision_is_source_backed_and_equivalent_across_surfaces() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "semantic-equivalence-outstanding-decision";
    let ids = FixtureIds::fixed();
    let fixture = persist_records(
        target.path(),
        run_id,
        outstanding_decision_records(run_id, ids),
    );
    assert_eq!(
        fixture.read.projection.outstanding_questions(),
        vec![ids.question]
    );
    let presentation = kuzushi_core::run_lifecycle::present_run(&fixture.read);
    let roles = presentation
        .semantic_keys()
        .into_iter()
        .map(|key| key.role)
        .collect::<BTreeSet<_>>();
    assert!(roles.contains(&RunCellRoleV1::Question));
    assert!(!roles.contains(&RunCellRoleV1::Decision));
    assert_surface_equivalence(target.path(), run_id, fixture);
}

#[test]
fn acceptance_fixture_discloses_loss_and_preserves_cost_usage_and_result_identity() {
    let target = tempfile::tempdir().unwrap();
    let ids = FixtureIds::fixed();
    let complete = persist_complete_fixture(target.path(), COMPLETE_RUN_ID, ids);
    let presentation = kuzushi_core::run_lifecycle::present_run(&complete.read);
    assert_eq!(
        presentation.health.progress,
        RunProgressFidelity::Coalesced { omitted: 7 }
    );
    assert_complete_contract(&presentation, ids);

    let partial_target = tempfile::tempdir().unwrap();
    let partial = persist_records(
        partial_target.path(),
        PARTIAL_RUN_ID,
        partial_records(PARTIAL_RUN_ID, ids),
    );
    assert_partial_contract(&kuzushi_core::run_lifecycle::present_run(&partial.read));
}

fn terminal_statuses() -> [RunItemStatus; 6] {
    [
        RunItemStatus::Completed,
        RunItemStatus::Partial,
        RunItemStatus::Failed,
        RunItemStatus::Canceled,
        RunItemStatus::Interrupted,
        RunItemStatus::Skipped,
    ]
}
